use std::{
    collections::HashMap,
    ffi::CString,
    io::{BufRead, BufReader, BufWriter, Write},
    net::{TcpListener, TcpStream},
    sync::{
        mpsc::{channel, Receiver, Sender},
        Mutex,
    },
};

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use windows::{
    core::PCSTR,
    Win32::{
        Foundation::HWND,
        System::Threading::PROCESS_SET_INFORMATION,
        UI::{Shell::ShellExecuteA, WindowsAndMessaging::SW_HIDE},
    },
};

use crate::process::ProcessHandle;
use crate::token::ProcessToken;
use crate::{
    util::{create_process, CommandLineBuilder, ProcessControlFlow},
    ForkResult,
};

#[ctor::ctor]
fn elevate_by_command_line() {
    if let Some(ElevateToken::Elevate { port }) = ElevateToken::from_command_line() {
        let code = match listen_elevation_request(port) {
            Ok(_) => 0,
            Err(_) => -1,
        };
        std::process::exit(code);
    }
}

fn listen_elevation_request(port: u16) -> Result<(), String> {
    let stream = TcpStream::connect(format!("127.0.0.1:{port}")).map_err(|err| format!("{err}"))?;
    stream.set_nodelay(true).map_err(|err| format!("{err}"))?;

    let reader = BufReader::new(stream.try_clone().map_err(|err| format!("{err}"))?);
    let mut writer = BufWriter::new(stream);

    for l in reader.lines() {
        let l = l.map_err(|err| format!("{err}"))?;
        let request: ElevationRequest = serde_json::from_str(&l).map_err(|err| format!("{err}"))?;
        let result = replace_with_current_token(request.pid);
        let success = result.is_ok();
        let error = result.map_or_else(|err| Some(err), |_| None);
        let msg = format!(
            "{}\n",
            serde_json::to_string(&ElevationResponse {
                id: request.id,
                success,
                error
            })
            .map_err(|err| format!("{err}"))?
        );
        writer
            .write_all(msg.as_bytes())
            .map_err(|err| format!("{err}"))?;
        writer.flush().map_err(|err| format!("{err}"))?;
    }

    Ok(())
}

pub static GLOBAL_CLIENT: ElevationClient = ElevationClient::new();

pub struct ElevationClient {
    pipe: Mutex<Option<Sender<ElevationRequest>>>,
    pending: Mutex<Vec<(String, Sender<ElevationResponse>)>>,
}

fn start_elevation_host(receiver: Receiver<ElevationRequest>) -> Result<u16, String> {
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|err| format!("{err}"))?;
    let port = listener
        .local_addr()
        .map_err(|err| format!("{err}"))?
        .port();
    std::thread::spawn(move || {
        if let Ok((client, _)) = listener.accept() {
            let _ = client.set_nodelay(true);
            let Ok(stream_cloned) = client.try_clone() else {
                return;
            };

            // receive
            let reader = BufReader::new(stream_cloned);
            let t1 = std::thread::spawn(move || {
                for l in reader.lines() {
                    match l {
                        Ok(l) => {
                            let _ = GLOBAL_CLIENT.receive(&l);
                        }
                        Err(_) => break,
                    }
                }
            });

            // send
            let mut writer = BufWriter::new(client);
            let t2 = std::thread::spawn(move || {
                while let Ok(req) = { receiver.recv() } {
                    match serde_json::to_string(&req).map(|s| s + "\n") {
                        Ok(msg) => {
                            let _ = writer
                                .write_all(msg.as_bytes())
                                .and_then(|_| writer.flush());
                        }
                        Err(_) => {}
                    }
                }
            });

            let _ = t1.join();
            let _ = t2.join();
        }
    });
    Ok(port)
}

impl ElevationClient {
    pub const fn new() -> Self {
        Self {
            pipe: Mutex::new(None),
            pending: Mutex::new(Vec::new()),
        }
    }

    pub fn request(&self, request: ElevationRequest) -> Result<(), String> {
        let id = {
            let mut lock = self.pipe.lock().map_err(|err| format!("{err}"))?;
            if lock.is_none() {
                let (sender, receiver) = channel();
                *lock = Some(sender);

                let port = start_elevation_host(receiver)?;

                let token = ElevateToken::Elevate { port };
                let cmd = CommandLineBuilder::new().arg(&token.to_string()).encode();
                run_as(
                    std::env::current_exe()
                        .map_err(|err| format!("{err}"))?
                        .to_str()
                        .ok_or_else(|| format!("Current executable path invalid"))?,
                    &cmd,
                );
            }

            let id = request.id.to_owned();
            let sender = lock.as_ref().unwrap();
            sender.send(request).map_err(|err| format!("{err}"))?;

            id
        };

        let wait_recv = {
            let (wait_send, wait_recv) = channel();
            let mut lock = self.pending.lock().map_err(|err| format!("{err}"))?;
            lock.push((id, wait_send));
            wait_recv
        };

        wait_recv.recv().map_err(|err| format!("{err}"))?;

        Ok(())
    }

    pub fn receive(&self, content: &str) -> Result<(), String> {
        let response: ElevationResponse =
            serde_json::from_str(content).map_err(|err| format!("{err}"))?;
        let lock = self.pending.lock().map_err(|err| format!("{err}"))?;
        for (id, sender) in lock.iter() {
            if id == &response.id {
                let _ = sender.send(response);
                break;
            }
        }
        Ok(())
    }
}

pub trait ElevatedOperation: DeserializeOwned + Serialize {
    fn id() -> &'static str;

    fn check() -> Result<(), String> {
        try_execute_task::<Self>(Self::id())
    }

    fn execute(&self) -> Result<(), String> {
        if is_elevated() {
            unreachable!();
        }
        let ret = create_process(
            |pid| match GLOBAL_CLIENT.request(ElevationRequest::new(pid)) {
                Ok(_) => ProcessControlFlow::ResumeMainThread,
                Err(_) => ProcessControlFlow::Terminate,
            },
        )
        .unwrap();
        if matches!(ret, ForkResult::Child) {
            self.execute().unwrap();
        }

        Ok(())
    }

    fn run(&self);
}

#[derive(Debug)]
pub enum ElevateToken {
    Elevate { port: u16 },
    Execute { task_id: String, payload: String },
}

#[derive(Serialize, Deserialize)]
pub struct ElevationRequest {
    id: String,
    pid: u32,
}

#[derive(Serialize, Deserialize)]
pub struct ElevationResponse {
    id: String,
    success: bool,
    error: Option<String>,
}

impl ElevationRequest {
    pub fn new(pid: u32) -> Self {
        Self {
            id: std::time::SystemTime::now()
                .duration_since(std::time::SystemTime::UNIX_EPOCH)
                .unwrap()
                .as_millis()
                .to_string(),
            pid,
        }
    }
}

impl ElevateToken {
    pub fn from_command_line() -> Option<Self> {
        std::env::args()
            .skip(1)
            .next()
            .and_then(|s| ElevateToken::from_str(&s))
    }

    pub fn from_str(s: &str) -> Option<Self> {
        const PREFIX: &str = "--elevate-token=";
        if !s.starts_with(PREFIX) {
            return None;
        }
        let s = &s[PREFIX.len()..];
        let (cmd, s) = s.split_once(',')?;
        match cmd {
            "elevate" => {
                let map: HashMap<_, _> = s.split(',').filter_map(|s| s.split_once('=')).collect();
                let port: u16 = map.get("port")?.parse().ok()?;
                Some(ElevateToken::Elevate { port })
            }
            "execute" => {
                let (id, s) = s.split_once(',')?;
                let (_, id) = id.split_once('=')?;
                Some(ElevateToken::Execute {
                    task_id: id.to_string(),
                    payload: s.to_string(),
                })
            }
            _ => None,
        }
    }

    pub fn to_string(&self) -> String {
        match self {
            ElevateToken::Elevate { port } => {
                format!("--elevate-token=elevate,port={port}")
            }
            ElevateToken::Execute { task_id, payload } => {
                format!("--elevate-token=execute,id={},{}", task_id, payload)
            }
        }
    }
}

pub fn is_elevated() -> bool {
    let process = ProcessHandle::from_current_process().unwrap();
    let token = ProcessToken::open_process(&process).unwrap();
    token.is_elevated().unwrap()
}

pub fn replace_with_current_token(pid: u32) -> Result<(), String> {
    let current_process = ProcessHandle::from_current_process()?;
    let desired_token = ProcessToken::open_process(&current_process)?.duplicate()?;
    let target_process = ProcessHandle::from_pid(pid, PROCESS_SET_INFORMATION)?;
    target_process.replace_primary_token(&desired_token)?;
    Ok(())
}

pub fn run_as(exe: &str, cmd: &str) {
    let verb = CString::new("runas").unwrap();
    let exe = CString::new(exe).unwrap();
    let args = CString::new(cmd).unwrap();
    unsafe {
        ShellExecuteA(
            HWND::default(),
            PCSTR::from_raw(verb.as_ptr() as _),
            PCSTR::from_raw(exe.as_ptr() as _),
            PCSTR::from_raw(args.as_ptr() as _),
            PCSTR::null(),
            SW_HIDE,
        )
    };
}

pub fn try_execute_task<T: ElevatedOperation>(id: &str) -> Result<(), String> {
    match ElevateToken::from_command_line() {
        Some(ElevateToken::Execute { task_id, payload }) if id == task_id => {
            let inst: T = serde_json::from_str(&payload).map_err(|err| format!("{err}"))?;
            inst.run();
            std::process::exit(0);
        }
        _ => Ok(()),
    }
}
