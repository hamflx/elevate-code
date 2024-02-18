use rand::random;
use std::net::UdpSocket;
use std::{
    collections::HashMap,
    ffi::CString,
    sync::{
        mpsc::{channel, Receiver, Sender},
        Mutex,
    },
};

use serde::{Deserialize, Serialize};
use windows::Win32::System::Threading::PROCESS_SYNCHRONIZE;
use windows::{
    core::PCSTR,
    Win32::{
        Foundation::HWND,
        System::Threading::PROCESS_SET_INFORMATION,
        UI::{Shell::ShellExecuteA, WindowsAndMessaging::SW_HIDE},
    },
};

use crate::execute_tasks;
use crate::process::ProcessHandle;
use crate::token::ProcessToken;
use crate::util::CommandLineBuilder;

pub fn execute_elevation_and_tasks() {
    elevate_by_command_line();
    match execute_tasks() {
        Ok(_) => todo!(),
        Err(err) => println!("execute_tasks error: {err}"),
    };
}

fn elevate_by_command_line() {
    if let Some(ElevateToken::Elevate { port, ppid }) = ElevateToken::from_command_line() {
        listen_parent_process_exit(ppid);
        let code = match listen_elevation_request(port) {
            Ok(_) => 0,
            Err(_) => -1,
        };
        std::process::exit(code);
    }
}

fn listen_parent_process_exit(ppid: u32) {
    std::thread::spawn(move || {
        let process = ProcessHandle::from_pid(ppid, PROCESS_SYNCHRONIZE).unwrap();
        process.wait();
        std::process::exit(0);
    });
}

fn listen_elevation_request(port: u16) -> Result<(), String> {
    let sock = UdpSocket::bind("127.0.0.1:0").map_err(|err| format!("{err}"))?;
    sock.connect(format!("127.0.0.1:{port}"))
        .map_err(|err| format!("{err}"))?;

    sock.send("hello".as_bytes())
        .map_err(|err| format!("{err}"))?;

    loop {
        let mut buf = vec![0; 1048576];
        let (len, _) = match sock.recv_from(&mut buf) {
            Ok((0, _)) | Err(_) => break,
            Ok((len, peer)) => (len, peer),
        };
        let message = String::from_utf8(buf[..len].to_vec())
            .map_err(|err| format!("parse utf8 error: {err}"))?;
        let request: ElevationRequest =
            serde_json::from_str(&message).map_err(|err| format!("{err}"))?;
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
        sock.send(msg.as_bytes()).map_err(|err| format!("{err}"))?;
    }

    Ok(())
}

pub static GLOBAL_CLIENT: ElevationClient = ElevationClient::new();

pub struct ElevationClient {
    pipe: Mutex<Option<Sender<ElevationRequest>>>,
    pending: Mutex<Vec<(String, Sender<ElevationResponse>)>>,
}

fn start_elevation_host(receiver: Receiver<ElevationRequest>) -> Result<u16, String> {
    let sock_read = UdpSocket::bind("127.0.0.1:0").map_err(|err| format!("{err}"))?;
    let port = sock_read
        .local_addr()
        .map_err(|err| format!("{err}"))?
        .port();

    std::thread::spawn(move || {
        let mut buf = vec![0; 1048576];

        let (_, peer) = match sock_read.recv_from(&mut buf) {
            Ok((0, _)) | Err(_) => return,
            Ok((len, peer)) => (len, peer),
        };
        let sock_write = sock_read.try_clone().unwrap();
        std::thread::spawn(move || {
            while let Ok(req) = { receiver.recv() } {
                match serde_json::to_string(&req).map(|s| s + "\n") {
                    Ok(msg) => {
                        sock_write.send_to(msg.as_bytes(), peer).unwrap();
                    }
                    Err(_) => {}
                }
            }
        });

        loop {
            let (len, _) = match sock_read.recv_from(&mut buf) {
                Ok((0, _)) | Err(_) => return,
                Ok((len, peer)) => (len, peer),
            };
            let message = String::from_utf8(buf[..len].to_vec()).unwrap();
            let _ = GLOBAL_CLIENT.receive(&message);
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
                let ppid = std::process::id();
                let token = ElevateToken::Elevate { port, ppid };
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

#[derive(Debug)]
pub enum ElevateToken {
    Elevate { port: u16, ppid: u32 },
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
            id: random::<usize>().to_string(),
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
                let ppid: u32 = map.get("ppid")?.parse().ok()?;
                Some(ElevateToken::Elevate { port, ppid })
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
            ElevateToken::Elevate { port, ppid } => {
                format!("--elevate-token=elevate,port={port},ppid={ppid}")
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
