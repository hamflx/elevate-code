use std::ffi::CString;

use windows::{
    core::{PCSTR, PSTR},
    Win32::{
        Foundation::CloseHandle,
        System::Threading::{
            CreateProcessA, ResumeThread, TerminateProcess, WaitForSingleObject, CREATE_SUSPENDED,
            INFINITE, PROCESS_INFORMATION, STARTUPINFOA,
        },
    },
};

pub struct CommandLineBuilder {
    args: Vec<String>,
}

impl CommandLineBuilder {
    pub fn new() -> Self {
        Self { args: Vec::new() }
    }

    pub fn arg(mut self, arg: &str) -> Self {
        self.args.push(arg.to_string());
        self
    }

    pub fn encode(&self) -> String {
        let mut params = String::new();
        for arg in self.args.iter() {
            params.push(' ');
            if arg.len() == 0 {
                params.push_str("\"\"");
            } else if arg.find(&[' ', '\t', '"'][..]).is_none() {
                params.push_str(&arg);
            } else {
                params.push('"');
                for c in arg.chars() {
                    match c {
                        '\\' => params.push_str("\\\\"),
                        '"' => params.push_str("\\\""),
                        c => params.push(c),
                    }
                }
                params.push('"');
            }
        }
        if !params.is_empty() {
            params.remove(0);
        }
        params
    }
}

pub enum ProcessControlFlow {
    ResumeMainThread,
    Terminate,
}

pub fn create_process(args: &[&str], work: impl Fn(u32) -> ProcessControlFlow) {
    unsafe {
        let mut si = STARTUPINFOA::default();
        let mut pi = PROCESS_INFORMATION::default();
        si.cb = std::mem::size_of_val(&si) as _;
        let exe = std::env::current_exe()
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        let mut builder = CommandLineBuilder::new().arg(&exe);
        for i in args {
            builder = builder.arg(i);
        }
        let cmd = CString::new(builder.encode()).unwrap();
        CreateProcessA(
            PCSTR::null(),
            PSTR::from_raw(cmd.as_ptr() as _),
            None,
            None,
            true,
            CREATE_SUSPENDED,
            None,
            PCSTR::null(),
            &si,
            &mut pi,
        )
        .unwrap();

        match work(pi.dwProcessId) {
            ProcessControlFlow::ResumeMainThread => {
                ResumeThread(pi.hThread);
                WaitForSingleObject(pi.hProcess, INFINITE);
            }
            ProcessControlFlow::Terminate => {
                let _ = TerminateProcess(pi.hProcess, u32::MAX);
            }
        }

        CloseHandle(pi.hThread).unwrap();
        CloseHandle(pi.hProcess).unwrap();
    };
}
