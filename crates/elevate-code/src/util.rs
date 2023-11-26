use std::ffi::c_void;

use windows::Win32::{
    Foundation::{CloseHandle, HANDLE},
    Security::PSECURITY_DESCRIPTOR,
    System::{
        Console::{AttachConsole, FreeConsole},
        Threading::{
            GetCurrentProcessId, OpenProcess, OpenThread, ResumeThread, TerminateProcess,
            WaitForSingleObject, INFINITE, PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS,
        },
        WindowsProgramming::CLIENT_ID,
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

#[repr(C)]
#[allow(non_camel_case_types, non_snake_case)]
struct SECTION_IMAGE_INFORMATION {
    EntryPoint: c_void,
    StackZeroBits: u32,
    StackReserved: u32,
    StackCommit: u32,
    ImageSubsystem: u32,
    SubSystemVersionLow: u16,
    SubSystemVersionHigh: u16,
    Unknown1: u32,
    ImageCharacteristics: u32,
    ImageMachineType: u32,
    Unknown2: [u32; 3],
}

#[repr(C)]
#[allow(non_camel_case_types, non_snake_case)]
struct RTL_USER_PROCESS_INFORMATION {
    Size: u32,
    Process: HANDLE,
    Thread: HANDLE,
    ClientId: CLIENT_ID,
    ImageInformation: SECTION_IMAGE_INFORMATION,
}

#[link(name = "ntdll.dll", kind = "raw-dylib", modifiers = "+verbatim")]
extern "system" {
    #[link_name = "RtlCloneUserProcess"]
    fn RtlCloneUserProcess(
        ProcessFlags: u32,
        ProcessSecurityDescriptor: PSECURITY_DESCRIPTOR,
        ThreadSecurityDescriptor: PSECURITY_DESCRIPTOR,
        DebugPort: HANDLE,
        ProcessInformation: &mut RTL_USER_PROCESS_INFORMATION,
    ) -> i32;
}

const RTL_CLONE_PROCESS_FLAGS_CREATE_SUSPENDED: u32 = 0x00000001;
const RTL_CLONE_PROCESS_FLAGS_INHERIT_HANDLES: u32 = 0x00000002;

const RTL_CLONE_PARENT: i32 = 0;
const RTL_CLONE_CHILD: i32 = 297;

pub enum ProcessControlFlow {
    ResumeMainThread,
    Terminate,
}

pub enum ForkResult {
    Parent,
    Child,
}

pub fn create_process(work: impl Fn(u32) -> ProcessControlFlow) -> Result<ForkResult, String> {
    unsafe {
        let parent_pid = GetCurrentProcessId();

        let mut process_info = std::mem::MaybeUninit::zeroed().assume_init();
        let ret = RtlCloneUserProcess(
            RTL_CLONE_PROCESS_FLAGS_CREATE_SUSPENDED | RTL_CLONE_PROCESS_FLAGS_INHERIT_HANDLES,
            PSECURITY_DESCRIPTOR::default(),
            PSECURITY_DESCRIPTOR::default(),
            HANDLE::default(),
            &mut process_info,
        );
        if ret == RTL_CLONE_PARENT {
            // panic!("RTL_CLONE_PARENT");
        } else if ret == RTL_CLONE_CHILD {
            FreeConsole().unwrap();
            AttachConsole(parent_pid).unwrap();

            return Ok(ForkResult::Child);
        } else {
            panic!("Failed");
        }

        let pid: u32 = process_info.ClientId.UniqueProcess.0 as u32;
        let tid = process_info.ClientId.UniqueThread.0 as u32;
        let hp = OpenProcess(PROCESS_ALL_ACCESS, false, pid).unwrap();
        let ht = OpenThread(THREAD_ALL_ACCESS, false, tid).unwrap();

        match work(process_info.ClientId.UniqueProcess.0 as _) {
            ProcessControlFlow::ResumeMainThread => {
                ResumeThread(ht);
                WaitForSingleObject(hp, INFINITE);
            }
            ProcessControlFlow::Terminate => {
                let _ = TerminateProcess(hp, u32::MAX);
            }
        }

        CloseHandle(hp).unwrap();
        CloseHandle(ht).unwrap();

        Ok(ForkResult::Parent)
    }
}
