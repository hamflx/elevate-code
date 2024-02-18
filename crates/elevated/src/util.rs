use std::{
    ffi::{c_void, OsStr},
    fs::{File, OpenOptions},
    io::Read,
    ops::{Deref, DerefMut},
    os::windows::{
        ffi::OsStrExt,
        fs::OpenOptionsExt,
        io::{AsRawHandle, FromRawHandle},
    },
    slice::from_raw_parts,
};

use ntapi::{
    ntobapi::{
        NtSetInformationObject, ObjectHandleFlagInformation, OBJECT_HANDLE_FLAG_INFORMATION,
        OBJ_INHERIT, OBJ_PROTECT_CLOSE,
    },
    ntpsapi::{
        NtCurrentProcess, NtQueryInformationProcess, ProcessHandleInformation,
        PROCESS_HANDLE_SNAPSHOT_INFORMATION,
    },
    ntrtl::RtlGetCurrentPeb,
};
use serde::{Deserialize, Serialize};
use windows::{
    core::{PCWSTR, PWSTR},
    Win32::{
        Foundation::{
            HANDLE, NTSTATUS, STATUS_BUFFER_OVERFLOW, STATUS_BUFFER_TOO_SMALL,
            STATUS_INFO_LENGTH_MISMATCH,
        },
        Security::PSECURITY_DESCRIPTOR,
        Storage::FileSystem::PIPE_ACCESS_DUPLEX,
        System::{
            Console::{AttachConsole, FreeConsole},
            Environment::GetCommandLineW,
            Pipes::{
                ConnectNamedPipe, CreateNamedPipeW, PIPE_READMODE_MESSAGE, PIPE_TYPE_MESSAGE,
                PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
            },
            Threading::{
                CreateProcessW, GetCurrentProcessId, CREATE_SUSPENDED, PROCESS_INFORMATION,
                STARTUPINFOW,
            },
            WindowsProgramming::CLIENT_ID,
        },
    },
};

use crate::process::{ProcessHandle, ThreadHandle};

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

pub enum ForkResult {
    Parent {
        process: ProcessHandle,
        thread: ThreadHandle,
    },
    Child,
}

#[allow(dead_code)]
enum Operation {
    Enable,
    Disable,
    Restore,
}

#[repr(C)]
struct HandleEntry {
    handle_value: usize,
    handle_attrs: u32,
    granted_access: u32,
    object_type_index: u32,
}

// https://github.com/huntandhackett/process-cloning/blob/master/5.Library/Library/cloning.c#L291
fn capture_handle_attributes() -> Result<Vec<HandleEntry>, NTSTATUS> {
    let peb = unsafe { &*RtlGetCurrentPeb() };
    let win8_plus = peb.OSMajorVersion > 6 || (peb.OSMajorVersion == 6 && peb.OSMinorVersion > 6);
    if !win8_plus {
        // Windows 7 requires enumerating all system handles
        panic!("unsupported os");
    }

    // Windows 8+ supports enumerating per-process handles

    let mut buffer_size: u32 = 0x800; // 2 KiB to start with
    let buffer = loop {
        let mut buffer = vec![0u8; buffer_size as _];

        let status = NTSTATUS(unsafe {
            NtQueryInformationProcess(
                NtCurrentProcess,
                ProcessHandleInformation,
                buffer.as_mut_ptr() as _,
                buffer_size,
                &mut buffer_size,
            )
        });

        if status.is_ok() {
            break buffer;
        } else if status == STATUS_INFO_LENGTH_MISMATCH
            || status == STATUS_BUFFER_TOO_SMALL
            || status == STATUS_BUFFER_OVERFLOW
        {
            continue;
        } else {
            return Err(status);
        }
    };
    let handle_info = unsafe { &*(buffer.as_ptr() as *const PROCESS_HANDLE_SNAPSHOT_INFORMATION) };

    let mut handles = Vec::new();
    let entries =
        unsafe { from_raw_parts(handle_info.Handles.as_ptr(), handle_info.NumberOfHandles) };
    for item in entries {
        handles.push(HandleEntry {
            handle_value: item.HandleValue as _,
            handle_attrs: item.HandleAttributes,
            granted_access: item.GrantedAccess,
            object_type_index: item.ObjectTypeIndex,
        });
    }

    Ok(handles)
}

// https://github.com/huntandhackett/process-cloning/blob/master/5.Library/Library/cloning.c#L291
unsafe fn set_inheritance_handles(snapshot: &[HandleEntry], op: Operation) {
    let mut handle_flags: OBJECT_HANDLE_FLAG_INFORMATION = Default::default();

    match op {
        Operation::Enable => {
            handle_flags.Inherit = 1;
        }
        Operation::Disable => {
            handle_flags.Inherit = 0;
        }
        Operation::Restore => {}
    }

    for handle in snapshot {
        if matches!(op, Operation::Restore) {
            handle_flags.Inherit = (handle.handle_attrs & OBJ_INHERIT) as _;
        }

        handle_flags.ProtectFromClose = (handle.handle_attrs & OBJ_PROTECT_CLOSE) as _;

        NtSetInformationObject(
            handle.handle_value as _,
            ObjectHandleFlagInformation,
            &mut handle_flags as *mut _ as *mut c_void,
            std::mem::size_of_val(&handle_flags) as _,
        );
    }
}

#[derive(Serialize, Deserialize)]
pub struct TaskInfo {
    pub(crate) port: u16,
    pub(crate) module: String,
    pub(crate) caller_offset: usize,
    pub(crate) args: String,
}

impl TaskInfo {
    pub fn new(port: u16, module: String, caller_offset: usize, args: String) -> Self {
        Self {
            port,
            module,
            caller_offset,
            args,
        }
    }
}

pub struct PipeClient {
    pipe: File,
}

impl Deref for PipeClient {
    type Target = File;

    fn deref(&self) -> &Self::Target {
        &self.pipe
    }
}

impl DerefMut for PipeClient {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.pipe
    }
}

impl AsMut<File> for PipeClient {
    fn as_mut(&mut self) -> &mut File {
        &mut self.pipe
    }
}

impl PipeClient {
    pub fn new(name: &str) -> Result<Self, String> {
        let pipe = OpenOptions::new()
            .read(true)
            .write(true)
            .share_mode(0)
            .open(name)
            .map_err(|err| format!("open pipe {} error: {}", name, err))?;
        Ok(Self { pipe })
    }

    pub fn read_buf_string(&mut self) -> Result<String, String> {
        read_file_to_string(&mut self.pipe)
    }
}

pub struct NamedPipeServer {
    pipe: File,
}

impl AsMut<File> for NamedPipeServer {
    fn as_mut(&mut self) -> &mut File {
        &mut self.pipe
    }
}

impl Deref for NamedPipeServer {
    type Target = File;

    fn deref(&self) -> &Self::Target {
        &self.pipe
    }
}

impl DerefMut for NamedPipeServer {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.pipe
    }
}

impl NamedPipeServer {
    pub fn new(name: &str) -> Result<Self, String> {
        let pipe_name = OsStr::new(name)
            .encode_wide()
            .chain([0])
            .collect::<Vec<_>>();

        let handle = unsafe {
            CreateNamedPipeW(
                PCWSTR(pipe_name.as_ptr()),
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                PIPE_UNLIMITED_INSTANCES,
                1048576,
                1048576,
                0,
                None,
            )
        };
        if handle.is_invalid() {
            return Err("invalid pipe handle".to_string());
        }

        let pipe = unsafe { std::fs::File::from_raw_handle(handle.0 as _) };
        Ok(Self { pipe })
    }

    pub fn accept(&self) -> Result<(), String> {
        unsafe {
            ConnectNamedPipe(HANDLE(self.pipe.as_raw_handle() as _), None)
                .map_err(|err| format!("ConnectNamedPipe Error: {}", err))
        }
    }

    pub fn read_buf_string(&mut self) -> Result<String, String> {
        read_file_to_string(&mut self.pipe)
    }
}

fn read_file_to_string(file: &mut File) -> Result<String, String> {
    let mut buf = vec![0; 1048576];
    let n = file
        .read(&mut buf)
        .map_err(|err| format!("read error: {err}"))?;
    Ok(String::from_utf8(buf[..n].to_vec()).map_err(|err| format!("from_utf8 error: {err}"))?)
}

pub fn fork() -> Result<ForkResult, String> {
    unsafe {
        let parent_pid = GetCurrentProcessId();
        let mut process_info = std::mem::MaybeUninit::zeroed().assume_init();
        let suspended = RTL_CLONE_PROCESS_FLAGS_CREATE_SUSPENDED;

        let snapshot =
            capture_handle_attributes().map_err(|err| format!("nt error: 0x{:x}", err.0))?;
        set_inheritance_handles(&snapshot, Operation::Enable);

        let ret = RtlCloneUserProcess(
            suspended | RTL_CLONE_PROCESS_FLAGS_INHERIT_HANDLES,
            PSECURITY_DESCRIPTOR::default(),
            PSECURITY_DESCRIPTOR::default(),
            HANDLE::default(),
            &mut process_info,
        );

        match ret {
            RTL_CLONE_PARENT => {
                set_inheritance_handles(&snapshot, Operation::Restore);

                let handle = ProcessHandle::from_raw_handle(process_info.Process);
                let thread = ThreadHandle::from_raw_handle(process_info.Thread);
                Ok(ForkResult::Parent {
                    process: handle,
                    thread,
                })
            }
            RTL_CLONE_CHILD => {
                FreeConsole().unwrap();
                AttachConsole(parent_pid).unwrap();

                Ok(ForkResult::Child)
            }
            _ => Err("fork error".to_string()),
        }
    }
}

pub struct PausedProcess(ProcessHandle, ThreadHandle);

impl AsRef<ProcessHandle> for PausedProcess {
    fn as_ref(&self) -> &ProcessHandle {
        &self.0
    }
}

impl Deref for PausedProcess {
    type Target = ProcessHandle;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl PausedProcess {
    pub fn run(self) -> ProcessHandle {
        self.1.resume();
        self.0
    }

    pub fn into_process(self) -> ProcessHandle {
        self.0
    }
}

pub fn create_paused_process() -> Result<PausedProcess, String> {
    let mut si = STARTUPINFOW::default();
    let mut pi = PROCESS_INFORMATION::default();
    si.cb = std::mem::size_of_val(&si) as _;
    let cmdline = unsafe { GetCommandLineW() };
    let mut cmdline = unsafe { cmdline.as_wide().to_vec() };
    cmdline.push(0);
    unsafe {
        CreateProcessW(
            PCWSTR::null(),
            PWSTR(cmdline.as_mut_ptr()),
            None,
            None,
            true,
            CREATE_SUSPENDED,
            None,
            PCWSTR::null(),
            &si,
            &mut pi,
        )
        .unwrap()
    };

    let process = unsafe { ProcessHandle::from_raw_handle(pi.hProcess) };
    let thread = unsafe { ThreadHandle::from_raw_handle(pi.hThread) };

    Ok(PausedProcess(process, thread))
}
