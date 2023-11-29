use crate::token::ProcessToken;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Threading::{
    GetCurrentProcessId, OpenProcess, PROCESS_ACCESS_RIGHTS, PROCESS_ALL_ACCESS,
    PROCESS_INFORMATION_CLASS,
};

const PROCESS_ACCESS_TOKEN: PROCESS_INFORMATION_CLASS = PROCESS_INFORMATION_CLASS(9);

#[repr(C)]
pub struct ProcessAccessToken {
    token: HANDLE,
    thread: HANDLE,
}

#[link(name = "ntdll.dll", kind = "raw-dylib", modifiers = "+verbatim")]
extern "system" {
    #[link_name = "NtSetInformationProcess"]
    fn NtSetInformationProcess(
        process: HANDLE,
        processinformationclass: PROCESS_INFORMATION_CLASS,
        lpprocessinformation: *mut ProcessAccessToken,
        processInformationLength: usize,
    ) -> isize;
}

pub struct ProcessHandle(pub(crate) HANDLE);

impl ProcessHandle {
    pub fn from_pid(pid: u32, access: PROCESS_ACCESS_RIGHTS) -> Result<Self, String> {
        Ok(Self(unsafe {
            OpenProcess(access, true, pid).map_err(|err| format!("{err}"))
        }?))
    }

    pub fn from_current_process() -> Result<Self, String> {
        Self::from_pid(unsafe { GetCurrentProcessId() }, PROCESS_ALL_ACCESS)
    }

    pub fn replace_primary_token(&self, token: &ProcessToken) -> Result<(), String> {
        let mut info: ProcessAccessToken = ProcessAccessToken {
            thread: HANDLE::default(),
            token: token.raw_handle(),
        };
        let ret = unsafe {
            NtSetInformationProcess(
                self.0,
                PROCESS_ACCESS_TOKEN,
                &mut info,
                std::mem::size_of_val(&info),
            )
        };
        match ret {
            0 => Ok(()),
            code => Err(format!("{}", std::io::Error::from_raw_os_error(code as _))),
        }
    }
}

impl Drop for ProcessHandle {
    fn drop(&mut self) {
        let _ = unsafe { CloseHandle(self.0) };
    }
}
