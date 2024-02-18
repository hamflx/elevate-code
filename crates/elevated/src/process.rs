use std::ops::Deref;

use crate::token::ProcessToken;
use windows::Win32::Foundation::{
    CloseHandle, DuplicateHandle, BOOL, DUPLICATE_SAME_ACCESS, HANDLE,
};
use windows::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentProcessId, GetProcessId, OpenProcess, ResumeThread,
    TerminateProcess, WaitForSingleObject, INFINITE, PROCESS_ACCESS_RIGHTS, PROCESS_ALL_ACCESS,
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

pub struct ThreadHandle(pub(crate) HANDLE);

impl ThreadHandle {
    pub(crate) unsafe fn from_raw_handle(handle: HANDLE) -> Self {
        Self(handle)
    }

    pub(crate) fn resume(&self) {
        unsafe { ResumeThread(self.0) };
    }
}

impl Drop for ThreadHandle {
    fn drop(&mut self) {
        let _ = unsafe { CloseHandle(self.0) };
    }
}

pub struct AutoTerminateProcess<P: AsRef<ProcessHandle>>(pub(crate) P);

impl<P> Deref for AutoTerminateProcess<P>
where
    P: AsRef<ProcessHandle>,
{
    type Target = P;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<P> Drop for AutoTerminateProcess<P>
where
    P: AsRef<ProcessHandle>,
{
    fn drop(&mut self) {
        let _ = self.as_ref().terminate();
    }
}

impl<P> AutoTerminateProcess<P>
where
    P: AsRef<ProcessHandle>,
{
    pub fn new(process: P) -> Self
    where
        P: AsRef<ProcessHandle>,
    {
        Self(process)
    }
}

pub struct ProcessHandle(pub(crate) HANDLE);

impl AsRef<ProcessHandle> for ProcessHandle {
    fn as_ref(&self) -> &ProcessHandle {
        self
    }
}

impl ProcessHandle {
    pub(crate) fn from_pid(pid: u32, access: PROCESS_ACCESS_RIGHTS) -> Result<Self, String> {
        Ok(Self(unsafe {
            OpenProcess(access, true, pid).map_err(|err| format!("{err}"))
        }?))
    }

    pub(crate) unsafe fn from_raw_handle(handle: HANDLE) -> Self {
        Self(handle)
    }

    pub(crate) fn from_current_process() -> Result<Self, String> {
        Self::from_pid(unsafe { GetCurrentProcessId() }, PROCESS_ALL_ACCESS)
    }

    pub(crate) fn pid(&self) -> u32 {
        unsafe { GetProcessId(self.0) }
    }

    pub(crate) fn replace_primary_token(&self, token: &ProcessToken) -> Result<(), String> {
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

    pub(crate) fn dupe(&self) -> Result<Self, String> {
        let current_process = unsafe { GetCurrentProcess() };
        let mut dupe = Default::default();
        unsafe {
            DuplicateHandle(
                current_process,
                self.0,
                current_process,
                &mut dupe,
                0,
                BOOL(0),
                DUPLICATE_SAME_ACCESS,
            )
        }
        .map_err(|err| format!("DuplicateHandle Error: {err}"))?;
        Ok(Self(dupe))
    }

    pub(crate) fn terminate(&self) -> std::io::Result<()> {
        unsafe { TerminateProcess(self.0, u32::MAX) }.map_err(|_| std::io::Error::last_os_error())
    }

    pub(crate) fn wait(&self) {
        unsafe { WaitForSingleObject(self.0, INFINITE) };
    }
}

impl Drop for ProcessHandle {
    fn drop(&mut self) {
        let _ = unsafe { CloseHandle(self.0) };
    }
}
