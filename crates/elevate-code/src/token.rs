use crate::process::ProcessHandle;
use std::ffi::CString;
use windows::core::PCSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Security::{
    AdjustTokenPrivileges, DuplicateTokenEx, GetTokenInformation, LookupPrivilegeValueA,
    SecurityImpersonation, TokenElevation, TokenPrimary, LUID_AND_ATTRIBUTES, SE_PRIVILEGE_ENABLED,
    TOKEN_ACCESS_MASK, TOKEN_ELEVATION, TOKEN_PRIVILEGES,
};
use windows::Win32::System::Threading::OpenProcessToken;

const MAXIMUM_ALLOWED: TOKEN_ACCESS_MASK = TOKEN_ACCESS_MASK(0x02000000);

pub struct ProcessToken<'h>(&'h ProcessHandle, HANDLE);

impl<'h> ProcessToken<'h> {
    pub(crate) fn raw_handle(&self) -> HANDLE {
        self.1
    }

    pub(crate) fn open_process(process: &'h ProcessHandle) -> Result<Self, String> {
        let mut token = Default::default();
        unsafe { OpenProcessToken(process.0, MAXIMUM_ALLOWED, &mut token) }
            .map_err(|err| format!("{err}"))?;
        Ok(Self(process, token))
    }

    #[allow(dead_code)]
    pub(crate) fn enable_privilege(&self, name: &str) -> Result<(), String> {
        let name = CString::new(name).map_err(|err| format!("{err}"))?;
        let mut luid = Default::default();
        unsafe {
            LookupPrivilegeValueA(
                PCSTR::null(),
                PCSTR::from_raw(name.as_ptr() as _),
                &mut luid,
            )
            .map_err(|err| format!("{err}"))?
        };

        let tp = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Attributes: SE_PRIVILEGE_ENABLED,
                Luid: luid,
            }],
        };
        unsafe {
            AdjustTokenPrivileges(self.1, false, Some(&tp), 0, None, None)
                .map_err(|err| format!("{err}"))?
        };

        Ok(())
    }

    pub(crate) fn duplicate(&self) -> Result<Self, String> {
        let mut new_token = Default::default();
        unsafe {
            DuplicateTokenEx(
                self.1,
                MAXIMUM_ALLOWED,
                None,
                SecurityImpersonation,
                TokenPrimary,
                &mut new_token,
            )
            .map_err(|err| format!("{err}"))?
        };
        Ok(Self(self.0, new_token))
    }

    pub(crate) fn is_elevated(&self) -> Result<bool, String> {
        let mut elevation: TOKEN_ELEVATION = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let size = std::mem::size_of::<TOKEN_ELEVATION>() as u32;
        let mut ret_size = size;
        unsafe {
            GetTokenInformation(
                self.1,
                TokenElevation,
                Some(&mut elevation as *const _ as *mut _),
                size,
                &mut ret_size,
            )
        }
        .map_err(|err| format!("{err}"))?;
        Ok(elevation.TokenIsElevated != 0)
    }
}

impl<'h> Drop for ProcessToken<'h> {
    fn drop(&mut self) {
        let _ = unsafe { CloseHandle(self.1) };
    }
}
