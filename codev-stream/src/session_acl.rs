//! Fail-closed access-control validation for private session inputs.
//!
//! The Windows API adapter is intentionally kept separate from the policy so
//! every rejection rule remains testable on non-Windows build hosts.

use std::fs::File;
#[cfg(not(any(unix, windows)))]
use std::io;

use crate::SessionError;

#[cfg(any(windows, test))]
const GENERIC_ALL: u32 = 0x1000_0000;
#[cfg(any(windows, test))]
const GENERIC_READ: u32 = 0x8000_0000;
#[cfg(any(windows, test))]
const FILE_GENERIC_READ: u32 = 0x0012_0089;

#[cfg(any(windows, test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AceKind {
    Allow,
    Unsupported,
}

#[cfg(any(windows, test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AceFacts {
    kind: AceKind,
    flags: u8,
    current_user: bool,
    mask: u32,
}

#[cfg(any(windows, test))]
#[derive(Debug, Eq, PartialEq)]
struct AclFacts {
    owner_is_current_user: bool,
    dacl_present: bool,
    dacl_protected: bool,
    entries: Vec<AceFacts>,
}

#[cfg(any(windows, test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AclViolation {
    Owner,
    MissingDacl,
    UnprotectedDacl,
    InheritedAce,
    UnsupportedAce,
    OtherPrincipal,
    MissingCurrentUserRights,
}

#[cfg(windows)]
impl AclViolation {
    const fn message(self) -> &'static str {
        match self {
            Self::Owner => "the file owner is not the current user",
            Self::MissingDacl => "the file has no restrictive DACL",
            Self::UnprotectedDacl => "DACL inheritance is enabled",
            Self::InheritedAce => "the DACL contains an inherited ACE",
            Self::UnsupportedAce => "the DACL contains an unsupported ACE",
            Self::OtherPrincipal => "the DACL grants access to another principal",
            Self::MissingCurrentUserRights => "the current user lacks explicit read rights",
        }
    }
}

#[cfg(any(windows, test))]
fn validate_acl(facts: &AclFacts) -> Result<(), AclViolation> {
    if !facts.owner_is_current_user {
        return Err(AclViolation::Owner);
    }
    if !facts.dacl_present {
        return Err(AclViolation::MissingDacl);
    }
    if !facts.dacl_protected {
        return Err(AclViolation::UnprotectedDacl);
    }

    let mut current_user_rights = 0_u32;
    for entry in &facts.entries {
        if entry.flags & 0x10 != 0 {
            return Err(AclViolation::InheritedAce);
        }
        // Private session files only accept simple, non-inheriting allow ACEs.
        // Callback, object, deny, audit, and inherit-only entries are rejected
        // so the accepted DACL has one exact, auditable interpretation.
        if entry.kind != AceKind::Allow || entry.flags != 0 {
            return Err(AclViolation::UnsupportedAce);
        }
        if !entry.current_user {
            return Err(AclViolation::OtherPrincipal);
        }
        current_user_rights |= entry.mask;
    }

    if current_user_rights & (GENERIC_ALL | GENERIC_READ) == 0
        && current_user_rights & FILE_GENERIC_READ != FILE_GENERIC_READ
    {
        return Err(AclViolation::MissingCurrentUserRights);
    }
    Ok(())
}

#[cfg(unix)]
pub(crate) fn enforce_private_permissions(file: &File) -> Result<(), SessionError> {
    use std::os::unix::fs::PermissionsExt;

    let mode = file.metadata()?.permissions().mode();
    if mode & 0o077 != 0 {
        return Err(SessionError::InsecureSessionPermissions(mode & 0o777));
    }
    Ok(())
}

#[cfg(windows)]
pub(crate) fn enforce_private_permissions(file: &File) -> Result<(), SessionError> {
    let facts = windows::inspect(file)?;
    validate_acl(&facts)
        .map_err(|violation| SessionError::InsecureWindowsSessionAcl(violation.message()))
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn enforce_private_permissions(_file: &File) -> Result<(), SessionError> {
    Err(SessionError::Io(io::Error::new(
        io::ErrorKind::Unsupported,
        "private session permissions are unsupported on this platform",
    )))
}

#[cfg(windows)]
mod windows {
    use std::ffi::c_void;
    use std::fs::File;
    use std::io;
    use std::os::windows::io::AsRawHandle;
    use std::ptr::null_mut;

    use windows_sys::Win32::Foundation::{
        CloseHandle, ERROR_INSUFFICIENT_BUFFER, HANDLE, LocalFree,
    };
    use windows_sys::Win32::Security::Authorization::{GetSecurityInfo, SE_FILE_OBJECT};
    use windows_sys::Win32::Security::{
        ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, DACL_SECURITY_INFORMATION, EqualSid, GetAce,
        GetSecurityDescriptorControl, GetTokenInformation, OWNER_SECURITY_INFORMATION,
        PSECURITY_DESCRIPTOR, PSID, SE_DACL_PRESENT, SE_DACL_PROTECTED, TOKEN_QUERY, TOKEN_USER,
        TokenUser,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    use super::{AceFacts, AceKind, AclFacts};

    const ACCESS_ALLOWED_ACE_TYPE: u8 = 0;

    struct OwnedHandle(HANDLE);

    impl Drop for OwnedHandle {
        fn drop(&mut self) {
            // SAFETY: this owns the successful OpenProcessToken result.
            unsafe { CloseHandle(self.0) };
        }
    }

    struct LocalSecurityDescriptor(PSECURITY_DESCRIPTOR);

    impl Drop for LocalSecurityDescriptor {
        fn drop(&mut self) {
            // SAFETY: GetSecurityInfo allocates this descriptor with LocalAlloc.
            unsafe { LocalFree(self.0.cast::<c_void>()) };
        }
    }

    pub(super) fn inspect(file: &File) -> Result<AclFacts, io::Error> {
        let token_user = current_user()?;
        // SAFETY: a successful TokenUser query starts with TOKEN_USER, and its
        // referenced SID remains alive for the duration of this function.
        let current_sid = unsafe { (*(token_user.as_ptr().cast::<TOKEN_USER>())).User.Sid };

        let mut owner: PSID = null_mut();
        let mut dacl: *mut ACL = null_mut();
        let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
        // GetSecurityInfo examines the exact already-opened file, so replacing
        // the path after this point cannot substitute an unchecked session.
        // SAFETY: all output pointers are valid and the raw handle belongs to
        // `file` for at least the duration of this call.
        let status = unsafe {
            GetSecurityInfo(
                file.as_raw_handle() as HANDLE,
                SE_FILE_OBJECT,
                OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
                &mut owner,
                null_mut(),
                &mut dacl,
                null_mut(),
                &mut descriptor,
            )
        };
        if status != 0 {
            return Err(io::Error::from_raw_os_error(status as i32));
        }
        if descriptor.is_null() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "GetSecurityInfo returned no security descriptor",
            ));
        }
        let _descriptor = LocalSecurityDescriptor(descriptor);

        let mut control = 0_u16;
        let mut revision = 0_u32;
        // SAFETY: descriptor remains owned by `_descriptor` through this call.
        if unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) } == 0 {
            return Err(io::Error::last_os_error());
        }

        let owner_is_current_user =
            !owner.is_null() && unsafe { EqualSid(owner, current_sid) } != 0;
        let dacl_present = control & SE_DACL_PRESENT != 0 && !dacl.is_null();
        let dacl_protected = control & SE_DACL_PROTECTED != 0;
        let mut entries = Vec::new();
        if dacl_present {
            // SAFETY: dacl points inside the live security descriptor.
            let ace_count = unsafe { (*dacl).AceCount };
            entries.reserve(usize::from(ace_count));
            for index in 0..u32::from(ace_count) {
                let mut raw_ace = null_mut();
                // SAFETY: GetAce validates `index` against the ACL itself.
                if unsafe { GetAce(dacl, index, &mut raw_ace) } == 0 || raw_ace.is_null() {
                    return Err(io::Error::last_os_error());
                }
                // SAFETY: every ACE begins with ACE_HEADER.
                let header = unsafe { &*(raw_ace.cast::<ACE_HEADER>()) };
                if header.AceType != ACCESS_ALLOWED_ACE_TYPE
                    || usize::from(header.AceSize) < std::mem::size_of::<ACCESS_ALLOWED_ACE>()
                {
                    entries.push(AceFacts {
                        kind: AceKind::Unsupported,
                        flags: header.AceFlags,
                        current_user: false,
                        mask: 0,
                    });
                    continue;
                }
                // SAFETY: the size check above proves the fixed ACE prefix is
                // present; SidStart is the documented start of the inline SID.
                let ace = unsafe { &*(raw_ace.cast::<ACCESS_ALLOWED_ACE>()) };
                let ace_sid = std::ptr::addr_of!(ace.SidStart).cast_mut().cast::<c_void>();
                let current_user = unsafe { EqualSid(ace_sid, current_sid) } != 0;
                entries.push(AceFacts {
                    kind: AceKind::Allow,
                    flags: ace.Header.AceFlags,
                    current_user,
                    mask: ace.Mask,
                });
            }
        }

        Ok(AclFacts {
            owner_is_current_user,
            dacl_present,
            dacl_protected,
            entries,
        })
    }

    fn current_user() -> Result<Vec<usize>, io::Error> {
        let mut token = null_mut();
        // SAFETY: output pointer is valid and TOKEN_QUERY is sufficient.
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let token = OwnedHandle(token);

        let mut required = 0_u32;
        // SAFETY: null/zero is the documented size-probe form.
        unsafe { GetTokenInformation(token.0, TokenUser, null_mut(), 0, &mut required) };
        let probe_error = io::Error::last_os_error();
        if probe_error.raw_os_error() != Some(ERROR_INSUFFICIENT_BUFFER as i32) || required == 0 {
            return Err(probe_error);
        }

        let word_size = std::mem::size_of::<usize>();
        let mut buffer = vec![0_usize; (required as usize).div_ceil(word_size)];
        // SAFETY: the buffer is aligned and has the probed byte capacity.
        if unsafe {
            GetTokenInformation(
                token.0,
                TokenUser,
                buffer.as_mut_ptr().cast(),
                required,
                &mut required,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(buffer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn private_acl(entries: Vec<AceFacts>) -> AclFacts {
        AclFacts {
            owner_is_current_user: true,
            dacl_present: true,
            dacl_protected: true,
            entries,
        }
    }

    fn allow(current_user: bool, flags: u8, mask: u32) -> AceFacts {
        AceFacts {
            kind: AceKind::Allow,
            flags,
            current_user,
            mask,
        }
    }

    #[test]
    fn accepts_only_explicit_current_user_full_control() {
        let facts = private_acl(vec![allow(true, 0, 0x001f_01ff)]);
        assert_eq!(validate_acl(&facts), Ok(()));
    }

    #[test]
    fn accepts_explicit_current_user_read_only_access() {
        let facts = private_acl(vec![allow(true, 0, FILE_GENERIC_READ)]);
        assert_eq!(validate_acl(&facts), Ok(()));
        let generic = private_acl(vec![allow(true, 0, GENERIC_READ)]);
        assert_eq!(validate_acl(&generic), Ok(()));
    }

    #[test]
    fn rejects_owner_mismatch_null_or_unprotected_dacl() {
        let mut facts = private_acl(vec![allow(true, 0, GENERIC_ALL)]);
        facts.owner_is_current_user = false;
        assert_eq!(validate_acl(&facts), Err(AclViolation::Owner));
        facts.owner_is_current_user = true;
        facts.dacl_present = false;
        assert_eq!(validate_acl(&facts), Err(AclViolation::MissingDacl));
        facts.dacl_present = true;
        facts.dacl_protected = false;
        assert_eq!(validate_acl(&facts), Err(AclViolation::UnprotectedDacl));
    }

    #[test]
    fn rejects_inherited_other_or_non_allow_aces() {
        assert_eq!(
            validate_acl(&private_acl(vec![allow(true, 0x10, GENERIC_ALL)])),
            Err(AclViolation::InheritedAce)
        );
        assert_eq!(
            validate_acl(&private_acl(vec![allow(false, 0, GENERIC_ALL)])),
            Err(AclViolation::OtherPrincipal)
        );
        assert_eq!(
            validate_acl(&private_acl(vec![AceFacts {
                kind: AceKind::Unsupported,
                flags: 0,
                current_user: true,
                mask: GENERIC_ALL,
            }])),
            Err(AclViolation::UnsupportedAce)
        );
    }

    #[test]
    fn rejects_current_user_without_complete_read_access() {
        assert_eq!(
            validate_acl(&private_acl(vec![allow(true, 0, 0x0000_0001)])),
            Err(AclViolation::MissingCurrentUserRights)
        );
        assert_eq!(
            validate_acl(&private_acl(Vec::new())),
            Err(AclViolation::MissingCurrentUserRights)
        );
    }
}
