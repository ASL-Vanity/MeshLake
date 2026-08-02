//! Restricted file helpers for operational secrets.

use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};
use thiserror::Error;
use zeroize::Zeroizing;

const MAX_SECRET_FILE_BYTES: u64 = 64 * 1024;

#[derive(Debug, Error)]
pub enum SecretFileError {
    #[error("secret file is not a regular file: {0}")]
    NotRegular(PathBuf),
    #[error("secret file exceeds the 64 KiB size limit: {0}")]
    TooLarge(PathBuf),
    #[error("secret file permissions are not restricted: {0}")]
    InsecurePermissions(PathBuf),
    #[error("secret output file already exists: {0}")]
    AlreadyExists(PathBuf),
    #[error("cannot {action} secret file {path}: {source}")]
    Io {
        action: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[cfg(windows)]
    #[error("cannot {action} restricted Windows ACL for {path}: error {code}")]
    WindowsAcl {
        action: &'static str,
        path: PathBuf,
        code: u32,
    },
}

pub fn read_restricted_secret_file(path: &Path) -> Result<Zeroizing<Vec<u8>>, SecretFileError> {
    verify_restricted_secret_file(path)?;
    let metadata = fs::metadata(path).map_err(|source| secret_io("inspect", path, source))?;
    if metadata.len() > MAX_SECRET_FILE_BYTES {
        return Err(SecretFileError::TooLarge(path.to_path_buf()));
    }
    let file = File::open(path).map_err(|source| secret_io("open", path, source))?;
    let mut bytes = Zeroizing::new(Vec::with_capacity(metadata.len() as usize));
    file.take(MAX_SECRET_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| secret_io("read", path, source))?;
    if bytes.len() as u64 > MAX_SECRET_FILE_BYTES {
        return Err(SecretFileError::TooLarge(path.to_path_buf()));
    }
    Ok(bytes)
}

pub fn create_restricted_secret_file(path: &Path, contents: &[u8]) -> Result<(), SecretFileError> {
    let parent = path
        .parent()
        .filter(|value| !value.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)
        .map_err(|source| secret_io("create parent directory for", path, source))?;

    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|source| {
        if source.kind() == std::io::ErrorKind::AlreadyExists {
            SecretFileError::AlreadyExists(path.to_path_buf())
        } else {
            secret_io("create", path, source)
        }
    })?;

    let result = (|| {
        restrict_secret_file_permissions(path)?;
        file.write_all(contents)
            .map_err(|source| secret_io("write", path, source))?;
        file.sync_all()
            .map_err(|source| secret_io("sync", path, source))?;
        drop(file);
        verify_restricted_secret_file(path)
    })();
    if result.is_err() {
        let _ = fs::remove_file(path);
    }
    result
}

pub fn verify_restricted_secret_file(path: &Path) -> Result<(), SecretFileError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|source| secret_io("inspect", path, source))?;
    if !metadata.file_type().is_file() {
        return Err(SecretFileError::NotRegular(path.to_path_buf()));
    }
    verify_platform_permissions(path, &metadata)
}

#[cfg(unix)]
fn restrict_secret_file_permissions(path: &Path) -> Result<(), SecretFileError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|source| secret_io("restrict permissions on", path, source))
}

#[cfg(unix)]
fn verify_platform_permissions(
    path: &Path,
    metadata: &fs::Metadata,
) -> Result<(), SecretFileError> {
    use std::os::unix::fs::PermissionsExt;
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(SecretFileError::InsecurePermissions(path.to_path_buf()));
    }
    Ok(())
}

#[cfg(windows)]
fn restrict_secret_file_permissions(path: &Path) -> Result<(), SecretFileError> {
    windows_acl::restrict(path)
}

#[cfg(windows)]
fn verify_platform_permissions(path: &Path, _: &fs::Metadata) -> Result<(), SecretFileError> {
    windows_acl::verify(path)
}

fn secret_io(action: &'static str, path: &Path, source: std::io::Error) -> SecretFileError {
    SecretFileError::Io {
        action,
        path: path.to_path_buf(),
        source,
    }
}

#[cfg(windows)]
mod windows_acl {
    use super::SecretFileError;
    use std::{ffi::c_void, mem::size_of, os::windows::ffi::OsStrExt, path::Path, ptr};
    use windows_sys::Win32::{
        Foundation::{CloseHandle, LocalFree, ERROR_INSUFFICIENT_BUFFER, ERROR_SUCCESS, HANDLE},
        Security::{
            AclSizeInformation,
            Authorization::{
                BuildTrusteeWithSidW, GetNamedSecurityInfoW, SetEntriesInAclW,
                SetNamedSecurityInfoW, EXPLICIT_ACCESS_W, GRANT_ACCESS, SE_FILE_OBJECT,
                TRUSTEE_IS_SID,
            },
            CreateWellKnownSid, EqualSid, GetAce, GetAclInformation, GetSecurityDescriptorControl,
            GetTokenInformation, TokenUser, WinLocalSystemSid, ACL, ACL_SIZE_INFORMATION,
            DACL_SECURITY_INFORMATION, NO_INHERITANCE, PROTECTED_DACL_SECURITY_INFORMATION,
            PSECURITY_DESCRIPTOR, PSID, SE_DACL_PROTECTED, TOKEN_QUERY, TOKEN_USER,
        },
        Storage::FileSystem::FILE_ALL_ACCESS,
        System::SystemServices::ACCESS_ALLOWED_ACE_TYPE,
        System::Threading::{GetCurrentProcess, OpenProcessToken},
    };

    pub(super) fn restrict(path: &Path) -> Result<(), SecretFileError> {
        let current = current_user_sid(path)?;
        let system = local_system_sid(path)?;
        let mut entries = [
            explicit_access(current.as_ptr().cast_mut().cast()),
            explicit_access(system.as_ptr().cast_mut().cast()),
        ];
        if current == system {
            entries[1].grfAccessPermissions = 0;
        }
        let entry_count = if current == system { 1 } else { 2 };
        let mut acl: *mut ACL = ptr::null_mut();
        let status =
            unsafe { SetEntriesInAclW(entry_count, entries.as_ptr(), ptr::null(), &mut acl) };
        if status != ERROR_SUCCESS {
            return Err(acl_error("build", path, status));
        }
        let wide = wide_path(path);
        let status = unsafe {
            SetNamedSecurityInfoW(
                wide.as_ptr().cast_mut(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                acl,
                ptr::null(),
            )
        };
        unsafe { LocalFree(acl.cast()) };
        if status != ERROR_SUCCESS {
            return Err(acl_error("apply", path, status));
        }
        verify(path)
    }

    pub(super) fn verify(path: &Path) -> Result<(), SecretFileError> {
        let current = current_user_sid(path)?;
        let system = local_system_sid(path)?;
        let wide = wide_path(path);
        let mut acl: *mut ACL = ptr::null_mut();
        let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
        let status = unsafe {
            GetNamedSecurityInfoW(
                wide.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                ptr::null_mut(),
                ptr::null_mut(),
                &mut acl,
                ptr::null_mut(),
                &mut descriptor,
            )
        };
        if status != ERROR_SUCCESS {
            return Err(acl_error("read", path, status));
        }
        let result = (|| {
            if acl.is_null() {
                return Err(SecretFileError::InsecurePermissions(path.to_path_buf()));
            }
            let mut control = 0_u16;
            let mut revision = 0_u32;
            if unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) } == 0
                || control & SE_DACL_PROTECTED == 0
            {
                return Err(SecretFileError::InsecurePermissions(path.to_path_buf()));
            }
            let mut info = ACL_SIZE_INFORMATION {
                AceCount: 0,
                AclBytesInUse: 0,
                AclBytesFree: 0,
            };
            if unsafe {
                GetAclInformation(
                    acl,
                    (&mut info as *mut ACL_SIZE_INFORMATION).cast(),
                    size_of::<ACL_SIZE_INFORMATION>() as u32,
                    AclSizeInformation,
                )
            } == 0
            {
                return Err(acl_error("inspect", path, unsafe {
                    windows_sys::Win32::Foundation::GetLastError()
                }));
            }
            if info.AceCount == 0 || info.AceCount > 2 {
                return Err(SecretFileError::InsecurePermissions(path.to_path_buf()));
            }
            for index in 0..info.AceCount {
                let mut ace: *mut c_void = ptr::null_mut();
                if unsafe { GetAce(acl, index, &mut ace) } == 0 {
                    return Err(acl_error("inspect", path, unsafe {
                        windows_sys::Win32::Foundation::GetLastError()
                    }));
                }
                let allowed =
                    unsafe { &*(ace as *const windows_sys::Win32::Security::ACCESS_ALLOWED_ACE) };
                if allowed.Header.AceType != ACCESS_ALLOWED_ACE_TYPE as u8
                    || allowed.Mask & FILE_ALL_ACCESS != FILE_ALL_ACCESS
                {
                    return Err(SecretFileError::InsecurePermissions(path.to_path_buf()));
                }
                let sid = (&allowed.SidStart as *const u32)
                    .cast_mut()
                    .cast::<c_void>();
                if unsafe { EqualSid(sid, current.as_ptr().cast_mut().cast()) } == 0
                    && unsafe { EqualSid(sid, system.as_ptr().cast_mut().cast()) } == 0
                {
                    return Err(SecretFileError::InsecurePermissions(path.to_path_buf()));
                }
            }
            Ok(())
        })();
        unsafe { LocalFree(descriptor) };
        result
    }

    fn explicit_access(sid: PSID) -> EXPLICIT_ACCESS_W {
        let mut entry: EXPLICIT_ACCESS_W = unsafe { std::mem::zeroed() };
        entry.grfAccessPermissions = FILE_ALL_ACCESS;
        entry.grfAccessMode = GRANT_ACCESS;
        entry.grfInheritance = NO_INHERITANCE;
        unsafe { BuildTrusteeWithSidW(&mut entry.Trustee, sid) };
        entry.Trustee.TrusteeForm = TRUSTEE_IS_SID;
        entry
    }

    fn current_user_sid(path: &Path) -> Result<Vec<u8>, SecretFileError> {
        let mut token: HANDLE = ptr::null_mut();
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
            return Err(acl_error("open process token for", path, unsafe {
                windows_sys::Win32::Foundation::GetLastError()
            }));
        }
        let result = (|| {
            let mut required = 0_u32;
            unsafe { GetTokenInformation(token, TokenUser, ptr::null_mut(), 0, &mut required) };
            let error = unsafe { windows_sys::Win32::Foundation::GetLastError() };
            if error != ERROR_INSUFFICIENT_BUFFER || required == 0 {
                return Err(acl_error("query process token for", path, error));
            }
            let mut buffer = vec![0_u8; required as usize];
            if unsafe {
                GetTokenInformation(
                    token,
                    TokenUser,
                    buffer.as_mut_ptr().cast(),
                    required,
                    &mut required,
                )
            } == 0
            {
                return Err(acl_error("read process token for", path, unsafe {
                    windows_sys::Win32::Foundation::GetLastError()
                }));
            }
            let user = unsafe { &*(buffer.as_ptr() as *const TOKEN_USER) };
            copy_sid(user.User.Sid, path)
        })();
        unsafe { CloseHandle(token) };
        result
    }

    fn local_system_sid(path: &Path) -> Result<Vec<u8>, SecretFileError> {
        let mut length = windows_sys::Win32::Security::SECURITY_MAX_SID_SIZE as u32;
        let mut sid = vec![0_u8; length as usize];
        if unsafe {
            CreateWellKnownSid(
                WinLocalSystemSid,
                ptr::null_mut(),
                sid.as_mut_ptr().cast(),
                &mut length,
            )
        } == 0
        {
            return Err(acl_error("create LocalSystem SID for", path, unsafe {
                windows_sys::Win32::Foundation::GetLastError()
            }));
        }
        sid.truncate(length as usize);
        Ok(sid)
    }

    fn copy_sid(sid: PSID, path: &Path) -> Result<Vec<u8>, SecretFileError> {
        let length = unsafe { windows_sys::Win32::Security::GetLengthSid(sid) };
        if length == 0 {
            return Err(acl_error("inspect process SID for", path, unsafe {
                windows_sys::Win32::Foundation::GetLastError()
            }));
        }
        Ok(unsafe { std::slice::from_raw_parts(sid.cast::<u8>(), length as usize) }.to_vec())
    }

    fn wide_path(path: &Path) -> Vec<u16> {
        path.as_os_str().encode_wide().chain(Some(0)).collect()
    }

    fn acl_error(action: &'static str, path: &Path, code: u32) -> SecretFileError {
        SecretFileError::WindowsAcl {
            action,
            path: path.to_path_buf(),
            code,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn test_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("meshlake-secret-file-{name}-{}", Uuid::new_v4()))
    }

    #[test]
    fn restricted_secret_file_refuses_overwrite_and_round_trips() {
        let path = test_path("round-trip");
        create_restricted_secret_file(&path, b"secret\n").unwrap();
        assert_eq!(
            read_restricted_secret_file(&path).unwrap().as_slice(),
            b"secret\n"
        );
        assert!(matches!(
            create_restricted_secret_file(&path, b"replacement"),
            Err(SecretFileError::AlreadyExists(_))
        ));
        assert_eq!(fs::read(&path).unwrap(), b"secret\n");
        fs::remove_file(path).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn unix_rejects_group_or_other_secret_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let path = test_path("permissions");
        fs::write(&path, b"secret").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        assert!(matches!(
            read_restricted_secret_file(&path),
            Err(SecretFileError::InsecurePermissions(_))
        ));
        fs::remove_file(path).unwrap();
    }
}
