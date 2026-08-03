//! Restricted file helpers for operational secrets.

use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};
use thiserror::Error;
use zeroize::{Zeroize, Zeroizing};

const MAX_SECRET_FILE_BYTES: u64 = 64 * 1024;

#[derive(Debug, Error)]
pub enum SecretFileError {
    #[error("secret file is not a regular file: {0}")]
    NotRegular(PathBuf),
    #[error("secret file path changed while it was open: {0}")]
    PathChanged(PathBuf),
    #[error("secret file exceeds the 64 KiB size limit: {0}")]
    TooLarge(PathBuf),
    #[error("secret file permissions are not restricted: {0}")]
    InsecurePermissions(PathBuf),
    #[error("secret file is not valid UTF-8: {0}")]
    InvalidUtf8(PathBuf),
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
    read_secret_file_no_follow(path, true)
}

pub fn read_restricted_secret_string_file(
    path: &Path,
) -> Result<Zeroizing<String>, SecretFileError> {
    let bytes = read_secret_file_bytes(path, true)?;
    match String::from_utf8(bytes) {
        Ok(value) => Ok(Zeroizing::new(value)),
        Err(error) => {
            let mut bytes = error.into_bytes();
            bytes.zeroize();
            Err(SecretFileError::InvalidUtf8(path.to_path_buf()))
        }
    }
}

pub(crate) fn read_secret_file_no_follow(
    path: &Path,
    require_restricted_permissions: bool,
) -> Result<Zeroizing<Vec<u8>>, SecretFileError> {
    read_secret_file_bytes(path, require_restricted_permissions).map(Zeroizing::new)
}

fn read_secret_file_bytes(
    path: &Path,
    require_restricted_permissions: bool,
) -> Result<Vec<u8>, SecretFileError> {
    let mut file = open_secret_file_for_read(path)?;
    let metadata = verify_open_secret_file(&file, path, require_restricted_permissions)?;
    if metadata.len() > MAX_SECRET_FILE_BYTES {
        return Err(SecretFileError::TooLarge(path.to_path_buf()));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    if let Err(source) = std::io::Read::by_ref(&mut file)
        .take(MAX_SECRET_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
    {
        bytes.zeroize();
        return Err(secret_io("read", path, source));
    }
    if bytes.len() as u64 > MAX_SECRET_FILE_BYTES {
        bytes.zeroize();
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

    let mut file = create_secret_file_handle(path)?;
    let result = (|| {
        verify_open_file_is_regular(&file, path)?;
        restrict_open_secret_file_permissions(&file, path)?;
        file.write_all(contents)
            .map_err(|source| secret_io("write", path, source))?;
        file.sync_all()
            .map_err(|source| secret_io("sync", path, source))?;
        verify_open_secret_file(&file, path, true)?;
        verify_path_still_references_open_file(&file, path)
    })();

    let remove_path = result.is_err() && path_still_references_open_file(&file, path);
    if result.is_err() {
        let _ = file.set_len(0);
        let _ = file.sync_all();
    }
    drop(file);
    if remove_path {
        let _ = fs::remove_file(path);
    }
    result
}

pub fn verify_restricted_secret_file(path: &Path) -> Result<(), SecretFileError> {
    let file = open_secret_file_for_read(path)?;
    verify_open_secret_file(&file, path, true).map(|_| ())
}

fn verify_open_secret_file(
    file: &File,
    path: &Path,
    require_restricted_permissions: bool,
) -> Result<fs::Metadata, SecretFileError> {
    let metadata = verify_open_file_is_regular(file, path)?;
    if require_restricted_permissions {
        verify_platform_permissions(file, path, &metadata)?;
    }
    Ok(metadata)
}

fn verify_open_file_is_regular(file: &File, path: &Path) -> Result<fs::Metadata, SecretFileError> {
    let metadata = file
        .metadata()
        .map_err(|source| secret_io("inspect opened", path, source))?;
    if !metadata.is_file() {
        return Err(SecretFileError::NotRegular(path.to_path_buf()));
    }
    verify_platform_file_type(file, path)?;
    Ok(metadata)
}

#[cfg(unix)]
fn open_secret_file_for_read(path: &Path) -> Result<File, SecretFileError> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|source| secret_io("open without following a final symlink", path, source))
}

#[cfg(windows)]
fn open_secret_file_for_read(path: &Path) -> Result<File, SecretFileError> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ, FILE_SHARE_READ,
    };
    OpenOptions::new()
        .read(true)
        .access_mode(FILE_GENERIC_READ)
        .share_mode(FILE_SHARE_READ)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|source| secret_io("open without following a final reparse point", path, source))
}

#[cfg(unix)]
fn create_secret_file_handle(path: &Path) -> Result<File, SecretFileError> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|source| create_error(path, source))
}

#[cfg(windows)]
fn create_secret_file_handle(path: &Path) -> Result<File, SecretFileError> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ, FILE_GENERIC_WRITE, WRITE_DAC,
    };
    OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .access_mode(FILE_GENERIC_READ | FILE_GENERIC_WRITE | WRITE_DAC)
        .share_mode(0)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|source| create_error(path, source))
}

fn create_error(path: &Path, source: std::io::Error) -> SecretFileError {
    if source.kind() == std::io::ErrorKind::AlreadyExists {
        SecretFileError::AlreadyExists(path.to_path_buf())
    } else {
        secret_io("create", path, source)
    }
}

#[cfg(unix)]
fn restrict_open_secret_file_permissions(file: &File, path: &Path) -> Result<(), SecretFileError> {
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|source| secret_io("restrict permissions on opened", path, source))?;
    let metadata = file
        .metadata()
        .map_err(|source| secret_io("inspect opened", path, source))?;
    verify_platform_permissions(file, path, &metadata)
}

#[cfg(unix)]
fn verify_platform_permissions(
    _: &File,
    path: &Path,
    metadata: &fs::Metadata,
) -> Result<(), SecretFileError> {
    use std::os::unix::fs::PermissionsExt;
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(SecretFileError::InsecurePermissions(path.to_path_buf()));
    }
    Ok(())
}

#[cfg(unix)]
fn verify_platform_file_type(_: &File, _: &Path) -> Result<(), SecretFileError> {
    Ok(())
}

#[cfg(unix)]
fn path_still_references_open_file(file: &File, path: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    let Ok(opened) = file.metadata() else {
        return false;
    };
    let Ok(current) = fs::symlink_metadata(path) else {
        return false;
    };
    current.file_type().is_file() && opened.dev() == current.dev() && opened.ino() == current.ino()
}

#[cfg(windows)]
fn path_still_references_open_file(_: &File, _: &Path) -> bool {
    // The creation handle denies delete and write sharing until it is dropped.
    true
}

fn verify_path_still_references_open_file(file: &File, path: &Path) -> Result<(), SecretFileError> {
    if path_still_references_open_file(file, path) {
        Ok(())
    } else {
        Err(SecretFileError::PathChanged(path.to_path_buf()))
    }
}

fn secret_io(action: &'static str, path: &Path, source: std::io::Error) -> SecretFileError {
    SecretFileError::Io {
        action,
        path: path.to_path_buf(),
        source,
    }
}

#[cfg(windows)]
fn restrict_open_secret_file_permissions(file: &File, path: &Path) -> Result<(), SecretFileError> {
    windows_acl::restrict(file, path)
}

#[cfg(windows)]
fn verify_platform_permissions(
    file: &File,
    path: &Path,
    _: &fs::Metadata,
) -> Result<(), SecretFileError> {
    windows_acl::verify(file, path)
}

#[cfg(windows)]
fn verify_platform_file_type(file: &File, path: &Path) -> Result<(), SecretFileError> {
    windows_acl::verify_regular_file(file, path)
}

#[cfg(windows)]
mod windows_acl {
    use super::SecretFileError;
    use std::{ffi::c_void, fs::File, mem::size_of, os::windows::io::AsRawHandle, path::Path, ptr};
    use windows_sys::Win32::{
        Foundation::{LocalFree, ERROR_INSUFFICIENT_BUFFER, ERROR_SUCCESS, HANDLE},
        Security::{
            AclSizeInformation,
            Authorization::{
                BuildTrusteeWithSidW, GetSecurityInfo, SetEntriesInAclW, SetSecurityInfo,
                EXPLICIT_ACCESS_W, GRANT_ACCESS, SE_FILE_OBJECT, TRUSTEE_IS_SID,
            },
            CreateWellKnownSid, EqualSid, GetAce, GetAclInformation, GetSecurityDescriptorControl,
            GetTokenInformation, TokenUser, WinLocalSystemSid, ACL, ACL_SIZE_INFORMATION,
            DACL_SECURITY_INFORMATION, NO_INHERITANCE, PROTECTED_DACL_SECURITY_INFORMATION,
            PSECURITY_DESCRIPTOR, PSID, SE_DACL_PROTECTED, TOKEN_QUERY, TOKEN_USER,
        },
        Storage::FileSystem::{
            GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION, FILE_ALL_ACCESS,
            FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
        },
        System::{
            SystemServices::ACCESS_ALLOWED_ACE_TYPE,
            Threading::{GetCurrentProcess, OpenProcessToken},
        },
    };

    pub(super) fn verify_regular_file(file: &File, path: &Path) -> Result<(), SecretFileError> {
        let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
        if unsafe { GetFileInformationByHandle(handle(file), &mut info) } == 0 {
            return Err(acl_error("inspect opened file type for", path, unsafe {
                windows_sys::Win32::Foundation::GetLastError()
            }));
        }
        if info.dwFileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
            return Err(SecretFileError::NotRegular(path.to_path_buf()));
        }
        Ok(())
    }

    pub(super) fn restrict(file: &File, path: &Path) -> Result<(), SecretFileError> {
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
        let status = unsafe {
            SetSecurityInfo(
                handle(file),
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
        verify(file, path)
    }

    pub(super) fn verify(file: &File, path: &Path) -> Result<(), SecretFileError> {
        let current = current_user_sid(path)?;
        let system = local_system_sid(path)?;
        let same_identity = current == system;
        let mut acl: *mut ACL = ptr::null_mut();
        let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
        let status = unsafe {
            GetSecurityInfo(
                handle(file),
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
            let expected_count = if same_identity { 1 } else { 2 };
            if info.AceCount != expected_count {
                return Err(SecretFileError::InsecurePermissions(path.to_path_buf()));
            }
            let mut saw_current = false;
            let mut saw_system = false;
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
                if unsafe { EqualSid(sid, current.as_ptr().cast_mut().cast()) } != 0 {
                    saw_current = true;
                } else if unsafe { EqualSid(sid, system.as_ptr().cast_mut().cast()) } != 0 {
                    saw_system = true;
                } else {
                    return Err(SecretFileError::InsecurePermissions(path.to_path_buf()));
                }
            }
            if !saw_current || (!same_identity && !saw_system) {
                return Err(SecretFileError::InsecurePermissions(path.to_path_buf()));
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
        unsafe { windows_sys::Win32::Foundation::CloseHandle(token) };
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

    fn handle(file: &File) -> HANDLE {
        file.as_raw_handle().cast()
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
        assert_eq!(
            read_restricted_secret_string_file(&path).unwrap().as_str(),
            "secret\n"
        );
        assert!(matches!(
            create_restricted_secret_file(&path, b"replacement"),
            Err(SecretFileError::AlreadyExists(_))
        ));
        assert_eq!(fs::read(&path).unwrap(), b"secret\n");
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn invalid_utf8_is_rejected_without_returning_secret_bytes() {
        let path = test_path("invalid-utf8");
        create_restricted_secret_file(&path, &[0xff, 0xfe, 0xfd]).unwrap();
        assert!(matches!(
            read_restricted_secret_string_file(&path),
            Err(SecretFileError::InvalidUtf8(_))
        ));
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

    #[cfg(unix)]
    #[test]
    fn unix_rejects_a_final_symlink() {
        use std::os::unix::fs::symlink;
        let target = test_path("symlink-target");
        let link = test_path("symlink-link");
        create_restricted_secret_file(&target, b"secret").unwrap();
        symlink(&target, &link).unwrap();
        assert!(read_restricted_secret_file(&link).is_err());
        fs::remove_file(link).unwrap();
        fs::remove_file(target).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn unix_permission_check_uses_the_opened_handle_not_a_replaced_path() {
        use std::os::unix::fs::PermissionsExt;
        let path = test_path("opened-handle");
        let moved = test_path("opened-handle-moved");
        let replacement = test_path("opened-handle-replacement");
        create_restricted_secret_file(&path, b"original").unwrap();
        fs::write(&replacement, b"replacement").unwrap();
        fs::set_permissions(&replacement, fs::Permissions::from_mode(0o644)).unwrap();

        let mut opened = open_secret_file_for_read(&path).unwrap();
        fs::rename(&path, &moved).unwrap();
        fs::rename(&replacement, &path).unwrap();
        verify_open_secret_file(&opened, &path, true).unwrap();
        let mut value = String::new();
        opened.read_to_string(&mut value).unwrap();
        assert_eq!(value, "original");

        fs::remove_file(path).unwrap();
        fs::remove_file(moved).unwrap();
    }
}
