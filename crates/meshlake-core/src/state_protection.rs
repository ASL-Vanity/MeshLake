//! Platform state-file protection shared by the agent and controller.
//!
//! Windows stores serialized state inside a machine-bound DPAPI envelope so
//! autostarted SYSTEM services and an interactive administrator can use the
//! same state file. Unix-like systems keep JSON for service portability and
//! rely on the caller to enforce mode 0600.

#[cfg(windows)]
use base64::{engine::general_purpose::STANDARD, Engine as _};
use fs2::FileExt;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};
use thiserror::Error;
use uuid::Uuid;
use zeroize::Zeroizing;

const ENVELOPE_VERSION: u8 = 1;
const WINDOWS_DPAPI_PROTECTION: &str = "windows-dpapi-local-machine";
pub const AGENT_STATE_PROTECTION_PURPOSE: &[u8] = b"MeshLake agent state v1";
pub const CONTROLLER_STATE_PROTECTION_PURPOSE: &[u8] = b"MeshLake controller state v1";

/// Process-lifetime exclusive lock for one MeshLake state path.
///
/// The lock must be acquired before recovery, migration or the first write and
/// retained until the process exits. A dedicated sidecar is used so replacing
/// the state file never changes the locked file identity.
#[derive(Debug)]
pub struct StateFileLock {
    file: File,
}

impl StateFileLock {
    pub fn acquire(state_path: &Path) -> Result<Self, StateFileError> {
        let parent = state_parent(state_path);
        fs::create_dir_all(parent)
            .map_err(|source| state_io_error("create state directory", parent, source))?;
        let lock_path = suffixed_path(state_path, ".lock");
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&lock_path)
            .map_err(|source| state_io_error("open state lock", &lock_path, source))?;
        restrict_state_file_permissions(&lock_path)?;
        FileExt::try_lock_exclusive(&file).map_err(|source| StateFileError::Lock {
            path: state_path.to_path_buf(),
            source,
        })?;
        Ok(Self { file })
    }
}

impl Drop for StateFileLock {
    fn drop(&mut self) {
        let _ = FileExt::unlock(&self.file);
    }
}

#[derive(Debug)]
pub struct DecodedState<T> {
    pub value: T,
    /// True when a legacy plaintext Windows state should be rewritten into a
    /// DPAPI envelope after all schema migrations have completed.
    pub needs_protection_upgrade: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct ProtectedStateEnvelope {
    format_version: u8,
    protection: String,
    ciphertext_base64: String,
}

#[derive(Debug, Error)]
pub enum StateProtectionError {
    #[error("state JSON is invalid: {0}")]
    Json(#[from] serde_json::Error),
    #[error("protected state ciphertext is not valid Base64: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("protected state uses unsupported format version {0}")]
    UnsupportedVersion(u8),
    #[error("protected state uses unsupported protection {0}")]
    UnsupportedProtection(String),
    #[error("state or protection-purpose data exceeds the platform size limit")]
    SizeLimit,
    #[error("Windows DPAPI operation failed: {0}")]
    Platform(String),
}

#[derive(Debug, Error)]
pub enum StateFileError {
    #[error(transparent)]
    Protection(#[from] StateProtectionError),
    #[error("cannot exclusively lock MeshLake state {path}: {source}")]
    Lock {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("cannot {action} {path}: {source}")]
    Io {
        action: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

pub fn encode_protected_state<T: Serialize>(
    value: &T,
    purpose: &[u8],
) -> Result<Vec<u8>, StateProtectionError> {
    let plaintext = Zeroizing::new(serde_json::to_vec_pretty(value)?);
    encode_platform_state(&plaintext, purpose)
}

pub fn decode_protected_state<T: DeserializeOwned>(
    bytes: &[u8],
    purpose: &[u8],
) -> Result<DecodedState<T>, StateProtectionError> {
    decode_platform_state(bytes, purpose)
}

#[cfg(windows)]
fn encode_platform_state(
    plaintext: &[u8],
    purpose: &[u8],
) -> Result<Vec<u8>, StateProtectionError> {
    let protected = dpapi_protect(plaintext, purpose)?;
    Ok(serde_json::to_vec_pretty(&ProtectedStateEnvelope {
        format_version: ENVELOPE_VERSION,
        protection: WINDOWS_DPAPI_PROTECTION.to_owned(),
        ciphertext_base64: STANDARD.encode(protected),
    })?)
}

#[cfg(not(windows))]
fn encode_platform_state(
    plaintext: &[u8],
    _purpose: &[u8],
) -> Result<Vec<u8>, StateProtectionError> {
    Ok(plaintext.to_vec())
}

#[cfg(windows)]
fn decode_platform_state<T: DeserializeOwned>(
    bytes: &[u8],
    purpose: &[u8],
) -> Result<DecodedState<T>, StateProtectionError> {
    if let Ok(envelope) = serde_json::from_slice::<ProtectedStateEnvelope>(bytes) {
        validate_envelope(&envelope)?;
        let ciphertext = STANDARD.decode(envelope.ciphertext_base64)?;
        let plaintext = Zeroizing::new(dpapi_unprotect(&ciphertext, purpose)?);
        let value = serde_json::from_slice(&plaintext)?;
        return Ok(DecodedState {
            value,
            needs_protection_upgrade: false,
        });
    }
    Ok(DecodedState {
        value: serde_json::from_slice(bytes)?,
        needs_protection_upgrade: true,
    })
}

/// Recovers a backup left by an interrupted Windows replacement.
///
/// Callers must hold [`StateFileLock`] before invoking this function.
pub fn recover_protected_state_file(path: &Path) -> Result<(), StateFileError> {
    let backup = backup_path(path);
    if !path.exists() && backup.exists() {
        install_recovered_backup(&backup, path)?;
        restrict_state_file_permissions(path)?;
    }
    Ok(())
}

/// Removes a Windows replacement backup only after the caller has decoded and
/// validated the primary state file successfully.
///
/// `ReplaceFileW` briefly keeps the previous state at `<state>.bak`. During a
/// legacy plaintext-to-DPAPI migration, an abnormal shutdown after the replace
/// but before backup deletion can otherwise leave that plaintext backup on
/// disk indefinitely. Callers must hold [`StateFileLock`] and must not invoke
/// this function until the primary state has passed decoding, schema migration
/// and any required rewrite.
pub fn cleanup_stale_state_backup(path: &Path) -> Result<(), StateFileError> {
    cleanup_platform_stale_state_backup(path)
}

#[cfg(windows)]
fn cleanup_platform_stale_state_backup(path: &Path) -> Result<(), StateFileError> {
    let backup = backup_path(path);
    match fs::remove_file(&backup) {
        Ok(()) => Ok(()),
        Err(source) if source.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(state_io_error(
            "remove stale state backup after validating the primary state",
            &backup,
            source,
        )),
    }
}

#[cfg(not(windows))]
fn cleanup_platform_stale_state_backup(_: &Path) -> Result<(), StateFileError> {
    Ok(())
}

/// Writes state through a same-directory temporary file and replaces the
/// destination only after the new contents have reached stable storage.
///
/// Callers must hold [`StateFileLock`] for the entire process lifetime.
pub fn write_protected_state_file<T: Serialize>(
    path: &Path,
    value: &T,
    purpose: &[u8],
) -> Result<(), StateFileError> {
    let parent = state_parent(path);
    fs::create_dir_all(parent)
        .map_err(|source| state_io_error("create state directory", parent, source))?;
    let temporary = temporary_path(path);
    let result = (|| {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)
            .map_err(|source| state_io_error("create temporary state", &temporary, source))?;
        restrict_state_file_permissions(&temporary)?;
        let encoded = Zeroizing::new(encode_protected_state(value, purpose)?);
        file.write_all(&encoded)
            .map_err(|source| state_io_error("write temporary state", &temporary, source))?;
        file.sync_all()
            .map_err(|source| state_io_error("sync temporary state", &temporary, source))?;
        drop(file);
        replace_state_file(&temporary, path)?;
        restrict_state_file_permissions(path)?;
        sync_state_parent(parent)?;
        Ok(())
    })();
    if result.is_err() && temporary.exists() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

#[cfg(unix)]
pub fn restrict_state_file_permissions(path: &Path) -> Result<(), StateFileError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .map_err(|source| state_io_error("restrict state permissions to mode 0600", path, source))
}

#[cfg(windows)]
pub fn restrict_state_file_permissions(_: &Path) -> Result<(), StateFileError> {
    Ok(())
}

fn state_parent(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn suffixed_path(path: &Path, suffix: &str) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(suffix);
    PathBuf::from(value)
}

fn backup_path(path: &Path) -> PathBuf {
    suffixed_path(path, ".bak")
}

fn temporary_path(path: &Path) -> PathBuf {
    suffixed_path(path, &format!(".tmp-{}", Uuid::new_v4()))
}

fn state_io_error(action: &'static str, path: &Path, source: std::io::Error) -> StateFileError {
    StateFileError::Io {
        action,
        path: path.to_path_buf(),
        source,
    }
}

#[cfg(unix)]
fn replace_state_file(temporary: &Path, path: &Path) -> Result<(), StateFileError> {
    fs::rename(temporary, path)
        .map_err(|source| state_io_error("atomically replace state", path, source))
}

#[cfg(windows)]
fn replace_state_file(temporary: &Path, path: &Path) -> Result<(), StateFileError> {
    use std::{iter::once, os::windows::ffi::OsStrExt, ptr::null};
    use windows_sys::Win32::Storage::FileSystem::{
        MoveFileExW, ReplaceFileW, MOVEFILE_WRITE_THROUGH, REPLACEFILE_WRITE_THROUGH,
    };

    let wide = |value: &Path| {
        value
            .as_os_str()
            .encode_wide()
            .chain(once(0))
            .collect::<Vec<_>>()
    };
    let temporary_wide = wide(temporary);
    let path_wide = wide(path);
    if !path.exists() {
        let succeeded = unsafe {
            MoveFileExW(
                temporary_wide.as_ptr(),
                path_wide.as_ptr(),
                MOVEFILE_WRITE_THROUGH,
            )
        };
        if succeeded == 0 {
            return Err(state_io_error(
                "install state",
                path,
                std::io::Error::last_os_error(),
            ));
        }
        return Ok(());
    }

    let backup = backup_path(path);
    if backup.exists() {
        fs::remove_file(&backup)
            .map_err(|source| state_io_error("remove stale state backup", &backup, source))?;
    }
    let backup_wide = wide(&backup);
    let succeeded = unsafe {
        ReplaceFileW(
            path_wide.as_ptr(),
            temporary_wide.as_ptr(),
            backup_wide.as_ptr(),
            REPLACEFILE_WRITE_THROUGH,
            null(),
            null(),
        )
    };
    if succeeded == 0 {
        return Err(state_io_error(
            "atomically replace state",
            path,
            std::io::Error::last_os_error(),
        ));
    }
    if let Err(error) = fs::remove_file(&backup) {
        eprintln!(
            "WARNING: MeshLake committed state {} but could not remove backup {}: {}",
            path.display(),
            backup.display(),
            error
        );
    }
    Ok(())
}

#[cfg(unix)]
fn install_recovered_backup(backup: &Path, path: &Path) -> Result<(), StateFileError> {
    fs::rename(backup, path)
        .map_err(|source| state_io_error("recover state backup", backup, source))?;
    sync_state_parent(state_parent(path))
}

#[cfg(windows)]
fn install_recovered_backup(backup: &Path, path: &Path) -> Result<(), StateFileError> {
    use std::{iter::once, os::windows::ffi::OsStrExt};
    use windows_sys::Win32::Storage::FileSystem::{MoveFileExW, MOVEFILE_WRITE_THROUGH};

    let wide = |value: &Path| {
        value
            .as_os_str()
            .encode_wide()
            .chain(once(0))
            .collect::<Vec<_>>()
    };
    let backup_wide = wide(backup);
    let path_wide = wide(path);
    let succeeded = unsafe {
        MoveFileExW(
            backup_wide.as_ptr(),
            path_wide.as_ptr(),
            MOVEFILE_WRITE_THROUGH,
        )
    };
    if succeeded == 0 {
        return Err(state_io_error(
            "recover state backup",
            backup,
            std::io::Error::last_os_error(),
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn sync_state_parent(parent: &Path) -> Result<(), StateFileError> {
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| state_io_error("sync state directory", parent, source))
}

#[cfg(windows)]
fn sync_state_parent(_: &Path) -> Result<(), StateFileError> {
    Ok(())
}

#[cfg(not(windows))]
fn decode_platform_state<T: DeserializeOwned>(
    bytes: &[u8],
    _purpose: &[u8],
) -> Result<DecodedState<T>, StateProtectionError> {
    if let Ok(envelope) = serde_json::from_slice::<ProtectedStateEnvelope>(bytes) {
        validate_envelope(&envelope)?;
        return Err(StateProtectionError::UnsupportedProtection(
            envelope.protection,
        ));
    }
    Ok(DecodedState {
        value: serde_json::from_slice(bytes)?,
        needs_protection_upgrade: false,
    })
}

fn validate_envelope(envelope: &ProtectedStateEnvelope) -> Result<(), StateProtectionError> {
    if envelope.format_version != ENVELOPE_VERSION {
        return Err(StateProtectionError::UnsupportedVersion(
            envelope.format_version,
        ));
    }
    if envelope.protection != WINDOWS_DPAPI_PROTECTION {
        return Err(StateProtectionError::UnsupportedProtection(
            envelope.protection.clone(),
        ));
    }
    Ok(())
}

#[cfg(windows)]
fn dpapi_protect(plaintext: &[u8], purpose: &[u8]) -> Result<Vec<u8>, StateProtectionError> {
    use std::ptr::null;
    use windows_sys::Win32::{
        Foundation::LocalFree,
        Security::Cryptography::{
            CryptProtectData, CRYPTPROTECT_LOCAL_MACHINE, CRYPTPROTECT_UI_FORBIDDEN,
            CRYPT_INTEGER_BLOB,
        },
    };

    let input = data_blob(plaintext)?;
    let entropy = data_blob(purpose)?;
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };
    let succeeded = unsafe {
        CryptProtectData(
            &input,
            null(),
            &entropy,
            null(),
            null(),
            CRYPTPROTECT_LOCAL_MACHINE | CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    if succeeded == 0 {
        return Err(StateProtectionError::Platform(
            std::io::Error::last_os_error().to_string(),
        ));
    }
    if output.pbData.is_null() {
        return Err(StateProtectionError::Platform(
            "CryptProtectData returned no output buffer".into(),
        ));
    }
    let protected =
        unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec() };
    unsafe {
        LocalFree(output.pbData.cast());
    }
    Ok(protected)
}

#[cfg(windows)]
fn dpapi_unprotect(ciphertext: &[u8], purpose: &[u8]) -> Result<Vec<u8>, StateProtectionError> {
    use std::ptr::null;
    use windows_sys::Win32::{
        Foundation::LocalFree,
        Security::Cryptography::{
            CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
        },
    };

    let input = data_blob(ciphertext)?;
    let entropy = data_blob(purpose)?;
    let mut output = CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: std::ptr::null_mut(),
    };
    let succeeded = unsafe {
        CryptUnprotectData(
            &input,
            std::ptr::null_mut(),
            &entropy,
            null(),
            null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output,
        )
    };
    if succeeded == 0 {
        return Err(StateProtectionError::Platform(
            std::io::Error::last_os_error().to_string(),
        ));
    }
    if output.pbData.is_null() {
        return Err(StateProtectionError::Platform(
            "CryptUnprotectData returned no output buffer".into(),
        ));
    }
    let plaintext =
        unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec() };
    unsafe {
        for index in 0..output.cbData as usize {
            std::ptr::write_volatile(output.pbData.add(index), 0);
        }
        LocalFree(output.pbData.cast());
    }
    Ok(plaintext)
}

#[cfg(windows)]
fn data_blob(
    bytes: &[u8],
) -> Result<windows_sys::Win32::Security::Cryptography::CRYPT_INTEGER_BLOB, StateProtectionError> {
    Ok(
        windows_sys::Win32::Security::Cryptography::CRYPT_INTEGER_BLOB {
            cbData: bytes
                .len()
                .try_into()
                .map_err(|_| StateProtectionError::SizeLimit)?,
            pbData: bytes.as_ptr().cast_mut(),
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    struct ExampleState {
        secret: String,
    }

    #[test]
    fn protected_state_round_trips_on_the_current_platform() {
        let state = ExampleState {
            secret: "test-secret".into(),
        };
        let encoded = encode_protected_state(&state, b"MeshLake state protection test").unwrap();
        let decoded: DecodedState<ExampleState> =
            decode_protected_state(&encoded, b"MeshLake state protection test").unwrap();
        assert_eq!(decoded.value, state);
        assert!(!decoded.needs_protection_upgrade);
    }

    #[test]
    fn unsupported_envelope_version_and_protection_fail_closed() {
        let wrong_version = serde_json::to_vec(&ProtectedStateEnvelope {
            format_version: ENVELOPE_VERSION + 1,
            protection: WINDOWS_DPAPI_PROTECTION.into(),
            ciphertext_base64: "AA==".into(),
        })
        .unwrap();
        assert!(matches!(
            decode_protected_state::<ExampleState>(&wrong_version, b"purpose"),
            Err(StateProtectionError::UnsupportedVersion(_))
        ));

        let wrong_protection = serde_json::to_vec(&ProtectedStateEnvelope {
            format_version: ENVELOPE_VERSION,
            protection: "unknown-protection".into(),
            ciphertext_base64: "AA==".into(),
        })
        .unwrap();
        assert!(matches!(
            decode_protected_state::<ExampleState>(&wrong_protection, b"purpose"),
            Err(StateProtectionError::UnsupportedProtection(_))
        ));
    }

    #[test]
    fn state_file_lock_rejects_a_second_writer() {
        let directory =
            std::env::temp_dir().join(format!("meshlake-state-lock-test-{}", Uuid::new_v4()));
        let path = directory.join("state.json");
        let first = StateFileLock::acquire(&path).unwrap();
        assert!(StateFileLock::acquire(&path).is_err());
        drop(first);
        assert!(StateFileLock::acquire(&path).is_ok());
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn protected_state_file_replaces_and_recovers_without_losing_data() {
        let directory =
            std::env::temp_dir().join(format!("meshlake-state-write-test-{}", Uuid::new_v4()));
        let path = directory.join("state.json");
        let state_lock = StateFileLock::acquire(&path).unwrap();
        let mut state = ExampleState {
            secret: "first-secret".into(),
        };
        write_protected_state_file(&path, &state, b"state-file-test").unwrap();
        state.secret = "second-secret".into();
        write_protected_state_file(&path, &state, b"state-file-test").unwrap();
        let decoded: DecodedState<ExampleState> =
            decode_protected_state(&fs::read(&path).unwrap(), b"state-file-test").unwrap();
        assert_eq!(decoded.value, state);

        let backup = backup_path(&path);
        fs::rename(&path, &backup).unwrap();
        recover_protected_state_file(&path).unwrap();
        let recovered: DecodedState<ExampleState> =
            decode_protected_state(&fs::read(&path).unwrap(), b"state-file-test").unwrap();
        assert_eq!(recovered.value, state);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }

        drop(state_lock);
        fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn legacy_plaintext_state_requests_a_dpapi_upgrade() {
        let state = ExampleState {
            secret: "legacy-secret".into(),
        };
        let encoded = serde_json::to_vec_pretty(&state).unwrap();
        let decoded: DecodedState<ExampleState> =
            decode_protected_state(&encoded, b"MeshLake state protection test").unwrap();
        assert_eq!(decoded.value, state);
        assert!(decoded.needs_protection_upgrade);
    }

    #[cfg(windows)]
    #[test]
    fn dpapi_envelope_is_bound_to_its_purpose() {
        let state = ExampleState {
            secret: "purpose-bound-secret".into(),
        };
        let encoded = encode_protected_state(&state, b"purpose-a").unwrap();
        assert!(!String::from_utf8_lossy(&encoded).contains("purpose-bound-secret"));
        assert!(decode_protected_state::<ExampleState>(&encoded, b"purpose-b").is_err());
    }

    #[cfg(windows)]
    #[test]
    fn tampered_dpapi_ciphertext_is_rejected() {
        let state = ExampleState {
            secret: "tamper-test-secret".into(),
        };
        let encoded = encode_protected_state(&state, b"tamper-purpose").unwrap();
        let mut envelope: ProtectedStateEnvelope = serde_json::from_slice(&encoded).unwrap();
        let mut ciphertext = STANDARD.decode(&envelope.ciphertext_base64).unwrap();
        let middle = ciphertext.len() / 2;
        ciphertext[middle] ^= 0x80;
        envelope.ciphertext_base64 = STANDARD.encode(ciphertext);
        let tampered = serde_json::to_vec(&envelope).unwrap();
        assert!(decode_protected_state::<ExampleState>(&tampered, b"tamper-purpose").is_err());
    }

    #[cfg(not(windows))]
    #[test]
    fn unix_rejects_a_windows_dpapi_envelope() {
        let encoded = serde_json::to_vec(&ProtectedStateEnvelope {
            format_version: ENVELOPE_VERSION,
            protection: WINDOWS_DPAPI_PROTECTION.into(),
            ciphertext_base64: "AA==".into(),
        })
        .unwrap();
        assert!(matches!(
            decode_protected_state::<ExampleState>(&encoded, b"purpose"),
            Err(StateProtectionError::UnsupportedProtection(_))
        ));
    }
}
