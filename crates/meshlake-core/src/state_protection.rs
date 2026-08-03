//! Platform state-file protection shared by the agent and controller.
//!
//! Windows stores serialized state inside a machine-bound DPAPI envelope.
//! Linux can use a versioned XChaCha20-Poly1305 envelope whose master key is
//! supplied explicitly by systemd credentials or an external restricted file.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use fs2::FileExt;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};
use thiserror::Error;
use uuid::Uuid;
use zeroize::Zeroizing;

const ENVELOPE_VERSION: u8 = 1;
#[cfg_attr(unix, allow(dead_code))]
const WINDOWS_DPAPI_PROTECTION: &str = "windows-dpapi-local-machine";
const LINUX_MASTER_KEY_PROTECTION: &str = "linux-xchacha20poly1305-master-key-v1";
const LINUX_MASTER_KEY_LEN: usize = 32;
const LINUX_NONCE_LEN: usize = 24;
#[cfg(unix)]
const MAX_PROVIDER_KEY_FILE_BYTES: u64 = 64 * 1024;
pub const AGENT_STATE_PROTECTION_PURPOSE: &[u8] = b"MeshLake agent state v1";
pub const CONTROLLER_STATE_PROTECTION_PURPOSE: &[u8] = b"MeshLake controller state v1";
pub const ROOT_IDENTITY_PROTECTION_PURPOSE: &[u8] = b"MeshLake root service identity v1";
pub const RELAY_IDENTITY_PROTECTION_PURPOSE: &[u8] = b"MeshLake relay service identity v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StateKeyProvider {
    SystemdCredential(String),
    RestrictedFile(PathBuf),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StateProtectionLevel {
    WindowsDpapiLocalMachine,
    LinuxSystemdCredential,
    LinuxRestrictedExternalKeyFile,
    LinuxFilePermissionsOnly,
}

impl std::fmt::Display for StateProtectionLevel {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::WindowsDpapiLocalMachine => "windows-dpapi-local-machine",
            Self::LinuxSystemdCredential => "linux-systemd-credential-envelope",
            Self::LinuxRestrictedExternalKeyFile => "linux-restricted-external-key-envelope",
            Self::LinuxFilePermissionsOnly => "linux-0600-plaintext-compatibility",
        })
    }
}

pub struct StateProtection {
    kind: StateProtectionKind,
    level: StateProtectionLevel,
    #[cfg_attr(windows, allow(dead_code))]
    allow_plaintext_migration: bool,
}

enum StateProtectionKind {
    PlatformDefault,
    #[cfg_attr(windows, allow(dead_code))]
    LinuxMasterKey(Zeroizing<[u8; LINUX_MASTER_KEY_LEN]>),
}

impl std::fmt::Debug for StateProtection {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StateProtection")
            .field("level", &self.level)
            .field("master_key", &"[REDACTED]")
            .finish()
    }
}

impl StateProtection {
    pub fn platform_default() -> Self {
        Self {
            kind: StateProtectionKind::PlatformDefault,
            level: if cfg!(windows) {
                StateProtectionLevel::WindowsDpapiLocalMachine
            } else {
                StateProtectionLevel::LinuxFilePermissionsOnly
            },
            allow_plaintext_migration: false,
        }
    }

    pub fn from_provider(
        state_path: &Path,
        provider: StateKeyProvider,
    ) -> Result<Self, StateProtectionError> {
        Self::from_provider_with_plaintext_migration(state_path, provider, false)
    }

    pub fn from_provider_with_plaintext_migration(
        state_path: &Path,
        provider: StateKeyProvider,
        allow_plaintext_migration: bool,
    ) -> Result<Self, StateProtectionError> {
        #[cfg(windows)]
        {
            let _ = state_path;
            let _ = provider;
            let _ = allow_plaintext_migration;
            return Err(StateProtectionError::Provider(
                "Linux state-key providers cannot be used on Windows".into(),
            ));
        }
        #[cfg(unix)]
        {
            match provider {
                StateKeyProvider::SystemdCredential(name) => {
                    let key = load_systemd_credential(&name)?;
                    Ok(Self::linux_master_key_with_migration(
                        key,
                        StateProtectionLevel::LinuxSystemdCredential,
                        allow_plaintext_migration,
                    ))
                }
                StateKeyProvider::RestrictedFile(path) => {
                    reject_key_beside_state(state_path, &path)?;
                    let bytes = crate::read_restricted_secret_file(&path).map_err(|error| {
                        StateProtectionError::Provider(format!(
                            "cannot read restricted state master-key file: {error}"
                        ))
                    })?;
                    let key = exact_master_key(&bytes)?;
                    Ok(Self::linux_master_key_with_migration(
                        key,
                        StateProtectionLevel::LinuxRestrictedExternalKeyFile,
                        allow_plaintext_migration,
                    ))
                }
            }
        }
    }

    pub fn level(&self) -> StateProtectionLevel {
        self.level
    }

    #[cfg(test)]
    fn linux_master_key(key: [u8; LINUX_MASTER_KEY_LEN], level: StateProtectionLevel) -> Self {
        Self::linux_master_key_with_migration(key, level, false)
    }

    #[cfg_attr(windows, allow(dead_code))]
    fn linux_master_key_with_migration(
        key: [u8; LINUX_MASTER_KEY_LEN],
        level: StateProtectionLevel,
        allow_plaintext_migration: bool,
    ) -> Self {
        Self {
            kind: StateProtectionKind::LinuxMasterKey(Zeroizing::new(key)),
            level,
            allow_plaintext_migration,
        }
    }

    #[cfg(test)]
    fn test_linux_master_key(key: [u8; LINUX_MASTER_KEY_LEN]) -> Self {
        Self::linux_master_key(key, StateProtectionLevel::LinuxSystemdCredential)
    }

    #[cfg(all(test, unix))]
    fn test_linux_master_key_with_migration(key: [u8; LINUX_MASTER_KEY_LEN]) -> Self {
        Self::linux_master_key_with_migration(
            key,
            StateProtectionLevel::LinuxSystemdCredential,
            true,
        )
    }
}

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
        reject_symlink_path(state_path)?;
        let parent = state_parent(state_path);
        fs::create_dir_all(parent)
            .map_err(|source| state_io_error("create state directory", parent, source))?;
        reject_symlink_path(state_path)?;
        let lock_path = suffixed_path(state_path, ".lock");
        reject_symlink_path(&lock_path)?;
        let file = secure_open_lock(&lock_path)?;
        if !file
            .metadata()
            .map_err(|source| state_io_error("inspect state lock", &lock_path, source))?
            .is_file()
        {
            return Err(state_io_error(
                "open a regular state lock",
                &lock_path,
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "state lock is not a regular file",
                ),
            ));
        }
        restrict_state_file_permissions(&lock_path)?;
        FileExt::try_lock_exclusive(&file).map_err(|source| StateFileError::Lock {
            path: state_path.to_path_buf(),
            source,
        })?;
        Ok(Self { file })
    }
}

/// Securely reads one locked state file with a hard size limit. The final
/// component is opened without following links and every existing parent
/// component is rejected when it is a symlink/reparse point.
pub fn read_protected_state_file<T: DeserializeOwned>(
    path: &Path,
    purpose: &[u8],
    maximum_bytes: usize,
) -> Result<DecodedState<T>, StateFileError> {
    reject_symlink_path(path)?;
    let file = secure_open_read(path)?;
    let metadata = file
        .metadata()
        .map_err(|source| state_io_error("inspect state", path, source))?;
    if !metadata.is_file() || metadata.len() > maximum_bytes as u64 {
        return Err(state_io_error(
            "read state within its size limit",
            path,
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "state file is not a regular file or exceeds its size limit",
            ),
        ));
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(metadata.len() as usize));
    file.take(maximum_bytes.saturating_add(1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|source| state_io_error("read state", path, source))?;
    if bytes.len() > maximum_bytes {
        return Err(state_io_error(
            "read state within its size limit",
            path,
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "state file exceeds its size limit",
            ),
        ));
    }
    decode_protected_state(&bytes, purpose).map_err(Into::into)
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    nonce_base64: Option<String>,
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
    #[error("state master-key provider configuration is invalid: {0}")]
    Provider(String),
    #[error("protected Linux state requires the configured master-key provider")]
    MissingMasterKey,
    #[error(
        "plaintext state is rejected while a Linux master-key provider is configured; pass --allow-plaintext-state-migration for one explicitly authorized migration run"
    )]
    PlaintextMigrationNotAllowed,
    #[error("protected state authentication failed")]
    Authentication,
    #[error("protected state nonce is missing or invalid")]
    InvalidNonce,
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
    encode_protected_state_with(value, purpose, &StateProtection::platform_default())
}

pub fn encode_protected_state_with<T: Serialize>(
    value: &T,
    purpose: &[u8],
    protection: &StateProtection,
) -> Result<Vec<u8>, StateProtectionError> {
    let plaintext = Zeroizing::new(serde_json::to_vec_pretty(value)?);
    encode_platform_state(&plaintext, purpose, protection)
}

pub fn decode_protected_state<T: DeserializeOwned>(
    bytes: &[u8],
    purpose: &[u8],
) -> Result<DecodedState<T>, StateProtectionError> {
    decode_protected_state_with(bytes, purpose, &StateProtection::platform_default())
}

pub fn decode_protected_state_with<T: DeserializeOwned>(
    bytes: &[u8],
    purpose: &[u8],
    protection: &StateProtection,
) -> Result<DecodedState<T>, StateProtectionError> {
    decode_platform_state(bytes, purpose, protection)
}

#[cfg(windows)]
fn encode_platform_state(
    plaintext: &[u8],
    purpose: &[u8],
    protection: &StateProtection,
) -> Result<Vec<u8>, StateProtectionError> {
    if let StateProtectionKind::LinuxMasterKey(key) = &protection.kind {
        return encode_linux_master_key_state(plaintext, purpose, key);
    }
    let protected = dpapi_protect(plaintext, purpose)?;
    Ok(serde_json::to_vec_pretty(&ProtectedStateEnvelope {
        format_version: ENVELOPE_VERSION,
        protection: WINDOWS_DPAPI_PROTECTION.to_owned(),
        nonce_base64: None,
        ciphertext_base64: STANDARD.encode(protected),
    })?)
}

#[cfg(not(windows))]
fn encode_platform_state(
    plaintext: &[u8],
    purpose: &[u8],
    protection: &StateProtection,
) -> Result<Vec<u8>, StateProtectionError> {
    match &protection.kind {
        StateProtectionKind::PlatformDefault => Ok(plaintext.to_vec()),
        StateProtectionKind::LinuxMasterKey(key) => {
            encode_linux_master_key_state(plaintext, purpose, key)
        }
    }
}

#[cfg(windows)]
fn decode_platform_state<T: DeserializeOwned>(
    bytes: &[u8],
    purpose: &[u8],
    protection: &StateProtection,
) -> Result<DecodedState<T>, StateProtectionError> {
    if let Ok(envelope) = serde_json::from_slice::<ProtectedStateEnvelope>(bytes) {
        validate_envelope_version(&envelope)?;
        if envelope.protection == LINUX_MASTER_KEY_PROTECTION {
            return decode_linux_master_key_state(envelope, purpose, protection);
        }
        if envelope.protection != WINDOWS_DPAPI_PROTECTION {
            return Err(StateProtectionError::UnsupportedProtection(
                envelope.protection,
            ));
        }
        let ciphertext = STANDARD.decode(&envelope.ciphertext_base64)?;
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
    write_protected_state_file_with(path, value, purpose, &StateProtection::platform_default())
}

pub fn write_protected_state_file_with<T: Serialize>(
    path: &Path,
    value: &T,
    purpose: &[u8],
    protection: &StateProtection,
) -> Result<(), StateFileError> {
    reject_symlink_path(path)?;
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
        let encoded = Zeroizing::new(encode_protected_state_with(value, purpose, protection)?);
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

fn reject_symlink_path(path: &Path) -> Result<(), StateFileError> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(state_io_error(
                    "use a non-symlink state path",
                    &current,
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "state path contains a symbolic link or reparse point",
                    ),
                ));
            }
            Ok(metadata) => {
                #[cfg(windows)]
                {
                    use std::os::windows::fs::MetadataExt;
                    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;
                    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
                        return Err(state_io_error(
                            "use a non-reparse state path",
                            &current,
                            std::io::Error::new(
                                std::io::ErrorKind::InvalidInput,
                                "state path contains a symbolic link or reparse point",
                            ),
                        ));
                    }
                }
            }
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => break,
            Err(source) => return Err(state_io_error("inspect state path", &current, source)),
        }
    }
    Ok(())
}

#[cfg(unix)]
fn secure_open_read(path: &Path) -> Result<File, StateFileError> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|source| state_io_error("open state without following links", path, source))
}

#[cfg(unix)]
fn secure_open_lock(path: &Path) -> Result<File, StateFileError> {
    use std::os::unix::fs::OpenOptionsExt;
    OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .map_err(|source| state_io_error("open state lock without following links", path, source))
}

#[cfg(windows)]
fn secure_open_read(path: &Path) -> Result<File, StateFileError> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;
    OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|source| state_io_error("open state without following links", path, source))
}

#[cfg(windows)]
fn secure_open_lock(path: &Path) -> Result<File, StateFileError> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;
    OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|source| state_io_error("open state lock without following links", path, source))
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
    purpose: &[u8],
    protection: &StateProtection,
) -> Result<DecodedState<T>, StateProtectionError> {
    if let Ok(envelope) = serde_json::from_slice::<ProtectedStateEnvelope>(bytes) {
        validate_envelope_version(&envelope)?;
        if envelope.protection == LINUX_MASTER_KEY_PROTECTION {
            return decode_linux_master_key_state(envelope, purpose, protection);
        }
        return Err(StateProtectionError::UnsupportedProtection(
            envelope.protection,
        ));
    }
    match &protection.kind {
        StateProtectionKind::PlatformDefault => Ok(DecodedState {
            value: serde_json::from_slice(bytes)?,
            needs_protection_upgrade: false,
        }),
        StateProtectionKind::LinuxMasterKey(_) if protection.allow_plaintext_migration => {
            Ok(DecodedState {
                value: serde_json::from_slice(bytes)?,
                needs_protection_upgrade: true,
            })
        }
        StateProtectionKind::LinuxMasterKey(_) => {
            Err(StateProtectionError::PlaintextMigrationNotAllowed)
        }
    }
}

fn validate_envelope_version(
    envelope: &ProtectedStateEnvelope,
) -> Result<(), StateProtectionError> {
    if envelope.format_version != ENVELOPE_VERSION {
        return Err(StateProtectionError::UnsupportedVersion(
            envelope.format_version,
        ));
    }
    Ok(())
}

fn encode_linux_master_key_state(
    plaintext: &[u8],
    purpose: &[u8],
    key: &[u8; LINUX_MASTER_KEY_LEN],
) -> Result<Vec<u8>, StateProtectionError> {
    let mut nonce = [0_u8; LINUX_NONCE_LEN];
    getrandom::fill(&mut nonce).map_err(|error| {
        StateProtectionError::Provider(format!("cannot generate state nonce: {error:?}"))
    })?;
    let cipher = XChaCha20Poly1305::new(key.into());
    let associated_data = state_associated_data(purpose);
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext,
                aad: &associated_data,
            },
        )
        .map_err(|_| StateProtectionError::Authentication)?;
    Ok(serde_json::to_vec_pretty(&ProtectedStateEnvelope {
        format_version: ENVELOPE_VERSION,
        protection: LINUX_MASTER_KEY_PROTECTION.into(),
        nonce_base64: Some(STANDARD.encode(nonce)),
        ciphertext_base64: STANDARD.encode(ciphertext),
    })?)
}

fn decode_linux_master_key_state<T: DeserializeOwned>(
    envelope: ProtectedStateEnvelope,
    purpose: &[u8],
    protection: &StateProtection,
) -> Result<DecodedState<T>, StateProtectionError> {
    let StateProtectionKind::LinuxMasterKey(key) = &protection.kind else {
        return Err(StateProtectionError::MissingMasterKey);
    };
    let nonce = envelope
        .nonce_base64
        .as_deref()
        .ok_or(StateProtectionError::InvalidNonce)
        .and_then(|value| STANDARD.decode(value).map_err(StateProtectionError::Base64))?;
    let nonce: [u8; LINUX_NONCE_LEN] = nonce
        .try_into()
        .map_err(|_| StateProtectionError::InvalidNonce)?;
    let ciphertext = STANDARD.decode(envelope.ciphertext_base64)?;
    let associated_data = state_associated_data(purpose);
    let cipher = XChaCha20Poly1305::new(key.as_ref().into());
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &ciphertext,
                    aad: &associated_data,
                },
            )
            .map_err(|_| StateProtectionError::Authentication)?,
    );
    Ok(DecodedState {
        value: serde_json::from_slice(&plaintext)?,
        needs_protection_upgrade: false,
    })
}

fn state_associated_data(purpose: &[u8]) -> Vec<u8> {
    let mut data = Vec::with_capacity(64 + purpose.len());
    data.extend_from_slice(b"MeshLake protected state envelope\0");
    data.push(ENVELOPE_VERSION);
    data.extend_from_slice(LINUX_MASTER_KEY_PROTECTION.as_bytes());
    data.push(0);
    data.extend_from_slice(&(purpose.len() as u64).to_le_bytes());
    data.extend_from_slice(purpose);
    data
}

#[cfg(unix)]
fn load_systemd_credential(name: &str) -> Result<[u8; LINUX_MASTER_KEY_LEN], StateProtectionError> {
    let directory = std::env::var_os("CREDENTIALS_DIRECTORY").ok_or_else(|| {
        StateProtectionError::Provider(
            "CREDENTIALS_DIRECTORY is not set for the requested systemd credential".into(),
        )
    })?;
    let directory = PathBuf::from(directory);
    if !directory.is_absolute() {
        return Err(StateProtectionError::Provider(
            "CREDENTIALS_DIRECTORY must be an absolute path".into(),
        ));
    }
    load_systemd_credential_from_directory(name, &directory)
}

#[cfg(unix)]
fn load_systemd_credential_from_directory(
    name: &str,
    directory: &Path,
) -> Result<[u8; LINUX_MASTER_KEY_LEN], StateProtectionError> {
    let component = Path::new(name);
    if name.is_empty()
        || component.components().count() != 1
        || !matches!(
            component.components().next(),
            Some(std::path::Component::Normal(_))
        )
    {
        return Err(StateProtectionError::Provider(
            "systemd credential name must be one plain file name".into(),
        ));
    }
    let bytes = read_provider_key_file(&directory.join(name))?;
    exact_master_key(&bytes)
}

#[cfg(unix)]
fn read_provider_key_file(path: &Path) -> Result<Zeroizing<Vec<u8>>, StateProtectionError> {
    let bytes = crate::secret_file::read_secret_file_no_follow(path, false).map_err(|error| {
        StateProtectionError::Provider(format!("cannot read state master-key source: {error}"))
    })?;
    if bytes.len() as u64 > MAX_PROVIDER_KEY_FILE_BYTES {
        return Err(StateProtectionError::Provider(
            "state master-key source exceeds 64 KiB".into(),
        ));
    }
    Ok(bytes)
}

#[cfg(unix)]
fn exact_master_key(bytes: &[u8]) -> Result<[u8; LINUX_MASTER_KEY_LEN], StateProtectionError> {
    bytes.try_into().map_err(|_| {
        StateProtectionError::Provider(
            "state master-key source must contain exactly 32 raw bytes".into(),
        )
    })
}

#[cfg(unix)]
fn reject_key_beside_state(state_path: &Path, key_path: &Path) -> Result<(), StateProtectionError> {
    let state_parent = absolute_parent(state_path)?;
    let key_parent = key_path.parent().unwrap_or_else(|| Path::new("."));
    let key_parent = fs::canonicalize(key_parent).map_err(|error| {
        StateProtectionError::Provider(format!(
            "cannot resolve state master-key parent directory: {error}"
        ))
    })?;
    if state_parent == key_parent {
        return Err(StateProtectionError::Provider(
            "restricted state master-key file must not be stored beside the state file".into(),
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn absolute_parent(path: &Path) -> Result<PathBuf, StateProtectionError> {
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent).map_err(|error| {
        StateProtectionError::Provider(format!("cannot create state directory: {error}"))
    })?;
    fs::canonicalize(parent).map_err(|error| {
        StateProtectionError::Provider(format!("cannot resolve state directory: {error}"))
    })
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
            nonce_base64: None,
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
            nonce_base64: None,
            ciphertext_base64: "AA==".into(),
        })
        .unwrap();
        assert!(matches!(
            decode_protected_state::<ExampleState>(&wrong_protection, b"purpose"),
            Err(StateProtectionError::UnsupportedProtection(_))
        ));
    }

    #[cfg(unix)]
    #[test]
    fn linux_master_key_envelope_requires_explicit_plaintext_migration() {
        let state = ExampleState {
            secret: "linux-provider-secret".into(),
        };
        let protection = StateProtection::test_linux_master_key([7; 32]);
        let plaintext = serde_json::to_vec_pretty(&state).unwrap();
        assert!(matches!(
            decode_protected_state_with::<ExampleState>(&plaintext, b"purpose", &protection),
            Err(StateProtectionError::PlaintextMigrationNotAllowed)
        ));

        let migration = StateProtection::test_linux_master_key_with_migration([7; 32]);
        let legacy: DecodedState<ExampleState> =
            decode_protected_state_with(&plaintext, b"purpose", &migration).unwrap();
        assert_eq!(legacy.value, state);
        assert!(legacy.needs_protection_upgrade);

        let encoded = encode_protected_state_with(&state, b"purpose", &migration).unwrap();
        assert!(!String::from_utf8_lossy(&encoded).contains(&state.secret));
        let decoded: DecodedState<ExampleState> =
            decode_protected_state_with(&encoded, b"purpose", &protection).unwrap();
        assert_eq!(decoded.value, state);
        assert!(!decoded.needs_protection_upgrade);

        assert!(matches!(
            decode_protected_state_with::<ExampleState>(
                &encoded,
                b"purpose",
                &StateProtection::platform_default()
            ),
            Err(StateProtectionError::MissingMasterKey)
        ));
        let wrong_key = StateProtection::test_linux_master_key([8; 32]);
        assert!(matches!(
            decode_protected_state_with::<ExampleState>(&encoded, b"purpose", &wrong_key),
            Err(StateProtectionError::Authentication)
        ));
        assert!(matches!(
            decode_protected_state_with::<ExampleState>(&encoded, b"different", &protection),
            Err(StateProtectionError::Authentication)
        ));
    }

    #[test]
    fn state_protection_debug_never_contains_the_master_key() {
        let protection = StateProtection::test_linux_master_key([0x41; 32]);
        let rendered = format!("{protection:?}");
        assert!(!rendered.contains("AAAAAAAA"));
        assert!(rendered.contains("REDACTED"));
    }

    #[cfg(windows)]
    #[test]
    fn windows_rejects_linux_provider_configuration_without_fallback() {
        let error = StateProtection::from_provider(
            Path::new("controller.json"),
            StateKeyProvider::RestrictedFile(PathBuf::from("state.key")),
        )
        .unwrap_err();
        assert!(error.to_string().contains("cannot be used on Windows"));
        assert_eq!(
            StateProtection::platform_default().level(),
            StateProtectionLevel::WindowsDpapiLocalMachine
        );
    }

    #[cfg(unix)]
    #[test]
    fn linux_restricted_file_provider_enforces_location_permissions_and_size() {
        use std::os::unix::fs::PermissionsExt;

        let directory =
            std::env::temp_dir().join(format!("meshlake-linux-state-provider-{}", Uuid::new_v4()));
        let state_directory = directory.join("state");
        let key_directory = directory.join("credentials");
        fs::create_dir_all(&state_directory).unwrap();
        fs::create_dir_all(&key_directory).unwrap();
        let state_path = state_directory.join("agent.json");
        let key_path = key_directory.join("state.key");
        crate::create_restricted_secret_file(&key_path, &[7; 32]).unwrap();

        let protection = StateProtection::from_provider(
            &state_path,
            StateKeyProvider::RestrictedFile(key_path.clone()),
        )
        .unwrap();
        assert_eq!(
            protection.level(),
            StateProtectionLevel::LinuxRestrictedExternalKeyFile
        );

        let beside = state_directory.join("state.key");
        crate::create_restricted_secret_file(&beside, &[8; 32]).unwrap();
        assert!(StateProtection::from_provider(
            &state_path,
            StateKeyProvider::RestrictedFile(beside)
        )
        .unwrap_err()
        .to_string()
        .contains("must not be stored beside"));

        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o640)).unwrap();
        assert!(StateProtection::from_provider(
            &state_path,
            StateKeyProvider::RestrictedFile(key_path.clone())
        )
        .unwrap_err()
        .to_string()
        .contains("permissions are not restricted"));

        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::write(&key_path, [9; 31]).unwrap();
        assert!(StateProtection::from_provider(
            &state_path,
            StateKeyProvider::RestrictedFile(key_path)
        )
        .unwrap_err()
        .to_string()
        .contains("exactly 32 raw bytes"));

        fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn systemd_credential_provider_validates_name_and_reads_raw_key() {
        let directory =
            std::env::temp_dir().join(format!("meshlake-systemd-credential-{}", Uuid::new_v4()));
        fs::create_dir_all(&directory).unwrap();
        fs::write(directory.join("meshlake-state-key"), [5; 32]).unwrap();
        assert_eq!(
            load_systemd_credential_from_directory("meshlake-state-key", &directory).unwrap(),
            [5; 32]
        );
        assert!(load_systemd_credential_from_directory("../state-key", &directory).is_err());
        assert!(load_systemd_credential_from_directory("missing", &directory).is_err());
        fs::remove_dir_all(directory).unwrap();
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
            nonce_base64: None,
            ciphertext_base64: "AA==".into(),
        })
        .unwrap();
        assert!(matches!(
            decode_protected_state::<ExampleState>(&encoded, b"purpose"),
            Err(StateProtectionError::UnsupportedProtection(_))
        ));
    }
}
