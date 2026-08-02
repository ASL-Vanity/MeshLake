//! Password-protected, machine-portable backups for agent and controller state.

use argon2::{Algorithm, Argon2, Params, Version};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use chacha20poly1305::{
    aead::{Aead, Payload},
    KeyInit, XChaCha20Poly1305, XNonce,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};
use thiserror::Error;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::{restrict_state_file_permissions, StateFileError};

const FORMAT_NAME: &str = "meshlake-state-backup";
const FORMAT_VERSION: u16 = 1;
const KDF_NAME: &str = "argon2id";
const KDF_VERSION: u32 = 0x13;
const KDF_MEMORY_KIB: u32 = 19_456;
const KDF_ITERATIONS: u32 = 2;
const KDF_PARALLELISM: u32 = 1;
const CIPHER_NAME: &str = "xchacha20poly1305";
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const KEY_LEN: usize = 32;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StateBackupKind {
    Agent,
    Controller,
}

impl std::fmt::Display for StateBackupKind {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Agent => formatter.write_str("agent"),
            Self::Controller => formatter.write_str("controller"),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BackupEnvelope {
    format: String,
    format_version: u16,
    state_kind: StateBackupKind,
    kdf: KdfHeader,
    cipher: CipherHeader,
    ciphertext_base64: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KdfHeader {
    algorithm: String,
    version: u32,
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
    salt_base64: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CipherHeader {
    algorithm: String,
    nonce_base64: String,
}

#[derive(Serialize)]
struct AssociatedData<'a> {
    format: &'a str,
    format_version: u16,
    state_kind: StateBackupKind,
    kdf: &'a KdfHeader,
    cipher: &'a CipherHeader,
}

#[derive(Debug, Error)]
pub enum StateBackupError {
    #[error("backup password must not be empty")]
    EmptyPassword,
    #[error("state backup is malformed or truncated")]
    InvalidFormat,
    #[error("unsupported state backup format version {0}")]
    UnsupportedVersion(u16),
    #[error("state backup contains {actual} state, not {expected} state")]
    StateKindMismatch {
        expected: StateBackupKind,
        actual: StateBackupKind,
    },
    #[error("state backup uses an unsupported key derivation configuration")]
    UnsupportedKdf,
    #[error("state backup uses an unsupported cipher")]
    UnsupportedCipher,
    #[error("cannot derive state backup encryption key")]
    KeyDerivation,
    #[error("state backup authentication failed")]
    AuthenticationFailed,
    #[error("decrypted state backup is invalid")]
    InvalidState,
    #[error("cannot generate secure state backup randomness")]
    Randomness,
    #[error("state backup destination already exists: {0}")]
    DestinationExists(PathBuf),
    #[error(transparent)]
    StateFile(#[from] StateFileError),
    #[error("cannot {action} {path}: {source}")]
    Io {
        action: &'static str,
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

pub fn encode_state_backup<T: Serialize>(
    state: &T,
    password: &[u8],
    kind: StateBackupKind,
) -> Result<Vec<u8>, StateBackupError> {
    require_password(password)?;
    let plaintext =
        Zeroizing::new(serde_json::to_vec(state).map_err(|_| StateBackupError::InvalidState)?);
    let mut salt = [0_u8; SALT_LEN];
    let mut nonce = [0_u8; NONCE_LEN];
    getrandom::fill(&mut salt).map_err(|_| StateBackupError::Randomness)?;
    getrandom::fill(&mut nonce).map_err(|_| StateBackupError::Randomness)?;
    let kdf = KdfHeader {
        algorithm: KDF_NAME.into(),
        version: KDF_VERSION,
        memory_kib: KDF_MEMORY_KIB,
        iterations: KDF_ITERATIONS,
        parallelism: KDF_PARALLELISM,
        salt_base64: STANDARD.encode(salt),
    };
    let cipher = CipherHeader {
        algorithm: CIPHER_NAME.into(),
        nonce_base64: STANDARD.encode(nonce),
    };
    let associated_data = serialize_associated_data(kind, &kdf, &cipher)?;
    let key = derive_key(password, &salt)?;
    let ciphertext = XChaCha20Poly1305::new_from_slice(key.as_ref())
        .map_err(|_| StateBackupError::UnsupportedCipher)?
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &plaintext,
                aad: &associated_data,
            },
        )
        .map_err(|_| StateBackupError::AuthenticationFailed)?;
    serde_json::to_vec_pretty(&BackupEnvelope {
        format: FORMAT_NAME.into(),
        format_version: FORMAT_VERSION,
        state_kind: kind,
        kdf,
        cipher,
        ciphertext_base64: STANDARD.encode(ciphertext),
    })
    .map_err(|_| StateBackupError::InvalidFormat)
}

pub fn decode_state_backup<T: DeserializeOwned>(
    bytes: &[u8],
    password: &[u8],
    expected_kind: StateBackupKind,
) -> Result<T, StateBackupError> {
    require_password(password)?;
    let envelope: BackupEnvelope =
        serde_json::from_slice(bytes).map_err(|_| StateBackupError::InvalidFormat)?;
    validate_envelope(&envelope, expected_kind)?;
    let salt = decode_fixed::<SALT_LEN>(&envelope.kdf.salt_base64)?;
    let nonce = decode_fixed::<NONCE_LEN>(&envelope.cipher.nonce_base64)?;
    let ciphertext = STANDARD
        .decode(&envelope.ciphertext_base64)
        .map_err(|_| StateBackupError::InvalidFormat)?;
    let associated_data =
        serialize_associated_data(envelope.state_kind, &envelope.kdf, &envelope.cipher)?;
    let key = derive_key(password, &salt)?;
    let plaintext = Zeroizing::new(
        XChaCha20Poly1305::new_from_slice(key.as_ref())
            .map_err(|_| StateBackupError::UnsupportedCipher)?
            .decrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &ciphertext,
                    aad: &associated_data,
                },
            )
            .map_err(|_| StateBackupError::AuthenticationFailed)?,
    );
    serde_json::from_slice(&plaintext).map_err(|_| StateBackupError::InvalidState)
}

/// Atomically writes a fully constructed encrypted backup. Existing files are
/// rejected unless `overwrite` is explicitly requested.
pub fn write_state_backup_file(
    path: &Path,
    bytes: &[u8],
    overwrite: bool,
) -> Result<(), StateBackupError> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)
        .map_err(|source| backup_io("create backup directory", parent, source))?;
    if path.exists() && !overwrite {
        return Err(StateBackupError::DestinationExists(path.to_path_buf()));
    }
    let temporary = suffixed_path(path, &format!(".tmp-{}", Uuid::new_v4()));
    let result = (|| {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)
            .map_err(|source| backup_io("create temporary backup", &temporary, source))?;
        restrict_state_file_permissions(&temporary)?;
        file.write_all(bytes)
            .map_err(|source| backup_io("write temporary backup", &temporary, source))?;
        file.sync_all()
            .map_err(|source| backup_io("sync temporary backup", &temporary, source))?;
        drop(file);
        install_backup(&temporary, path, overwrite)?;
        restrict_state_file_permissions(path)?;
        sync_backup_parent(parent)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn validate_envelope(
    envelope: &BackupEnvelope,
    expected_kind: StateBackupKind,
) -> Result<(), StateBackupError> {
    if envelope.format != FORMAT_NAME {
        return Err(StateBackupError::InvalidFormat);
    }
    if envelope.format_version != FORMAT_VERSION {
        return Err(StateBackupError::UnsupportedVersion(
            envelope.format_version,
        ));
    }
    if envelope.state_kind != expected_kind {
        return Err(StateBackupError::StateKindMismatch {
            expected: expected_kind,
            actual: envelope.state_kind,
        });
    }
    if envelope.kdf.algorithm != KDF_NAME
        || envelope.kdf.version != KDF_VERSION
        || envelope.kdf.memory_kib != KDF_MEMORY_KIB
        || envelope.kdf.iterations != KDF_ITERATIONS
        || envelope.kdf.parallelism != KDF_PARALLELISM
    {
        return Err(StateBackupError::UnsupportedKdf);
    }
    if envelope.cipher.algorithm != CIPHER_NAME {
        return Err(StateBackupError::UnsupportedCipher);
    }
    Ok(())
}

fn serialize_associated_data(
    kind: StateBackupKind,
    kdf: &KdfHeader,
    cipher: &CipherHeader,
) -> Result<Vec<u8>, StateBackupError> {
    serde_json::to_vec(&AssociatedData {
        format: FORMAT_NAME,
        format_version: FORMAT_VERSION,
        state_kind: kind,
        kdf,
        cipher,
    })
    .map_err(|_| StateBackupError::InvalidFormat)
}

fn derive_key(password: &[u8], salt: &[u8]) -> Result<Zeroizing<[u8; KEY_LEN]>, StateBackupError> {
    let params = Params::new(
        KDF_MEMORY_KIB,
        KDF_ITERATIONS,
        KDF_PARALLELISM,
        Some(KEY_LEN),
    )
    .map_err(|_| StateBackupError::KeyDerivation)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0_u8; KEY_LEN]);
    argon2
        .hash_password_into(password, salt, key.as_mut())
        .map_err(|_| StateBackupError::KeyDerivation)?;
    Ok(key)
}

fn require_password(password: &[u8]) -> Result<(), StateBackupError> {
    if password.is_empty() {
        Err(StateBackupError::EmptyPassword)
    } else {
        Ok(())
    }
}

fn decode_fixed<const N: usize>(value: &str) -> Result<[u8; N], StateBackupError> {
    STANDARD
        .decode(value)
        .map_err(|_| StateBackupError::InvalidFormat)?
        .try_into()
        .map_err(|_| StateBackupError::InvalidFormat)
}

fn suffixed_path(path: &Path, suffix: &str) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(suffix);
    PathBuf::from(value)
}

fn backup_io(action: &'static str, path: &Path, source: std::io::Error) -> StateBackupError {
    StateBackupError::Io {
        action,
        path: path.to_path_buf(),
        source,
    }
}

#[cfg(unix)]
fn sync_backup_parent(parent: &Path) -> Result<(), StateBackupError> {
    std::fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|source| backup_io("sync backup directory", parent, source))
}

#[cfg(windows)]
fn sync_backup_parent(_: &Path) -> Result<(), StateBackupError> {
    Ok(())
}

#[cfg(unix)]
fn install_backup(temporary: &Path, path: &Path, overwrite: bool) -> Result<(), StateBackupError> {
    if !overwrite {
        return match fs::hard_link(temporary, path) {
            Ok(()) => fs::remove_file(temporary)
                .map_err(|source| backup_io("remove temporary backup", temporary, source)),
            Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => {
                Err(StateBackupError::DestinationExists(path.to_path_buf()))
            }
            Err(source) => Err(backup_io("install state backup", path, source)),
        };
    }
    fs::rename(temporary, path).map_err(|source| backup_io("install state backup", path, source))
}

#[cfg(windows)]
fn install_backup(temporary: &Path, path: &Path, overwrite: bool) -> Result<(), StateBackupError> {
    use std::{iter::once, os::windows::ffi::OsStrExt};
    use windows_sys::Win32::Storage::FileSystem::{
        MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
    };

    if !overwrite && path.exists() {
        return Err(StateBackupError::DestinationExists(path.to_path_buf()));
    }
    let wide = |value: &Path| {
        value
            .as_os_str()
            .encode_wide()
            .chain(once(0))
            .collect::<Vec<_>>()
    };
    let flags = MOVEFILE_WRITE_THROUGH
        | if overwrite {
            MOVEFILE_REPLACE_EXISTING
        } else {
            0
        };
    let succeeded = unsafe { MoveFileExW(wide(temporary).as_ptr(), wide(path).as_ptr(), flags) };
    if succeeded == 0 {
        let source = std::io::Error::last_os_error();
        if !overwrite && path.exists() {
            return Err(StateBackupError::DestinationExists(path.to_path_buf()));
        }
        return Err(backup_io("install state backup", path, source));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};

    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    struct SecretState {
        private_key: String,
        administrator_token: String,
        network_psk: String,
    }

    fn secret_state() -> SecretState {
        SecretState {
            private_key: "device-private-key-material".into(),
            administrator_token: "controller-administrator-token".into(),
            network_psk: "network-pre-shared-key".into(),
        }
    }

    #[test]
    fn backup_round_trip_hides_all_secret_values() {
        let original = secret_state();
        let encoded =
            encode_state_backup(&original, b"correct horse", StateBackupKind::Agent).unwrap();
        let visible = String::from_utf8_lossy(&encoded);
        assert!(!visible.contains(&original.private_key));
        assert!(!visible.contains(&original.administrator_token));
        assert!(!visible.contains(&original.network_psk));
        let decoded: SecretState =
            decode_state_backup(&encoded, b"correct horse", StateBackupKind::Agent).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn wrong_password_and_ciphertext_tampering_fail_authentication() {
        let encoded =
            encode_state_backup(&secret_state(), b"right", StateBackupKind::Agent).unwrap();
        assert!(matches!(
            decode_state_backup::<SecretState>(&encoded, b"wrong", StateBackupKind::Agent),
            Err(StateBackupError::AuthenticationFailed)
        ));

        let mut envelope: BackupEnvelope = serde_json::from_slice(&encoded).unwrap();
        let mut ciphertext = STANDARD.decode(&envelope.ciphertext_base64).unwrap();
        ciphertext[0] ^= 1;
        envelope.ciphertext_base64 = STANDARD.encode(ciphertext);
        let tampered = serde_json::to_vec(&envelope).unwrap();
        assert!(matches!(
            decode_state_backup::<SecretState>(&tampered, b"right", StateBackupKind::Agent),
            Err(StateBackupError::AuthenticationFailed)
        ));
    }

    #[test]
    fn truncated_unknown_version_and_kind_mismatch_fail_closed() {
        let encoded =
            encode_state_backup(&secret_state(), b"password", StateBackupKind::Agent).unwrap();
        assert!(decode_state_backup::<SecretState>(
            &encoded[..encoded.len() / 2],
            b"password",
            StateBackupKind::Agent
        )
        .is_err());
        assert!(matches!(
            decode_state_backup::<SecretState>(&encoded, b"password", StateBackupKind::Controller),
            Err(StateBackupError::StateKindMismatch { .. })
        ));

        let mut envelope: BackupEnvelope = serde_json::from_slice(&encoded).unwrap();
        envelope.format_version += 1;
        let unknown = serde_json::to_vec(&envelope).unwrap();
        assert!(matches!(
            decode_state_backup::<SecretState>(&unknown, b"password", StateBackupKind::Agent),
            Err(StateBackupError::UnsupportedVersion(_))
        ));
    }
}
