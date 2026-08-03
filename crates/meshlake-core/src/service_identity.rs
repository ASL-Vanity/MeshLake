//! Planet-pinned service identities and explicit dual-sign rotation windows.

use crate::{
    cleanup_stale_state_backup, read_protected_state_file, recover_protected_state_file,
    write_protected_state_file, StateFileError, StateFileLock, RELAY_IDENTITY_PROTECTION_PURPOSE,
    ROOT_IDENTITY_PROTECTION_PURPOSE,
};
use ed25519_dalek::{SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::path::Path;
use thiserror::Error;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

const SERVICE_IDENTITY_SCHEMA_VERSION: u32 = 2;
const SERVICE_IDENTITY_MAX_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceIdentityPolicy {
    pub service_id: Uuid,
    pub current_public_key: Vec<u8>,
    pub next_public_key: Option<Vec<u8>>,
    pub transition_not_before_unix_seconds: Option<u64>,
    pub transition_not_after_unix_seconds: Option<u64>,
    #[serde(default)]
    pub revoked_public_keys: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceSignature {
    pub public_key: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ServiceIdentityError {
    #[error("service identity key has an invalid length")]
    InvalidKey,
    #[error("service identity rotation window is invalid")]
    InvalidRotationWindow,
    #[error("service identity rotation window expired before Planet convergence")]
    RotationWindowExpired,
    #[error("service identity key was revoked by Planet")]
    RevokedKey,
    #[error("service identity signature set is incomplete or untrusted")]
    InvalidSignatureSet,
}

#[derive(Debug, Error)]
pub enum ServiceIdentityFileError {
    #[error(transparent)]
    State(#[from] StateFileError),
    #[error("service identity schema version is unsupported")]
    UnsupportedSchema,
    #[error("service identity kind does not match its protected purpose")]
    WrongKind,
    #[error("service identity secret key has an invalid length")]
    InvalidSecretKey,
    #[error("service identity file belongs to a different service ID")]
    ServiceIdMismatch,
    #[error("service identity ID must not be nil")]
    InvalidServiceId,
    #[error("operating-system randomness is unavailable")]
    RandomnessUnavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ServiceIdentityKind {
    Root,
    Relay,
}

#[derive(Debug, Serialize, Deserialize)]
struct PersistedServiceIdentity {
    schema_version: u32,
    kind: ServiceIdentityKind,
    service_id: Uuid,
    secret_key: SecretBytes,
}

#[derive(Debug, Serialize, Deserialize)]
struct LegacyPersistedServiceIdentity {
    schema_version: u32,
    #[serde(default)]
    service_id: Option<Uuid>,
    secret_key: SecretBytes,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(transparent)]
struct SecretBytes(Vec<u8>);

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

pub struct ServiceSigningIdentity {
    pub service_id: Uuid,
    pub signing_key: SigningKey,
    _state_lock: StateFileLock,
}

pub fn load_or_create_root_identity(
    path: &Path,
    expected_service_id: Option<Uuid>,
) -> Result<ServiceSigningIdentity, ServiceIdentityFileError> {
    load_or_create_service_identity(
        path,
        expected_service_id,
        ServiceIdentityKind::Root,
        ROOT_IDENTITY_PROTECTION_PURPOSE,
    )
}

pub fn load_or_create_relay_identity(
    path: &Path,
    expected_service_id: Option<Uuid>,
) -> Result<ServiceSigningIdentity, ServiceIdentityFileError> {
    load_or_create_service_identity(
        path,
        expected_service_id,
        ServiceIdentityKind::Relay,
        RELAY_IDENTITY_PROTECTION_PURPOSE,
    )
}

fn load_or_create_service_identity(
    path: &Path,
    expected_service_id: Option<Uuid>,
    kind: ServiceIdentityKind,
    purpose: &[u8],
) -> Result<ServiceSigningIdentity, ServiceIdentityFileError> {
    let state_lock = StateFileLock::acquire(path)?;
    recover_protected_state_file(path)?;
    let loaded = match read_current_identity(path, purpose) {
        Ok((persisted, needs_protection_upgrade)) => {
            validate_persisted_identity(&persisted, kind, expected_service_id)?;
            if needs_protection_upgrade {
                write_protected_state_file(path, &persisted, purpose)?;
            }
            persisted
        }
        Err(ServiceIdentityFileError::State(StateFileError::Io { source, .. }))
            if source.kind() == std::io::ErrorKind::NotFound =>
        {
            create_identity(path, expected_service_id, kind, purpose)?
        }
        Err(ServiceIdentityFileError::State(StateFileError::Protection(_))) => {
            migrate_legacy_identity(path, expected_service_id, kind, purpose)?
        }
        Err(error) => return Err(error),
    };
    cleanup_stale_state_backup(path)?;
    let service_id = loaded.service_id;
    let secret_key = parse_secret_key(&loaded.secret_key)?;
    Ok(ServiceSigningIdentity {
        service_id,
        signing_key: SigningKey::from_bytes(&secret_key),
        _state_lock: state_lock,
    })
}

fn read_current_identity(
    path: &Path,
    purpose: &[u8],
) -> Result<(PersistedServiceIdentity, bool), ServiceIdentityFileError> {
    let decoded = read_protected_state_file::<PersistedServiceIdentity>(
        path,
        purpose,
        SERVICE_IDENTITY_MAX_BYTES,
    )?;
    Ok((decoded.value, decoded.needs_protection_upgrade))
}

fn migrate_legacy_identity(
    path: &Path,
    expected_service_id: Option<Uuid>,
    kind: ServiceIdentityKind,
    purpose: &[u8],
) -> Result<PersistedServiceIdentity, ServiceIdentityFileError> {
    let decoded = read_protected_state_file::<LegacyPersistedServiceIdentity>(
        path,
        purpose,
        SERVICE_IDENTITY_MAX_BYTES,
    )?;
    if !matches!(decoded.value.schema_version, 1 | 2) {
        return Err(ServiceIdentityFileError::UnsupportedSchema);
    }
    parse_secret_key(&decoded.value.secret_key)?;
    let service_id = decoded
        .value
        .service_id
        .or(expected_service_id)
        .unwrap_or_else(Uuid::new_v4);
    validate_service_id(service_id, expected_service_id)?;
    let migrated = PersistedServiceIdentity {
        schema_version: SERVICE_IDENTITY_SCHEMA_VERSION,
        kind,
        service_id,
        secret_key: decoded.value.secret_key,
    };
    write_protected_state_file(path, &migrated, purpose)?;
    Ok(migrated)
}

fn create_identity(
    path: &Path,
    expected_service_id: Option<Uuid>,
    kind: ServiceIdentityKind,
    purpose: &[u8],
) -> Result<PersistedServiceIdentity, ServiceIdentityFileError> {
    let mut secret_key = Zeroizing::new([0_u8; 32]);
    getrandom::fill(secret_key.as_mut())
        .map_err(|_| ServiceIdentityFileError::RandomnessUnavailable)?;
    let service_id = expected_service_id.unwrap_or_else(Uuid::new_v4);
    validate_service_id(service_id, expected_service_id)?;
    let persisted = PersistedServiceIdentity {
        schema_version: SERVICE_IDENTITY_SCHEMA_VERSION,
        kind,
        service_id,
        secret_key: SecretBytes(secret_key.to_vec()),
    };
    write_protected_state_file(path, &persisted, purpose)?;
    Ok(persisted)
}

fn validate_persisted_identity(
    persisted: &PersistedServiceIdentity,
    expected_kind: ServiceIdentityKind,
    expected_service_id: Option<Uuid>,
) -> Result<(), ServiceIdentityFileError> {
    if persisted.schema_version != SERVICE_IDENTITY_SCHEMA_VERSION {
        return Err(ServiceIdentityFileError::UnsupportedSchema);
    }
    if persisted.kind != expected_kind {
        return Err(ServiceIdentityFileError::WrongKind);
    }
    validate_service_id(persisted.service_id, expected_service_id)?;
    parse_secret_key(&persisted.secret_key)?;
    Ok(())
}

fn validate_service_id(
    service_id: Uuid,
    expected_service_id: Option<Uuid>,
) -> Result<(), ServiceIdentityFileError> {
    if service_id.is_nil() {
        return Err(ServiceIdentityFileError::InvalidServiceId);
    }
    if expected_service_id.is_some_and(|expected| expected != service_id) {
        return Err(ServiceIdentityFileError::ServiceIdMismatch);
    }
    Ok(())
}

fn parse_secret_key(
    secret_key: &SecretBytes,
) -> Result<Zeroizing<[u8; 32]>, ServiceIdentityFileError> {
    let bytes: [u8; 32] = secret_key
        .0
        .as_slice()
        .try_into()
        .map_err(|_| ServiceIdentityFileError::InvalidSecretKey)?;
    Ok(Zeroizing::new(bytes))
}

impl ServiceIdentityPolicy {
    pub fn stable(service_id: Uuid, current_public_key: Vec<u8>) -> Self {
        Self {
            service_id,
            current_public_key,
            next_public_key: None,
            transition_not_before_unix_seconds: None,
            transition_not_after_unix_seconds: None,
            revoked_public_keys: Vec::new(),
        }
    }

    pub fn required_public_keys(
        &self,
        now_unix_seconds: u64,
    ) -> Result<Vec<&[u8]>, ServiceIdentityError> {
        validate_key(&self.current_public_key)?;
        if self
            .revoked_public_keys
            .iter()
            .any(|key| key == &self.current_public_key)
        {
            return Err(ServiceIdentityError::RevokedKey);
        }
        let Some(next) = self.next_public_key.as_deref() else {
            if self.transition_not_before_unix_seconds.is_some()
                || self.transition_not_after_unix_seconds.is_some()
            {
                return Err(ServiceIdentityError::InvalidRotationWindow);
            }
            return Ok(vec![self.current_public_key.as_slice()]);
        };
        validate_key(next)?;
        if self.revoked_public_keys.iter().any(|key| key == next) {
            return Err(ServiceIdentityError::RevokedKey);
        }
        let (Some(not_before), Some(not_after)) = (
            self.transition_not_before_unix_seconds,
            self.transition_not_after_unix_seconds,
        ) else {
            return Err(ServiceIdentityError::InvalidRotationWindow);
        };
        if not_before >= not_after || next == self.current_public_key {
            return Err(ServiceIdentityError::InvalidRotationWindow);
        }
        if now_unix_seconds < not_before {
            return Ok(vec![self.current_public_key.as_slice()]);
        }
        if now_unix_seconds > not_after {
            return Err(ServiceIdentityError::RotationWindowExpired);
        }
        Ok(vec![self.current_public_key.as_slice(), next])
    }

    pub fn verify_signatures(
        &self,
        message: &[u8],
        signatures: &[ServiceSignature],
        now_unix_seconds: u64,
    ) -> Result<(), ServiceIdentityError> {
        let required = self.required_public_keys(now_unix_seconds)?;
        if signatures.iter().any(|signature| {
            self.revoked_public_keys
                .iter()
                .any(|key| key == &signature.public_key)
        }) {
            return Err(ServiceIdentityError::RevokedKey);
        }
        if signatures.len() != required.len() {
            return Err(ServiceIdentityError::InvalidSignatureSet);
        }
        for (public_key, signature) in required.into_iter().zip(signatures) {
            if signature.public_key != public_key {
                return Err(ServiceIdentityError::InvalidSignatureSet);
            }
            let key: [u8; 32] = public_key
                .try_into()
                .map_err(|_| ServiceIdentityError::InvalidKey)?;
            let signature: [u8; 64] = signature
                .signature
                .as_slice()
                .try_into()
                .map_err(|_| ServiceIdentityError::InvalidSignatureSet)?;
            VerifyingKey::from_bytes(&key)
                .map_err(|_| ServiceIdentityError::InvalidKey)?
                .verify(message, &ed25519_dalek::Signature::from_bytes(&signature))
                .map_err(|_| ServiceIdentityError::InvalidSignatureSet)?;
        }
        Ok(())
    }
}

fn validate_key(key: &[u8]) -> Result<(), ServiceIdentityError> {
    if key.len() == 32 {
        Ok(())
    } else {
        Err(ServiceIdentityError::InvalidKey)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn signature(key: &SigningKey, message: &[u8]) -> ServiceSignature {
        ServiceSignature {
            public_key: key.verifying_key().to_bytes().to_vec(),
            signature: key.sign(message).to_bytes().to_vec(),
        }
    }

    #[test]
    fn rotation_requires_both_keys_then_rejects_the_expired_window() {
        let current = SigningKey::from_bytes(&[1; 32]);
        let next = SigningKey::from_bytes(&[2; 32]);
        let policy = ServiceIdentityPolicy {
            service_id: Uuid::from_u128(3),
            current_public_key: current.verifying_key().to_bytes().to_vec(),
            next_public_key: Some(next.verifying_key().to_bytes().to_vec()),
            transition_not_before_unix_seconds: Some(100),
            transition_not_after_unix_seconds: Some(200),
            revoked_public_keys: Vec::new(),
        };
        let message = b"rotation";
        assert_eq!(
            policy.verify_signatures(message, &[signature(&current, message)], 99),
            Ok(())
        );
        assert_eq!(
            policy.verify_signatures(
                message,
                &[signature(&current, message), signature(&next, message)],
                99
            ),
            Err(ServiceIdentityError::InvalidSignatureSet)
        );
        assert_eq!(
            policy.verify_signatures(message, &[signature(&current, message)], 150),
            Err(ServiceIdentityError::InvalidSignatureSet)
        );
        assert_eq!(
            policy.verify_signatures(
                message,
                &[signature(&current, message), signature(&next, message)],
                150
            ),
            Ok(())
        );
        assert_eq!(
            policy.verify_signatures(
                message,
                &[signature(&next, message), signature(&current, message)],
                150
            ),
            Err(ServiceIdentityError::InvalidSignatureSet)
        );
        assert_eq!(
            policy.verify_signatures(
                message,
                &[signature(&current, message), signature(&current, message)],
                150
            ),
            Err(ServiceIdentityError::InvalidSignatureSet)
        );
        assert_eq!(
            policy.verify_signatures(message, &[signature(&next, message)], 201),
            Err(ServiceIdentityError::RotationWindowExpired)
        );
    }

    #[test]
    fn revoked_old_identity_cannot_be_reintroduced() {
        let old = SigningKey::from_bytes(&[4; 32]);
        let current = SigningKey::from_bytes(&[5; 32]);
        let mut policy = ServiceIdentityPolicy::stable(
            Uuid::from_u128(6),
            current.verifying_key().to_bytes().to_vec(),
        );
        policy
            .revoked_public_keys
            .push(old.verifying_key().to_bytes().to_vec());
        assert_eq!(
            policy.verify_signatures(b"ack", &[signature(&old, b"ack")], 300),
            Err(ServiceIdentityError::RevokedKey)
        );
    }

    #[test]
    fn persisted_service_identity_is_stable_across_restarts() {
        let directory =
            std::env::temp_dir().join(format!("meshlake-service-identity-{}", Uuid::new_v4()));
        let path = directory.join("relay.identity");
        let first = load_or_create_relay_identity(&path, None).unwrap();
        let service_id = first.service_id;
        let public_key = first.signing_key.verifying_key();
        assert!(load_or_create_relay_identity(&path, Some(service_id)).is_err());
        drop(first);
        let second = load_or_create_relay_identity(&path, Some(service_id)).unwrap();
        assert_eq!(second.service_id, service_id);
        assert_eq!(second.signing_key.verifying_key(), public_key);

        #[cfg(windows)]
        assert!(!String::from_utf8_lossy(&std::fs::read(&path).unwrap()).contains("secret_key"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        drop(second);
        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn identity_rejects_unknown_schema_wrong_kind_and_oversized_state() {
        let directory =
            std::env::temp_dir().join(format!("meshlake-service-invalid-{}", Uuid::new_v4()));
        let schema_path = directory.join("schema.identity");
        let lock = StateFileLock::acquire(&schema_path).unwrap();
        write_protected_state_file(
            &schema_path,
            &PersistedServiceIdentity {
                schema_version: SERVICE_IDENTITY_SCHEMA_VERSION + 1,
                kind: ServiceIdentityKind::Relay,
                service_id: Uuid::new_v4(),
                secret_key: SecretBytes(vec![7; 32]),
            },
            RELAY_IDENTITY_PROTECTION_PURPOSE,
        )
        .unwrap();
        drop(lock);
        assert!(matches!(
            load_or_create_relay_identity(&schema_path, None),
            Err(ServiceIdentityFileError::UnsupportedSchema)
        ));

        let kind_path = directory.join("kind.identity");
        let root = load_or_create_root_identity(&kind_path, None).unwrap();
        drop(root);
        assert!(load_or_create_relay_identity(&kind_path, None).is_err());

        let oversized_path = directory.join("oversized.identity");
        let lock = StateFileLock::acquire(&oversized_path).unwrap();
        std::fs::write(&oversized_path, vec![0_u8; SERVICE_IDENTITY_MAX_BYTES + 1]).unwrap();
        drop(lock);
        assert!(load_or_create_relay_identity(&oversized_path, None).is_err());
        let _ = std::fs::remove_dir_all(directory);
    }

    #[test]
    fn identity_recovers_interrupted_atomic_replacement() {
        let directory =
            std::env::temp_dir().join(format!("meshlake-service-recovery-{}", Uuid::new_v4()));
        let path = directory.join("root.identity");
        let identity = load_or_create_root_identity(&path, None).unwrap();
        let service_id = identity.service_id;
        let public_key = identity.signing_key.verifying_key();
        drop(identity);
        let mut backup = path.as_os_str().to_os_string();
        backup.push(".bak");
        std::fs::rename(&path, std::path::PathBuf::from(backup)).unwrap();
        let recovered = load_or_create_root_identity(&path, Some(service_id)).unwrap();
        assert_eq!(recovered.signing_key.verifying_key(), public_key);
        drop(recovered);
        let _ = std::fs::remove_dir_all(directory);
    }

    #[cfg(unix)]
    #[test]
    fn identity_rejects_symlink_paths() {
        use std::os::unix::fs::symlink;
        let directory =
            std::env::temp_dir().join(format!("meshlake-service-symlink-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&directory).unwrap();
        let target = directory.join("target.identity");
        std::fs::write(&target, b"not-an-identity").unwrap();
        let link = directory.join("link.identity");
        symlink(&target, &link).unwrap();
        assert!(load_or_create_relay_identity(&link, None).is_err());
        let _ = std::fs::remove_dir_all(directory);
    }

    #[cfg(windows)]
    #[test]
    fn identity_rejects_windows_reparse_paths() {
        use std::os::windows::fs::symlink_file;

        let directory =
            std::env::temp_dir().join(format!("meshlake-service-reparse-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&directory).unwrap();
        let target = directory.join("target.identity");
        std::fs::write(&target, b"not-an-identity").unwrap();
        let link = directory.join("link.identity");
        if symlink_file(&target, &link).is_ok() {
            assert!(load_or_create_relay_identity(&link, None).is_err());
        }
        let _ = std::fs::remove_dir_all(directory);
    }
}
