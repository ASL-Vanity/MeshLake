//! Planet-pinned service identities and explicit dual-sign rotation windows.

use ed25519_dalek::{SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::{fs, path::Path};
use thiserror::Error;
use uuid::Uuid;

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
    #[error("service identity file operation failed")]
    Io(#[from] std::io::Error),
    #[error("service identity file is invalid")]
    InvalidFile(#[from] serde_json::Error),
    #[error("service identity secret key has an invalid length")]
    InvalidSecretKey,
    #[error("service identity file belongs to a different service ID")]
    ServiceIdMismatch,
    #[error("operating-system randomness is unavailable")]
    RandomnessUnavailable,
}

#[derive(Debug, Serialize, Deserialize)]
struct PersistedServiceIdentity {
    schema_version: u32,
    service_id: Uuid,
    secret_key: Vec<u8>,
}

pub struct ServiceSigningIdentity {
    pub service_id: Uuid,
    pub signing_key: SigningKey,
}

pub fn load_or_create_service_identity(
    path: &Path,
    expected_service_id: Option<Uuid>,
) -> Result<ServiceSigningIdentity, ServiceIdentityFileError> {
    if path.exists() {
        let persisted: PersistedServiceIdentity = serde_json::from_slice(&fs::read(path)?)?;
        if expected_service_id.is_some_and(|expected| expected != persisted.service_id) {
            return Err(ServiceIdentityFileError::ServiceIdMismatch);
        }
        let secret_key: [u8; 32] = persisted
            .secret_key
            .as_slice()
            .try_into()
            .map_err(|_| ServiceIdentityFileError::InvalidSecretKey)?;
        return Ok(ServiceSigningIdentity {
            service_id: persisted.service_id,
            signing_key: SigningKey::from_bytes(&secret_key),
        });
    }
    let mut secret_key = [0_u8; 32];
    getrandom::fill(&mut secret_key)
        .map_err(|_| ServiceIdentityFileError::RandomnessUnavailable)?;
    let service_id = expected_service_id.unwrap_or_else(Uuid::new_v4);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(
        path,
        serde_json::to_vec_pretty(&PersistedServiceIdentity {
            schema_version: 1,
            service_id,
            secret_key: secret_key.to_vec(),
        })?,
    )?;
    restrict_identity_permissions(path)?;
    Ok(ServiceSigningIdentity {
        service_id,
        signing_key: SigningKey::from_bytes(&secret_key),
    })
}

#[cfg(unix)]
fn restrict_identity_permissions(path: &Path) -> Result<(), std::io::Error> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn restrict_identity_permissions(_: &Path) -> Result<(), std::io::Error> {
    Ok(())
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
        for signature in signatures {
            if self
                .revoked_public_keys
                .iter()
                .any(|key| key == &signature.public_key)
            {
                return Err(ServiceIdentityError::RevokedKey);
            }
            if signature.public_key != self.current_public_key
                && self.next_public_key.as_ref() != Some(&signature.public_key)
            {
                return Err(ServiceIdentityError::InvalidSignatureSet);
            }
        }
        for public_key in required {
            let matching = signatures
                .iter()
                .filter(|signature| signature.public_key == public_key)
                .collect::<Vec<_>>();
            if matching.len() != 1 {
                return Err(ServiceIdentityError::InvalidSignatureSet);
            }
            let key: [u8; 32] = public_key
                .try_into()
                .map_err(|_| ServiceIdentityError::InvalidKey)?;
            let signature: [u8; 64] = matching[0]
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
        let path =
            std::env::temp_dir().join(format!("meshlake-service-identity-{}.json", Uuid::new_v4()));
        let first = load_or_create_service_identity(&path, None).unwrap();
        let second = load_or_create_service_identity(&path, Some(first.service_id)).unwrap();
        assert_eq!(first.service_id, second.service_id);
        assert_eq!(
            first.signing_key.verifying_key(),
            second.signing_key.verifying_key()
        );
        let _ = std::fs::remove_file(path);
    }
}
