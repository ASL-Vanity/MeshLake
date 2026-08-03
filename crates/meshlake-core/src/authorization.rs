//! Controller-signed online authorization state and authenticated key refresh.

use crate::{CryptoError, DeviceId, MembershipCertificate, NetworkId};
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

pub const AUTHORIZATION_MANIFEST_VERSION: u8 = 1;
pub const AUTHORIZATION_EPOCH_HINT_VERSION: u8 = 1;
const REFRESH_DOMAIN: &[u8] = b"MeshLake membership refresh v1\0";
const EPOCH_HINT_DOMAIN: &[u8] = b"MeshLake authorization epoch hint v1\0";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizationEpochHint {
    pub version: u8,
    pub network_id: NetworkId,
    pub authorization_epoch: u64,
    pub network_key_epoch: u64,
    pub issued_at_unix_seconds: u64,
    pub expires_at_unix_seconds: u64,
    pub controller_public_key: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Serialize)]
struct AuthorizationEpochHintPayload<'a> {
    version: u8,
    network_id: NetworkId,
    authorization_epoch: u64,
    network_key_epoch: u64,
    issued_at_unix_seconds: u64,
    expires_at_unix_seconds: u64,
    controller_public_key: &'a [u8],
}

impl AuthorizationEpochHint {
    pub fn is_expired(&self, now_unix_seconds: u64) -> bool {
        now_unix_seconds > self.expires_at_unix_seconds
    }

    pub fn supersedes(&self, current: &Self) -> bool {
        self.network_id == current.network_id
            && (
                self.authorization_epoch,
                self.issued_at_unix_seconds,
                self.expires_at_unix_seconds,
            ) > (
                current.authorization_epoch,
                current.issued_at_unix_seconds,
                current.expires_at_unix_seconds,
            )
    }

    pub fn sign(
        network_id: NetworkId,
        authorization_epoch: u64,
        network_key_epoch: u64,
        issued_at_unix_seconds: u64,
        expires_at_unix_seconds: u64,
        signing_key: &SigningKey,
    ) -> Result<Self, CryptoError> {
        let controller_public_key = signing_key.verifying_key().to_bytes().to_vec();
        let payload = AuthorizationEpochHintPayload {
            version: AUTHORIZATION_EPOCH_HINT_VERSION,
            network_id,
            authorization_epoch,
            network_key_epoch,
            issued_at_unix_seconds,
            expires_at_unix_seconds,
            controller_public_key: &controller_public_key,
        };
        let mut encoded = Vec::from(EPOCH_HINT_DOMAIN);
        encoded.extend_from_slice(
            &serde_json::to_vec(&payload).map_err(|_| CryptoError::CertificateEncodingFailed)?,
        );
        Ok(Self {
            version: AUTHORIZATION_EPOCH_HINT_VERSION,
            network_id,
            authorization_epoch,
            network_key_epoch,
            issued_at_unix_seconds,
            expires_at_unix_seconds,
            controller_public_key,
            signature: signing_key.sign(&encoded).to_bytes().to_vec(),
        })
    }

    pub fn verify_from_controller(
        &self,
        trusted_controller_public_key: &[u8],
        now_unix_seconds: u64,
    ) -> Result<(), CryptoError> {
        if self.version != AUTHORIZATION_EPOCH_HINT_VERSION
            || self.controller_public_key != trusted_controller_public_key
            || now_unix_seconds > self.expires_at_unix_seconds
            || self.issued_at_unix_seconds > now_unix_seconds.saturating_add(120)
        {
            return Err(CryptoError::UntrustedController);
        }
        let public_key: [u8; 32] = self
            .controller_public_key
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::InvalidCertificate)?;
        let signature: [u8; 64] = self
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::InvalidCertificate)?;
        let payload = AuthorizationEpochHintPayload {
            version: self.version,
            network_id: self.network_id,
            authorization_epoch: self.authorization_epoch,
            network_key_epoch: self.network_key_epoch,
            issued_at_unix_seconds: self.issued_at_unix_seconds,
            expires_at_unix_seconds: self.expires_at_unix_seconds,
            controller_public_key: &self.controller_public_key,
        };
        let mut encoded = Vec::from(EPOCH_HINT_DOMAIN);
        encoded.extend_from_slice(
            &serde_json::to_vec(&payload).map_err(|_| CryptoError::CertificateEncodingFailed)?,
        );
        VerifyingKey::from_bytes(&public_key)
            .map_err(|_| CryptoError::InvalidCertificate)?
            .verify(&encoded, &ed25519_dalek::Signature::from_bytes(&signature))
            .map_err(|_| CryptoError::InvalidCertificate)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizedMembership {
    pub device_id: DeviceId,
    pub certificate_id: Uuid,
    pub device_public_key: Vec<u8>,
    pub network_key_epoch: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkAuthorizationManifest {
    pub version: u8,
    pub network_id: NetworkId,
    pub authorization_epoch: u64,
    pub network_key_epoch: u64,
    pub active_members: Vec<AuthorizedMembership>,
    pub revoked_certificate_ids: Vec<Uuid>,
    pub issued_at_unix_seconds: u64,
    pub expires_at_unix_seconds: u64,
    pub controller_public_key: Vec<u8>,
    pub signature: Vec<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub epoch_hint: Option<AuthorizationEpochHint>,
}

#[derive(Serialize)]
struct ManifestPayload<'a> {
    version: u8,
    network_id: NetworkId,
    authorization_epoch: u64,
    network_key_epoch: u64,
    active_members: &'a [AuthorizedMembership],
    revoked_certificate_ids: &'a [Uuid],
    issued_at_unix_seconds: u64,
    expires_at_unix_seconds: u64,
    controller_public_key: &'a [u8],
}

impl NetworkAuthorizationManifest {
    #[allow(clippy::too_many_arguments)]
    pub fn sign(
        network_id: NetworkId,
        authorization_epoch: u64,
        network_key_epoch: u64,
        mut active_members: Vec<AuthorizedMembership>,
        mut revoked_certificate_ids: Vec<Uuid>,
        issued_at_unix_seconds: u64,
        expires_at_unix_seconds: u64,
        signing_key: &SigningKey,
    ) -> Result<Self, CryptoError> {
        active_members.sort_by_key(|member| (member.device_id.0, member.certificate_id));
        revoked_certificate_ids.sort_unstable();
        revoked_certificate_ids.dedup();
        let controller_public_key = signing_key.verifying_key().to_bytes().to_vec();
        let payload = ManifestPayload {
            version: AUTHORIZATION_MANIFEST_VERSION,
            network_id,
            authorization_epoch,
            network_key_epoch,
            active_members: &active_members,
            revoked_certificate_ids: &revoked_certificate_ids,
            issued_at_unix_seconds,
            expires_at_unix_seconds,
            controller_public_key: &controller_public_key,
        };
        let encoded =
            serde_json::to_vec(&payload).map_err(|_| CryptoError::CertificateEncodingFailed)?;
        Ok(Self {
            version: AUTHORIZATION_MANIFEST_VERSION,
            network_id,
            authorization_epoch,
            network_key_epoch,
            active_members,
            revoked_certificate_ids,
            issued_at_unix_seconds,
            expires_at_unix_seconds,
            controller_public_key,
            signature: signing_key.sign(&encoded).to_bytes().to_vec(),
            epoch_hint: Some(AuthorizationEpochHint::sign(
                network_id,
                authorization_epoch,
                network_key_epoch,
                issued_at_unix_seconds,
                expires_at_unix_seconds,
                signing_key,
            )?),
        })
    }

    pub fn verify_from_controller(
        &self,
        trusted_controller_public_key: &[u8],
        now_unix_seconds: u64,
    ) -> Result<(), CryptoError> {
        if self.version != AUTHORIZATION_MANIFEST_VERSION
            || self.controller_public_key != trusted_controller_public_key
        {
            return Err(CryptoError::UntrustedController);
        }
        if now_unix_seconds > self.expires_at_unix_seconds
            || self.issued_at_unix_seconds > now_unix_seconds.saturating_add(120)
        {
            return Err(CryptoError::AuthorizationManifestExpired);
        }
        let public_key: [u8; 32] = self
            .controller_public_key
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::InvalidCertificate)?;
        let signature: [u8; 64] = self
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::InvalidCertificate)?;
        let payload = ManifestPayload {
            version: self.version,
            network_id: self.network_id,
            authorization_epoch: self.authorization_epoch,
            network_key_epoch: self.network_key_epoch,
            active_members: &self.active_members,
            revoked_certificate_ids: &self.revoked_certificate_ids,
            issued_at_unix_seconds: self.issued_at_unix_seconds,
            expires_at_unix_seconds: self.expires_at_unix_seconds,
            controller_public_key: &self.controller_public_key,
        };
        let encoded =
            serde_json::to_vec(&payload).map_err(|_| CryptoError::CertificateEncodingFailed)?;
        VerifyingKey::from_bytes(&public_key)
            .map_err(|_| CryptoError::InvalidCertificate)?
            .verify(&encoded, &ed25519_dalek::Signature::from_bytes(&signature))
            .map_err(|_| CryptoError::InvalidCertificate)?;
        if let Some(hint) = &self.epoch_hint {
            hint.verify_from_controller(trusted_controller_public_key, now_unix_seconds)?;
            if hint.network_id != self.network_id
                || hint.authorization_epoch != self.authorization_epoch
                || hint.network_key_epoch != self.network_key_epoch
            {
                return Err(CryptoError::InvalidCertificate);
            }
        }
        Ok(())
    }

    pub fn authorizes(&self, certificate: &MembershipCertificate) -> bool {
        certificate.claims.network_id == self.network_id
            && certificate.network_key_epoch == self.network_key_epoch
            && !self
                .revoked_certificate_ids
                .contains(&certificate.certificate_id)
            && self.active_members.iter().any(|member| {
                member.device_id == certificate.claims.device_id
                    && member.certificate_id == certificate.certificate_id
                    && member.device_public_key == certificate.claims.device_public_key
                    && member.network_key_epoch == certificate.network_key_epoch
            })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MembershipRefreshRequestPayload {
    pub version: u8,
    pub network_id: NetworkId,
    pub device_id: DeviceId,
    pub certificate_id: Uuid,
    pub issued_at_unix_seconds: u64,
    pub nonce: [u8; 16],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MembershipRefreshRequest {
    pub payload: MembershipRefreshRequestPayload,
    pub signature: Vec<u8>,
}

impl MembershipRefreshRequest {
    pub fn sign(
        network_id: NetworkId,
        device_id: DeviceId,
        certificate_id: Uuid,
        issued_at_unix_seconds: u64,
        nonce: [u8; 16],
        signing_key: &SigningKey,
    ) -> Result<Self, CryptoError> {
        let payload = MembershipRefreshRequestPayload {
            version: 1,
            network_id,
            device_id,
            certificate_id,
            issued_at_unix_seconds,
            nonce,
        };
        let encoded = refresh_message(&payload)?;
        Ok(Self {
            payload,
            signature: signing_key.sign(&encoded).to_bytes().to_vec(),
        })
    }

    pub fn verify(
        &self,
        expected_device_public_key: &[u8],
        now_unix_seconds: u64,
        maximum_clock_skew_seconds: u64,
    ) -> Result<(), CryptoError> {
        if self.payload.version != 1
            || now_unix_seconds.abs_diff(self.payload.issued_at_unix_seconds)
                > maximum_clock_skew_seconds
        {
            return Err(CryptoError::StaleSessionHandshake);
        }
        let public_key: [u8; 32] = expected_device_public_key
            .try_into()
            .map_err(|_| CryptoError::InvalidIdentityKey)?;
        let signature: [u8; 64] = self
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| CryptoError::InvalidSessionSignature)?;
        let encoded = refresh_message(&self.payload)?;
        VerifyingKey::from_bytes(&public_key)
            .map_err(|_| CryptoError::InvalidIdentityKey)?
            .verify(&encoded, &ed25519_dalek::Signature::from_bytes(&signature))
            .map_err(|_| CryptoError::InvalidSessionSignature)
    }
}

fn refresh_message(payload: &MembershipRefreshRequestPayload) -> Result<Vec<u8>, CryptoError> {
    let encoded = serde_json::to_vec(payload).map_err(|_| CryptoError::InvalidSessionPacket)?;
    let mut message = Vec::with_capacity(REFRESH_DOMAIN.len() + encoded.len());
    message.extend_from_slice(REFRESH_DOMAIN);
    message.extend_from_slice(&encoded);
    Ok(message)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MembershipRefreshResponse {
    pub revoked: bool,
    pub authorization: NetworkAuthorizationManifest,
    pub certificate: Option<MembershipCertificate>,
    #[serde(default)]
    pub network_key: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MembershipCertificate, MembershipClaims};

    #[test]
    fn signed_manifest_authorizes_only_the_current_certificate_epoch() {
        let controller = SigningKey::from_bytes(&[41_u8; 32]);
        let device = SigningKey::from_bytes(&[42_u8; 32]);
        let network = NetworkId(Uuid::from_u128(43));
        let device_id = DeviceId(Uuid::from_u128(44));
        let certificate_id = Uuid::from_u128(45);
        let certificate = MembershipCertificate::sign_authorized(
            MembershipClaims {
                network_id: network,
                device_id,
                device_public_key: device.verifying_key().to_bytes().to_vec(),
                assigned_addresses: vec!["100.64.43.2".parse().unwrap()],
                allowed_routes: vec!["100.64.43.0/24".into()],
                issued_at_unix_seconds: 100,
                expires_at_unix_seconds: Some(1_000),
            },
            certificate_id,
            7,
            &controller,
        )
        .unwrap();
        let manifest = NetworkAuthorizationManifest::sign(
            network,
            9,
            7,
            vec![AuthorizedMembership {
                device_id,
                certificate_id,
                device_public_key: device.verifying_key().to_bytes().to_vec(),
                network_key_epoch: 7,
            }],
            vec![],
            100,
            200,
            &controller,
        )
        .unwrap();
        assert!(manifest.authorizes(&certificate));
        assert_eq!(
            manifest.verify_from_controller(&controller.verifying_key().to_bytes(), 150),
            Ok(())
        );
        let mut revoked = manifest.clone();
        revoked.revoked_certificate_ids.push(certificate_id);
        assert!(!revoked.authorizes(&certificate));
    }

    #[test]
    fn refresh_request_is_bound_to_the_device_identity() {
        let device = SigningKey::from_bytes(&[46_u8; 32]);
        let attacker = SigningKey::from_bytes(&[47_u8; 32]);
        let request = MembershipRefreshRequest::sign(
            NetworkId(Uuid::from_u128(48)),
            DeviceId(Uuid::from_u128(49)),
            Uuid::from_u128(50),
            100,
            [51_u8; 16],
            &device,
        )
        .unwrap();
        assert_eq!(
            request.verify(&device.verifying_key().to_bytes(), 100, 120),
            Ok(())
        );
        assert_eq!(
            request.verify(&attacker.verifying_key().to_bytes(), 100, 120),
            Err(CryptoError::InvalidSessionSignature)
        );
    }

    #[test]
    fn epoch_hint_is_controller_pinned_short_lived_and_tamper_evident() {
        let controller = SigningKey::from_bytes(&[52; 32]);
        let other_controller = SigningKey::from_bytes(&[53; 32]);
        let hint = AuthorizationEpochHint::sign(
            NetworkId(Uuid::from_u128(54)),
            8,
            3,
            100,
            120,
            &controller,
        )
        .unwrap();
        assert_eq!(
            hint.verify_from_controller(&controller.verifying_key().to_bytes(), 110),
            Ok(())
        );
        assert!(hint
            .verify_from_controller(&other_controller.verifying_key().to_bytes(), 110)
            .is_err());
        assert!(hint
            .verify_from_controller(&controller.verifying_key().to_bytes(), 121)
            .is_err());
        let mut tampered = hint;
        tampered.authorization_epoch = 9;
        assert!(tampered
            .verify_from_controller(&controller.verifying_key().to_bytes(), 110)
            .is_err());
    }

    #[test]
    fn epoch_hint_expiry_and_equal_epoch_replacement_are_explicit() {
        let controller = SigningKey::from_bytes(&[55; 32]);
        let network_id = NetworkId(Uuid::from_u128(56));
        let current =
            AuthorizationEpochHint::sign(network_id, 8, 3, 100, 120, &controller).unwrap();
        let later_issued =
            AuthorizationEpochHint::sign(network_id, 8, 3, 101, 120, &controller).unwrap();
        let later_expiry =
            AuthorizationEpochHint::sign(network_id, 8, 3, 101, 130, &controller).unwrap();
        let other_network = AuthorizationEpochHint::sign(
            NetworkId(Uuid::from_u128(57)),
            9,
            3,
            102,
            140,
            &controller,
        )
        .unwrap();

        assert!(!current.is_expired(120));
        assert!(current.is_expired(121));
        assert!(later_issued.supersedes(&current));
        assert!(later_expiry.supersedes(&later_issued));
        assert!(!current.supersedes(&later_expiry));
        assert!(!other_network.supersedes(&current));
    }
}
