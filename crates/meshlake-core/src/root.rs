//! Authenticated UDP discovery protocol shared by MeshLake roots and agents.
//!
//! Roots learn public endpoints and controller-authorized network membership,
//! but never receive a virtual network's traffic key.

use crate::{
    AuthorizationEpochHint, DeviceId, MembershipCertificate, NetworkAuthorizationManifest,
    NetworkId, ServiceIdentityError, ServiceIdentityPolicy, ServiceSignature,
};
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
};
use thiserror::Error;
use uuid::Uuid;

pub const ROOT_PROTOCOL_VERSION: u8 = 1;
pub const ROOT_REGISTRATION_PROTOCOL_VERSION_LEGACY: u8 = 1;
pub const ROOT_REGISTRATION_PROTOCOL_VERSION_TARGET_BOUND: u8 = 2;
const ROOT_IDENTITY_RESPONSE_DOMAIN: &[u8] = b"MeshLake root identity response v2\0";
const TARGET_BOUND_REGISTRATION_DOMAIN: &[u8] = b"MeshLake target-bound service registration v2\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RootRegistrationServiceKind {
    Root,
    Relay,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RootRegistrationTarget {
    pub service_kind: RootRegistrationServiceKind,
    pub service_id: Uuid,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RootRegistrationPayload {
    pub version: u8,
    pub device_id: DeviceId,
    pub device_public_key: Vec<u8>,
    pub certificates: Vec<MembershipCertificate>,
    pub authorization_manifests: Vec<NetworkAuthorizationManifest>,
    pub candidates: Vec<SocketAddr>,
    pub issued_at_unix_seconds: u64,
    pub nonce: [u8; 16],
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<RootRegistrationTarget>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RootRegistration {
    pub payload: RootRegistrationPayload,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RootPeer {
    pub network_id: NetworkId,
    pub device_id: DeviceId,
    pub candidates: Vec<SocketAddr>,
    #[serde(default)]
    pub assigned_addresses: Vec<IpAddr>,
    /// Controller-signed membership used by clients to authenticate the peer's
    /// device identity before starting a pairwise session.
    #[serde(default)]
    pub certificate: Option<MembershipCertificate>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RootResponse {
    Registered {
        observed_endpoint: SocketAddr,
        peers: Vec<RootPeer>,
        refresh_after_seconds: u32,
        #[serde(default)]
        authorization_hints: Vec<AuthorizationEpochHint>,
    },
    Error {
        message: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct RootResponsePayload<'a> {
    version: u8,
    root_public_key: &'a [u8],
    request_nonce: [u8; 16],
    response: &'a RootResponse,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct RootIdentityResponsePayload<'a> {
    version: u8,
    root_id: Uuid,
    request_nonce: [u8; 16],
    response: &'a RootResponse,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedRootResponse {
    pub version: u8,
    pub root_public_key: Vec<u8>,
    pub request_nonce: [u8; 16],
    pub response: RootResponse,
    pub signature: Vec<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_id: Option<Uuid>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub identity_signatures: Vec<ServiceSignature>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RootProtocolError {
    #[error("root protocol message has an unsupported version")]
    UnsupportedVersion,
    #[error("node or root identity key has an invalid length")]
    InvalidIdentityKey,
    #[error("root protocol signature is invalid")]
    InvalidSignature,
    #[error("root registration is too old or too far in the future")]
    StaleRegistration,
    #[error("root registration has no controller-authorized membership")]
    MissingMembership,
    #[error("membership does not match the registering node identity")]
    MembershipIdentityMismatch,
    #[error("membership was not signed by a trusted controller")]
    UntrustedMembership,
    #[error("membership is missing a current controller authorization manifest")]
    MissingAuthorization,
    #[error("registration authorization manifests are duplicate, unrelated, or untrusted")]
    InvalidAuthorizationSet,
    #[error("registration contains duplicate memberships for one network")]
    DuplicateMembership,
    #[error("membership has been revoked or uses an old network key epoch")]
    RevokedMembership,
    #[error("root registration target service does not match this service")]
    TargetMismatch,
    #[error("legacy root registration is disabled")]
    LegacyRegistrationDisabled,
    #[error("root protocol message cannot be encoded")]
    EncodingFailed,
    #[error(transparent)]
    InvalidServiceIdentity(#[from] ServiceIdentityError),
}

impl RootRegistration {
    pub fn sign(
        device_id: DeviceId,
        certificates: Vec<MembershipCertificate>,
        candidates: Vec<SocketAddr>,
        issued_at_unix_seconds: u64,
        nonce: [u8; 16],
        signing_key: &SigningKey,
    ) -> Result<Self, RootProtocolError> {
        Self::sign_authorized(
            device_id,
            certificates,
            Vec::new(),
            candidates,
            issued_at_unix_seconds,
            nonce,
            signing_key,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn sign_authorized(
        device_id: DeviceId,
        certificates: Vec<MembershipCertificate>,
        authorization_manifests: Vec<NetworkAuthorizationManifest>,
        candidates: Vec<SocketAddr>,
        issued_at_unix_seconds: u64,
        nonce: [u8; 16],
        signing_key: &SigningKey,
    ) -> Result<Self, RootProtocolError> {
        let payload = RootRegistrationPayload {
            version: ROOT_REGISTRATION_PROTOCOL_VERSION_LEGACY,
            device_id,
            device_public_key: signing_key.verifying_key().to_bytes().to_vec(),
            certificates,
            authorization_manifests,
            candidates,
            issued_at_unix_seconds,
            nonce,
            target: None,
        };
        Self::sign_payload(payload, signing_key)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn sign_authorized_for_service(
        device_id: DeviceId,
        certificates: Vec<MembershipCertificate>,
        authorization_manifests: Vec<NetworkAuthorizationManifest>,
        candidates: Vec<SocketAddr>,
        issued_at_unix_seconds: u64,
        nonce: [u8; 16],
        service_kind: RootRegistrationServiceKind,
        service_id: Uuid,
        signing_key: &SigningKey,
    ) -> Result<Self, RootProtocolError> {
        let payload = RootRegistrationPayload {
            version: ROOT_REGISTRATION_PROTOCOL_VERSION_TARGET_BOUND,
            device_id,
            device_public_key: signing_key.verifying_key().to_bytes().to_vec(),
            certificates,
            authorization_manifests,
            candidates,
            issued_at_unix_seconds,
            nonce,
            target: Some(RootRegistrationTarget {
                service_kind,
                service_id,
            }),
        };
        Self::sign_payload(payload, signing_key)
    }

    fn sign_payload(
        payload: RootRegistrationPayload,
        signing_key: &SigningKey,
    ) -> Result<Self, RootProtocolError> {
        let message = registration_signature_message(&payload)?;
        Ok(Self {
            signature: signing_key.sign(&message).to_bytes().to_vec(),
            payload,
        })
    }

    pub fn verify(
        &self,
        trusted_controller_keys: &[Vec<u8>],
        now_unix_seconds: u64,
        maximum_clock_skew_seconds: u64,
    ) -> Result<(), RootProtocolError> {
        self.verify_membership(
            trusted_controller_keys,
            now_unix_seconds,
            maximum_clock_skew_seconds,
            None,
        )?;
        self.verify_authorization_set(trusted_controller_keys, now_unix_seconds, false)
    }

    fn verify_membership(
        &self,
        trusted_controller_keys: &[Vec<u8>],
        now_unix_seconds: u64,
        maximum_clock_skew_seconds: u64,
        expected_target: Option<RootRegistrationTarget>,
    ) -> Result<(), RootProtocolError> {
        match (self.payload.version, self.payload.target, expected_target) {
            (ROOT_REGISTRATION_PROTOCOL_VERSION_LEGACY, None, None) => {}
            (ROOT_REGISTRATION_PROTOCOL_VERSION_TARGET_BOUND, Some(actual), Some(expected))
                if actual == expected => {}
            (ROOT_REGISTRATION_PROTOCOL_VERSION_LEGACY, _, _)
            | (ROOT_REGISTRATION_PROTOCOL_VERSION_TARGET_BOUND, _, _) => {
                return Err(RootProtocolError::TargetMismatch);
            }
            _ => return Err(RootProtocolError::UnsupportedVersion),
        }
        let age = now_unix_seconds.abs_diff(self.payload.issued_at_unix_seconds);
        if age > maximum_clock_skew_seconds {
            return Err(RootProtocolError::StaleRegistration);
        }
        let public_key: [u8; 32] = self
            .payload
            .device_public_key
            .as_slice()
            .try_into()
            .map_err(|_| RootProtocolError::InvalidIdentityKey)?;
        let signature: [u8; 64] = self
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| RootProtocolError::InvalidSignature)?;
        let message = registration_signature_message(&self.payload)?;
        VerifyingKey::from_bytes(&public_key)
            .map_err(|_| RootProtocolError::InvalidIdentityKey)?
            .verify(&message, &ed25519_dalek::Signature::from_bytes(&signature))
            .map_err(|_| RootProtocolError::InvalidSignature)?;

        if self.payload.certificates.is_empty() {
            return Err(RootProtocolError::MissingMembership);
        }
        for certificate in &self.payload.certificates {
            if certificate.claims.device_id != self.payload.device_id
                || certificate.claims.device_public_key != self.payload.device_public_key
            {
                return Err(RootProtocolError::MembershipIdentityMismatch);
            }
            let trusted = trusted_controller_keys.iter().any(|key| {
                certificate
                    .verify_from_controller(key, now_unix_seconds)
                    .is_ok()
            });
            if !trusted {
                return Err(RootProtocolError::UntrustedMembership);
            }
        }
        Ok(())
    }

    fn verify_authorization_set(
        &self,
        trusted_controller_keys: &[Vec<u8>],
        now_unix_seconds: u64,
        require_every_membership: bool,
    ) -> Result<(), RootProtocolError> {
        let mut certificates = HashMap::new();
        for certificate in &self.payload.certificates {
            if certificates
                .insert(certificate.claims.network_id, certificate)
                .is_some()
            {
                return Err(RootProtocolError::DuplicateMembership);
            }
        }
        let mut manifests = HashMap::new();
        for manifest in &self.payload.authorization_manifests {
            let Some(certificate) = certificates.get(&manifest.network_id).copied() else {
                return Err(RootProtocolError::InvalidAuthorizationSet);
            };
            if manifests.insert(manifest.network_id, manifest).is_some()
                || manifest.controller_public_key != certificate.controller_public_key
                || !trusted_controller_keys.iter().any(|key| {
                    manifest
                        .verify_from_controller(key, now_unix_seconds)
                        .is_ok()
                })
            {
                return Err(RootProtocolError::InvalidAuthorizationSet);
            }
            if !manifest.authorizes(certificate) {
                return Err(RootProtocolError::RevokedMembership);
            }
        }
        if require_every_membership && manifests.len() != certificates.len() {
            return Err(RootProtocolError::MissingAuthorization);
        }
        Ok(())
    }

    /// Verifies the registration and requires every membership certificate to
    /// be covered by a current controller-signed authorization manifest.
    /// Roots and relays use this after the online-revocation rollout; the
    /// compatibility [`Self::verify`] path remains available for state migration
    /// and explicit legacy tooling.
    pub fn verify_authorized(
        &self,
        trusted_controller_keys: &[Vec<u8>],
        now_unix_seconds: u64,
        maximum_clock_skew_seconds: u64,
    ) -> Result<(), RootProtocolError> {
        self.verify_membership(
            trusted_controller_keys,
            now_unix_seconds,
            maximum_clock_skew_seconds,
            None,
        )?;
        self.verify_authorization_set(trusted_controller_keys, now_unix_seconds, true)
    }

    pub fn verify_authorized_for_service(
        &self,
        trusted_controller_keys: &[Vec<u8>],
        now_unix_seconds: u64,
        maximum_clock_skew_seconds: u64,
        service_kind: RootRegistrationServiceKind,
        service_id: Uuid,
    ) -> Result<(), RootProtocolError> {
        self.verify_membership(
            trusted_controller_keys,
            now_unix_seconds,
            maximum_clock_skew_seconds,
            Some(RootRegistrationTarget {
                service_kind,
                service_id,
            }),
        )?;
        self.verify_authorization_set(trusted_controller_keys, now_unix_seconds, true)
    }
}

fn registration_signature_message(
    payload: &RootRegistrationPayload,
) -> Result<Vec<u8>, RootProtocolError> {
    let encoded = serde_json::to_vec(payload).map_err(|_| RootProtocolError::EncodingFailed)?;
    match payload.version {
        ROOT_REGISTRATION_PROTOCOL_VERSION_LEGACY if payload.target.is_none() => Ok(encoded),
        ROOT_REGISTRATION_PROTOCOL_VERSION_TARGET_BOUND if payload.target.is_some() => {
            let mut message =
                Vec::with_capacity(TARGET_BOUND_REGISTRATION_DOMAIN.len() + encoded.len());
            message.extend_from_slice(TARGET_BOUND_REGISTRATION_DOMAIN);
            message.extend_from_slice(&encoded);
            Ok(message)
        }
        _ => Err(RootProtocolError::UnsupportedVersion),
    }
}

impl SignedRootResponse {
    pub fn sign(
        request_nonce: [u8; 16],
        response: RootResponse,
        signing_key: &SigningKey,
    ) -> Result<Self, RootProtocolError> {
        let root_public_key = signing_key.verifying_key().to_bytes().to_vec();
        let payload = RootResponsePayload {
            version: ROOT_PROTOCOL_VERSION,
            root_public_key: &root_public_key,
            request_nonce,
            response: &response,
        };
        let bytes = serde_json::to_vec(&payload).map_err(|_| RootProtocolError::EncodingFailed)?;
        Ok(Self {
            version: ROOT_PROTOCOL_VERSION,
            root_public_key,
            request_nonce,
            response,
            signature: signing_key.sign(&bytes).to_bytes().to_vec(),
            root_id: None,
            identity_signatures: Vec::new(),
        })
    }

    pub fn sign_with_identity(
        request_nonce: [u8; 16],
        response: RootResponse,
        root_id: Uuid,
        signing_keys: &[&SigningKey],
    ) -> Result<Self, RootProtocolError> {
        let current = signing_keys
            .first()
            .ok_or(RootProtocolError::InvalidIdentityKey)?;
        let root_public_key = current.verifying_key().to_bytes().to_vec();
        let legacy_payload = RootResponsePayload {
            version: ROOT_PROTOCOL_VERSION,
            root_public_key: &root_public_key,
            request_nonce,
            response: &response,
        };
        let legacy_bytes =
            serde_json::to_vec(&legacy_payload).map_err(|_| RootProtocolError::EncodingFailed)?;
        let identity_payload = RootIdentityResponsePayload {
            version: ROOT_PROTOCOL_VERSION,
            root_id,
            request_nonce,
            response: &response,
        };
        let mut identity_message = Vec::from(ROOT_IDENTITY_RESPONSE_DOMAIN);
        identity_message.extend_from_slice(
            &serde_json::to_vec(&identity_payload)
                .map_err(|_| RootProtocolError::EncodingFailed)?,
        );
        Ok(Self {
            version: ROOT_PROTOCOL_VERSION,
            root_public_key,
            request_nonce,
            response,
            signature: current.sign(&legacy_bytes).to_bytes().to_vec(),
            root_id: Some(root_id),
            identity_signatures: signing_keys
                .iter()
                .map(|key| ServiceSignature {
                    public_key: key.verifying_key().to_bytes().to_vec(),
                    signature: key.sign(&identity_message).to_bytes().to_vec(),
                })
                .collect(),
        })
    }

    pub fn verify(&self, trusted_root_public_key: &[u8]) -> Result<(), RootProtocolError> {
        if self.version != ROOT_PROTOCOL_VERSION || self.root_public_key != trusted_root_public_key
        {
            return Err(RootProtocolError::InvalidIdentityKey);
        }
        let public_key: [u8; 32] = self
            .root_public_key
            .as_slice()
            .try_into()
            .map_err(|_| RootProtocolError::InvalidIdentityKey)?;
        let signature: [u8; 64] = self
            .signature
            .as_slice()
            .try_into()
            .map_err(|_| RootProtocolError::InvalidSignature)?;
        let payload = RootResponsePayload {
            version: self.version,
            root_public_key: &self.root_public_key,
            request_nonce: self.request_nonce,
            response: &self.response,
        };
        let bytes = serde_json::to_vec(&payload).map_err(|_| RootProtocolError::EncodingFailed)?;
        VerifyingKey::from_bytes(&public_key)
            .map_err(|_| RootProtocolError::InvalidIdentityKey)?
            .verify(&bytes, &ed25519_dalek::Signature::from_bytes(&signature))
            .map_err(|_| RootProtocolError::InvalidSignature)
    }

    pub fn verify_identity(
        &self,
        identity: &ServiceIdentityPolicy,
        now_unix_seconds: u64,
    ) -> Result<(), RootProtocolError> {
        if self.version != ROOT_PROTOCOL_VERSION
            || self.root_id != Some(identity.service_id)
            || self.root_public_key != identity.current_public_key
        {
            return Err(RootProtocolError::InvalidIdentityKey);
        }
        let payload = RootIdentityResponsePayload {
            version: self.version,
            root_id: identity.service_id,
            request_nonce: self.request_nonce,
            response: &self.response,
        };
        let mut message = Vec::from(ROOT_IDENTITY_RESPONSE_DOMAIN);
        message.extend_from_slice(
            &serde_json::to_vec(&payload).map_err(|_| RootProtocolError::EncodingFailed)?,
        );
        identity.verify_signatures(&message, &self.identity_signatures, now_unix_seconds)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AuthorizedMembership, MembershipClaims};
    use uuid::Uuid;

    fn test_authorization(
        controller: &SigningKey,
        certificate: &MembershipCertificate,
        now_unix_seconds: u64,
    ) -> NetworkAuthorizationManifest {
        NetworkAuthorizationManifest::sign(
            certificate.claims.network_id,
            1,
            certificate.network_key_epoch,
            vec![AuthorizedMembership {
                device_id: certificate.claims.device_id,
                certificate_id: certificate.certificate_id,
                device_public_key: certificate.claims.device_public_key.clone(),
                network_key_epoch: certificate.network_key_epoch,
            }],
            vec![],
            now_unix_seconds,
            now_unix_seconds + 90,
            controller,
        )
        .unwrap()
    }

    #[test]
    fn root_registration_binds_membership_to_node_key() {
        let controller = SigningKey::from_bytes(&[1_u8; 32]);
        let node = SigningKey::from_bytes(&[2_u8; 32]);
        let device_id = DeviceId(Uuid::from_u128(7));
        let certificate = MembershipCertificate::sign(
            MembershipClaims {
                network_id: NetworkId(Uuid::from_u128(8)),
                device_id,
                device_public_key: node.verifying_key().to_bytes().to_vec(),
                assigned_addresses: vec!["100.64.0.2".parse().unwrap()],
                allowed_routes: vec!["100.64.0.0/24".into()],
                issued_at_unix_seconds: 100,
                expires_at_unix_seconds: None,
            },
            &controller,
        )
        .unwrap();
        let registration = RootRegistration::sign(
            device_id,
            vec![certificate],
            vec!["192.0.2.1:40000".parse().unwrap()],
            100,
            [3_u8; 16],
            &node,
        )
        .unwrap();
        assert_eq!(
            registration.verify(&[controller.verifying_key().to_bytes().to_vec()], 100, 120),
            Ok(())
        );
        assert_eq!(
            registration.verify_authorized(
                &[controller.verifying_key().to_bytes().to_vec()],
                100,
                120
            ),
            Err(RootProtocolError::MissingAuthorization)
        );
    }

    #[test]
    fn strict_registration_requires_current_authorization() {
        let controller = SigningKey::from_bytes(&[11_u8; 32]);
        let node = SigningKey::from_bytes(&[12_u8; 32]);
        let device_id = DeviceId(Uuid::from_u128(13));
        let certificate = MembershipCertificate::sign_authorized(
            MembershipClaims {
                network_id: NetworkId(Uuid::from_u128(14)),
                device_id,
                device_public_key: node.verifying_key().to_bytes().to_vec(),
                assigned_addresses: vec!["100.64.14.2".parse().unwrap()],
                allowed_routes: vec!["100.64.14.0/24".into()],
                issued_at_unix_seconds: 100,
                expires_at_unix_seconds: Some(1_000),
            },
            Uuid::from_u128(15),
            7,
            &controller,
        )
        .unwrap();
        let authorization = test_authorization(&controller, &certificate, 100);
        let registration = RootRegistration::sign_authorized(
            device_id,
            vec![certificate.clone()],
            vec![authorization.clone()],
            vec![],
            100,
            [16_u8; 16],
            &node,
        )
        .unwrap();
        let trusted = [controller.verifying_key().to_bytes().to_vec()];
        assert_eq!(registration.verify_authorized(&trusted, 100, 120), Ok(()));

        let revoked = NetworkAuthorizationManifest::sign(
            certificate.claims.network_id,
            2,
            certificate.network_key_epoch,
            vec![],
            vec![certificate.certificate_id],
            100,
            190,
            &controller,
        )
        .unwrap();
        let revoked_registration = RootRegistration::sign_authorized(
            device_id,
            vec![certificate.clone()],
            vec![revoked],
            vec![],
            100,
            [17_u8; 16],
            &node,
        )
        .unwrap();
        assert_eq!(
            revoked_registration.verify_authorized(&trusted, 100, 120),
            Err(RootProtocolError::RevokedMembership)
        );

        let old_epoch = NetworkAuthorizationManifest::sign(
            certificate.claims.network_id,
            3,
            certificate.network_key_epoch + 1,
            authorization.active_members,
            vec![],
            100,
            190,
            &controller,
        )
        .unwrap();
        let old_epoch_registration = RootRegistration::sign_authorized(
            device_id,
            vec![certificate],
            vec![old_epoch],
            vec![],
            100,
            [18_u8; 16],
            &node,
        )
        .unwrap();
        assert_eq!(
            old_epoch_registration.verify_authorized(&trusted, 100, 120),
            Err(RootProtocolError::RevokedMembership)
        );
    }

    #[test]
    fn target_bound_registration_rejects_cross_service_and_legacy_replay() {
        let controller = SigningKey::from_bytes(&[31; 32]);
        let node = SigningKey::from_bytes(&[32; 32]);
        let device_id = DeviceId(Uuid::from_u128(33));
        let certificate = MembershipCertificate::sign_authorized(
            MembershipClaims {
                network_id: NetworkId(Uuid::from_u128(34)),
                device_id,
                device_public_key: node.verifying_key().to_bytes().to_vec(),
                assigned_addresses: vec!["100.64.34.2".parse().unwrap()],
                allowed_routes: vec!["100.64.34.0/24".into()],
                issued_at_unix_seconds: 100,
                expires_at_unix_seconds: Some(1_000),
            },
            Uuid::from_u128(35),
            1,
            &controller,
        )
        .unwrap();
        let authorization = test_authorization(&controller, &certificate, 100);
        let trusted = [controller.verifying_key().to_bytes().to_vec()];
        let relay_a = Uuid::from_u128(36);
        let relay_b = Uuid::from_u128(37);
        let root_a = Uuid::from_u128(38);
        let root_b = Uuid::from_u128(39);
        let relay_registration = RootRegistration::sign_authorized_for_service(
            device_id,
            vec![certificate.clone()],
            vec![authorization.clone()],
            vec![],
            100,
            [40; 16],
            RootRegistrationServiceKind::Relay,
            relay_a,
            &node,
        )
        .unwrap();
        assert_eq!(
            relay_registration.verify_authorized_for_service(
                &trusted,
                100,
                120,
                RootRegistrationServiceKind::Relay,
                relay_a,
            ),
            Ok(())
        );
        for (kind, service_id) in [
            (RootRegistrationServiceKind::Relay, relay_b),
            (RootRegistrationServiceKind::Root, root_a),
        ] {
            assert_eq!(
                relay_registration
                    .verify_authorized_for_service(&trusted, 100, 120, kind, service_id,),
                Err(RootProtocolError::TargetMismatch)
            );
        }
        assert_eq!(
            relay_registration.verify_authorized(&trusted, 100, 120),
            Err(RootProtocolError::TargetMismatch)
        );

        let root_registration = RootRegistration::sign_authorized_for_service(
            device_id,
            vec![certificate.clone()],
            vec![authorization.clone()],
            vec![],
            100,
            [41; 16],
            RootRegistrationServiceKind::Root,
            root_a,
            &node,
        )
        .unwrap();
        assert_eq!(
            root_registration.verify_authorized_for_service(
                &trusted,
                100,
                120,
                RootRegistrationServiceKind::Root,
                root_a,
            ),
            Ok(())
        );
        for (kind, service_id) in [
            (RootRegistrationServiceKind::Root, root_b),
            (RootRegistrationServiceKind::Relay, relay_a),
        ] {
            assert_eq!(
                root_registration
                    .verify_authorized_for_service(&trusted, 100, 120, kind, service_id,),
                Err(RootProtocolError::TargetMismatch)
            );
        }

        let legacy = RootRegistration::sign_authorized(
            device_id,
            vec![certificate],
            vec![authorization],
            vec![],
            100,
            [42; 16],
            &node,
        )
        .unwrap();
        assert_eq!(legacy.verify_authorized(&trusted, 100, 120), Ok(()));
        assert_eq!(
            legacy.verify_authorized_for_service(
                &trusted,
                100,
                120,
                RootRegistrationServiceKind::Relay,
                relay_a,
            ),
            Err(RootProtocolError::TargetMismatch)
        );
    }

    #[test]
    fn registration_rejects_a_valid_manifest_followed_by_a_forged_duplicate_hint() {
        let controller = SigningKey::from_bytes(&[43; 32]);
        let attacker = SigningKey::from_bytes(&[44; 32]);
        let node = SigningKey::from_bytes(&[45; 32]);
        let device_id = DeviceId(Uuid::from_u128(46));
        let certificate = MembershipCertificate::sign_authorized(
            MembershipClaims {
                network_id: NetworkId(Uuid::from_u128(47)),
                device_id,
                device_public_key: node.verifying_key().to_bytes().to_vec(),
                assigned_addresses: vec!["100.64.47.2".parse().unwrap()],
                allowed_routes: vec!["100.64.47.0/24".into()],
                issued_at_unix_seconds: 100,
                expires_at_unix_seconds: Some(1_000),
            },
            Uuid::from_u128(48),
            1,
            &controller,
        )
        .unwrap();
        let valid = test_authorization(&controller, &certificate, 100);
        let mut forged = valid.clone();
        forged.epoch_hint = Some(
            AuthorizationEpochHint::sign(
                certificate.claims.network_id,
                valid.authorization_epoch + 100,
                valid.network_key_epoch,
                100,
                190,
                &attacker,
            )
            .unwrap(),
        );
        let registration = RootRegistration::sign_authorized(
            device_id,
            vec![certificate],
            vec![valid, forged],
            vec![],
            100,
            [49; 16],
            &node,
        )
        .unwrap();
        assert_eq!(
            registration.verify_authorized(
                &[controller.verifying_key().to_bytes().to_vec()],
                100,
                120,
            ),
            Err(RootProtocolError::InvalidAuthorizationSet)
        );
    }

    #[test]
    fn signed_root_response_requires_pinned_root_key() {
        let root = SigningKey::from_bytes(&[4_u8; 32]);
        let response = SignedRootResponse::sign(
            [5_u8; 16],
            RootResponse::Error {
                message: "test".into(),
            },
            &root,
        )
        .unwrap();
        assert_eq!(response.verify(&root.verifying_key().to_bytes()), Ok(()));
        assert!(response.verify(&[9_u8; 32]).is_err());
    }

    #[test]
    fn root_identity_rotation_requires_dual_signatures_and_revokes_old_keys() {
        let current = SigningKey::from_bytes(&[21; 32]);
        let next = SigningKey::from_bytes(&[22; 32]);
        let root_id = Uuid::from_u128(23);
        let response = SignedRootResponse::sign_with_identity(
            [24; 16],
            RootResponse::Error {
                message: "bounded".into(),
            },
            root_id,
            &[&current, &next],
        )
        .unwrap();
        let transition = ServiceIdentityPolicy {
            service_id: root_id,
            current_public_key: current.verifying_key().to_bytes().to_vec(),
            next_public_key: Some(next.verifying_key().to_bytes().to_vec()),
            transition_not_before_unix_seconds: Some(100),
            transition_not_after_unix_seconds: Some(200),
            revoked_public_keys: Vec::new(),
        };
        assert_eq!(response.verify_identity(&transition, 150), Ok(()));

        let revoked = ServiceIdentityPolicy {
            service_id: root_id,
            current_public_key: next.verifying_key().to_bytes().to_vec(),
            next_public_key: None,
            transition_not_before_unix_seconds: None,
            transition_not_after_unix_seconds: None,
            revoked_public_keys: vec![current.verifying_key().to_bytes().to_vec()],
        };
        assert!(response.verify_identity(&revoked, 210).is_err());
    }
}
