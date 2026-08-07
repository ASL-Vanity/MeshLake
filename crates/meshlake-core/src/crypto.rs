//! End-to-end packet protection for a MeshLake virtual network.
//!
//! A relay sees the outer routing header but receives only `SealedPacket::ciphertext`.
//! Network keys must come from the controller enrollment flow and must never be logged.

use crate::{DeviceId, NetworkId, ServiceIdentityPolicy, VirtualNetwork};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::net::{IpAddr, SocketAddr};
use thiserror::Error;

#[derive(Clone, PartialEq, Eq)]
pub struct NetworkKey([u8; 32]);

impl NetworkKey {
    pub fn generate() -> Result<Self, CryptoError> {
        let mut bytes = [0_u8; 32];
        getrandom::fill(&mut bytes).map_err(|_| CryptoError::RandomnessUnavailable)?;
        Ok(Self(bytes))
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self, CryptoError> {
        let bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| CryptoError::InvalidNetworkKey)?;
        Ok(Self(bytes))
    }

    /// Exports the key for enrollment persistence. Callers must protect the returned bytes.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }

    /// Encrypts one IP packet. `associated_data` should contain immutable outer metadata,
    /// such as the network and source/destination device identifiers.
    pub fn seal(
        &self,
        plaintext: &[u8],
        associated_data: &[u8],
    ) -> Result<SealedPacket, CryptoError> {
        let mut nonce = [0_u8; 24];
        getrandom::fill(&mut nonce).map_err(|_| CryptoError::RandomnessUnavailable)?;
        let cipher = XChaCha20Poly1305::new((&self.0).into());
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: associated_data,
                },
            )
            .map_err(|_| CryptoError::EncryptionFailed)?;
        Ok(SealedPacket { nonce, ciphertext })
    }

    pub fn open(
        &self,
        packet: &SealedPacket,
        associated_data: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let cipher = XChaCha20Poly1305::new((&self.0).into());
        cipher
            .decrypt(
                XNonce::from_slice(&packet.nonce),
                Payload {
                    msg: &packet.ciphertext,
                    aad: associated_data,
                },
            )
            .map_err(|_| CryptoError::AuthenticationFailed)
    }
}

impl std::fmt::Debug for NetworkKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("NetworkKey([redacted])")
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedPacket {
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CryptoError {
    #[error("operating-system randomness is unavailable")]
    RandomnessUnavailable,
    #[error("packet encryption failed")]
    EncryptionFailed,
    #[error("packet authentication failed")]
    AuthenticationFailed,
    #[error("network key must contain exactly 32 bytes")]
    InvalidNetworkKey,
    #[error("overlay packet is malformed")]
    InvalidOverlayPacket,
    #[error("session packet is malformed")]
    InvalidSessionPacket,
    #[error("device identity key has an invalid length")]
    InvalidIdentityKey,
    #[error("session handshake signature is invalid")]
    InvalidSessionSignature,
    #[error("session handshake is too old or too far in the future")]
    StaleSessionHandshake,
    #[error("session handshake identities do not match the routed peers")]
    SessionIdentityMismatch,
    #[error("session key derivation failed")]
    InvalidSessionKey,
    #[error("session data packet was already received or is outside the replay window")]
    SessionReplayDetected,
    #[error("authorization manifest has expired or is not yet valid")]
    AuthorizationManifestExpired,
    #[error("membership certificate is malformed or has an invalid signature")]
    InvalidCertificate,
    #[error("membership certificate has expired")]
    CertificateExpired,
    #[error("membership certificate was not issued by the trusted controller")]
    UntrustedController,
    #[error("membership certificate cannot be encoded")]
    CertificateEncodingFailed,
    #[error("Planet service identity policy is invalid or expired")]
    InvalidServiceIdentity,
}

/// Controller-signed authorization for a device to participate in one virtual network.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MembershipClaims {
    pub network_id: NetworkId,
    pub device_id: DeviceId,
    /// Ed25519 identity used by this device when registering with root
    /// discovery services. Legacy certificates may omit it, but such
    /// certificates cannot use the authenticated root protocol.
    #[serde(default)]
    pub device_public_key: Vec<u8>,
    pub assigned_addresses: Vec<std::net::IpAddr>,
    pub allowed_routes: Vec<String>,
    pub issued_at_unix_seconds: u64,
    pub expires_at_unix_seconds: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MembershipCertificate {
    #[serde(default)]
    pub version: u8,
    #[serde(default)]
    pub certificate_id: uuid::Uuid,
    #[serde(default)]
    pub network_key_epoch: u64,
    pub claims: MembershipClaims,
    pub controller_public_key: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrollmentResponse {
    pub network: VirtualNetwork,
    pub certificate: MembershipCertificate,
    /// Per-network traffic key. The controller response must be delivered over TLS outside of
    /// loopback development, and agents must protect this value at rest.
    pub network_key: Vec<u8>,
    pub authorization: crate::authorization::NetworkAuthorizationManifest,
    /// Ephemeral TURN REST credential. It is intentionally not part of a
    /// joined network's persisted control-plane state.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub turn_credential: Option<TurnCredential>,
}

/// TURN server transport distributed as signed public Planet metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TurnTransport {
    Udp,
    Tcp,
    Tls,
}

/// Controller-signed public TURN endpoint. TLS transports pin the server leaf
/// certificate just like a Planet V4 TLS Relay; UDP/TCP TURN use no implicit
/// platform trust store.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanetTurnServer {
    pub endpoint: SocketAddr,
    pub transport: TurnTransport,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_name: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub certificate_sha256: Vec<u8>,
    #[serde(default)]
    pub priority: u16,
}

/// Short-lived credential generated from the Controller's protected TURN REST
/// shared secret. It is sent only through enrollment/refresh HTTPS responses,
/// is never persisted, and is redacted from `Debug` output.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TurnCredential {
    pub version: u8,
    pub username: String,
    pub password: String,
    pub expires_at_unix_seconds: u64,
}

impl std::fmt::Debug for TurnCredential {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TurnCredential")
            .field("version", &self.version)
            .field("username", &self.username)
            .field("password", &"[REDACTED]")
            .field("expires_at_unix_seconds", &self.expires_at_unix_seconds)
            .finish()
    }
}

#[derive(Serialize)]
struct MembershipCertificatePayload<'a> {
    version: u8,
    certificate_id: uuid::Uuid,
    network_key_epoch: u64,
    claims: &'a MembershipClaims,
}

/// A signed bootstrap document for a self-hosted MeshLake "Planet".  It
/// distributes only public discovery information; enrollment and packet keys
/// remain separate protocols.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanetRoot {
    pub public_key: Vec<u8>,
    pub endpoints: Vec<SocketAddr>,
    #[serde(default)]
    pub priority: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity: Option<ServiceIdentityPolicy>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanetRelay {
    pub endpoint: SocketAddr,
    #[serde(default)]
    pub priority: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity: Option<ServiceIdentityPolicy>,
}

/// Controller-signed pinned TLS endpoint attached to a Planet V3 Relay
/// service identity. The SHA-256 value is calculated over the leaf
/// certificate's DER encoding; clients never substitute system trust.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanetTlsRelay {
    pub relay_id: uuid::Uuid,
    pub endpoint: SocketAddr,
    pub server_name: String,
    pub certificate_sha256: Vec<u8>,
    #[serde(default)]
    pub priority: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanetManifest {
    pub version: u8,
    pub controller_url: String,
    /// Compatibility primary relay for Planet V1 clients.
    pub relay_endpoint: SocketAddr,
    #[serde(default)]
    pub roots: Vec<PlanetRoot>,
    #[serde(default)]
    pub relays: Vec<PlanetRelay>,
    #[serde(default)]
    pub tls_relays: Vec<PlanetTlsRelay>,
    #[serde(default)]
    pub turn_servers: Vec<PlanetTurnServer>,
    #[serde(default)]
    pub stun_servers: Vec<String>,
    pub issued_at_unix_seconds: u64,
    pub expires_at_unix_seconds: Option<u64>,
    pub controller_public_key: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Serialize)]
struct PlanetManifestPayload<'a> {
    version: u8,
    controller_url: &'a str,
    relay_endpoint: SocketAddr,
    stun_servers: &'a [String],
    issued_at_unix_seconds: u64,
    expires_at_unix_seconds: Option<u64>,
    controller_public_key: &'a [u8],
}

#[derive(Serialize)]
struct PlanetManifestV2Payload<'a> {
    version: u8,
    controller_url: &'a str,
    relay_endpoint: SocketAddr,
    roots: &'a [PlanetRoot],
    relays: &'a [PlanetRelay],
    stun_servers: &'a [String],
    issued_at_unix_seconds: u64,
    expires_at_unix_seconds: Option<u64>,
    controller_public_key: &'a [u8],
}

#[derive(Serialize)]
struct PlanetManifestV3Payload<'a> {
    version: u8,
    controller_url: &'a str,
    relay_endpoint: SocketAddr,
    roots: &'a [PlanetRoot],
    relays: &'a [PlanetRelay],
    stun_servers: &'a [String],
    issued_at_unix_seconds: u64,
    expires_at_unix_seconds: Option<u64>,
    controller_public_key: &'a [u8],
}

#[derive(Serialize)]
struct PlanetManifestV4Payload<'a> {
    version: u8,
    controller_url: &'a str,
    relay_endpoint: SocketAddr,
    roots: &'a [PlanetRoot],
    relays: &'a [PlanetRelay],
    tls_relays: &'a [PlanetTlsRelay],
    stun_servers: &'a [String],
    issued_at_unix_seconds: u64,
    expires_at_unix_seconds: Option<u64>,
    controller_public_key: &'a [u8],
}

#[derive(Serialize)]
struct PlanetManifestV5Payload<'a> {
    version: u8,
    controller_url: &'a str,
    relay_endpoint: SocketAddr,
    roots: &'a [PlanetRoot],
    relays: &'a [PlanetRelay],
    tls_relays: &'a [PlanetTlsRelay],
    turn_servers: &'a [PlanetTurnServer],
    stun_servers: &'a [String],
    issued_at_unix_seconds: u64,
    expires_at_unix_seconds: Option<u64>,
    controller_public_key: &'a [u8],
}

#[derive(Serialize)]
struct PlanetManifestSemanticPayload<'a> {
    version: u8,
    controller_url: &'a str,
    relay_endpoint: SocketAddr,
    roots: &'a [PlanetRoot],
    relays: &'a [PlanetRelay],
    tls_relays: &'a [PlanetTlsRelay],
    turn_servers: &'a [PlanetTurnServer],
    stun_servers: &'a [String],
    controller_public_key: &'a [u8],
}

impl PlanetManifest {
    /// Digest of public Planet routing and identity semantics. Timestamps,
    /// expiry, and signatures are intentionally excluded so equal-time
    /// mutation detection compares only the signed configuration meaning.
    pub fn semantic_digest(&self) -> Result<[u8; 32], CryptoError> {
        let encoded = serde_json::to_vec(&PlanetManifestSemanticPayload {
            version: self.version,
            controller_url: &self.controller_url,
            relay_endpoint: self.relay_endpoint,
            roots: &self.roots,
            relays: &self.relays,
            tls_relays: &self.tls_relays,
            turn_servers: &self.turn_servers,
            stun_servers: &self.stun_servers,
            controller_public_key: &self.controller_public_key,
        })
        .map_err(|_| CryptoError::CertificateEncodingFailed)?;
        Ok(Sha256::digest(encoded).into())
    }

    pub fn sign(
        controller_url: String,
        relay_endpoint: SocketAddr,
        stun_servers: Vec<String>,
        issued_at_unix_seconds: u64,
        expires_at_unix_seconds: Option<u64>,
        signing_key: &SigningKey,
    ) -> Result<Self, CryptoError> {
        let controller_public_key = signing_key.verifying_key().to_bytes().to_vec();
        let payload = PlanetManifestPayload {
            version: 1,
            controller_url: &controller_url,
            relay_endpoint,
            stun_servers: &stun_servers,
            issued_at_unix_seconds,
            expires_at_unix_seconds,
            controller_public_key: &controller_public_key,
        };
        let bytes =
            serde_json::to_vec(&payload).map_err(|_| CryptoError::CertificateEncodingFailed)?;
        Ok(Self {
            version: 1,
            controller_url,
            relay_endpoint,
            roots: Vec::new(),
            relays: Vec::new(),
            tls_relays: Vec::new(),
            turn_servers: Vec::new(),
            stun_servers,
            issued_at_unix_seconds,
            expires_at_unix_seconds,
            controller_public_key,
            signature: signing_key.sign(&bytes).to_bytes().to_vec(),
        })
    }

    pub fn sign_v2(
        controller_url: String,
        mut roots: Vec<PlanetRoot>,
        mut relays: Vec<PlanetRelay>,
        stun_servers: Vec<String>,
        issued_at_unix_seconds: u64,
        expires_at_unix_seconds: Option<u64>,
        signing_key: &SigningKey,
    ) -> Result<Self, CryptoError> {
        roots.sort_by_key(|root| root.priority);
        relays.sort_by_key(|relay| relay.priority);
        let relay_endpoint = relays
            .first()
            .ok_or(CryptoError::InvalidCertificate)?
            .endpoint;
        let controller_public_key = signing_key.verifying_key().to_bytes().to_vec();
        let payload = PlanetManifestV2Payload {
            version: 2,
            controller_url: &controller_url,
            relay_endpoint,
            roots: &roots,
            relays: &relays,
            stun_servers: &stun_servers,
            issued_at_unix_seconds,
            expires_at_unix_seconds,
            controller_public_key: &controller_public_key,
        };
        let bytes =
            serde_json::to_vec(&payload).map_err(|_| CryptoError::CertificateEncodingFailed)?;
        Ok(Self {
            version: 2,
            controller_url,
            relay_endpoint,
            roots,
            relays,
            tls_relays: Vec::new(),
            turn_servers: Vec::new(),
            stun_servers,
            issued_at_unix_seconds,
            expires_at_unix_seconds,
            controller_public_key,
            signature: signing_key.sign(&bytes).to_bytes().to_vec(),
        })
    }

    pub fn sign_v3(
        controller_url: String,
        mut roots: Vec<PlanetRoot>,
        mut relays: Vec<PlanetRelay>,
        stun_servers: Vec<String>,
        issued_at_unix_seconds: u64,
        expires_at_unix_seconds: Option<u64>,
        signing_key: &SigningKey,
    ) -> Result<Self, CryptoError> {
        roots.sort_by_key(|root| root.priority);
        relays.sort_by_key(|relay| relay.priority);
        if roots.iter().any(|root| root.identity.is_none())
            || relays.is_empty()
            || relays.iter().any(|relay| relay.identity.is_none())
        {
            return Err(CryptoError::InvalidServiceIdentity);
        }
        for root in &roots {
            let identity = root
                .identity
                .as_ref()
                .ok_or(CryptoError::InvalidServiceIdentity)?;
            identity
                .required_public_keys(issued_at_unix_seconds)
                .map_err(|_| CryptoError::InvalidServiceIdentity)?;
            if root.public_key != identity.current_public_key {
                return Err(CryptoError::InvalidServiceIdentity);
            }
        }
        for relay in &relays {
            relay
                .identity
                .as_ref()
                .ok_or(CryptoError::InvalidServiceIdentity)?
                .required_public_keys(issued_at_unix_seconds)
                .map_err(|_| CryptoError::InvalidServiceIdentity)?;
        }
        let relay_endpoint = relays[0].endpoint;
        let controller_public_key = signing_key.verifying_key().to_bytes().to_vec();
        let payload = PlanetManifestV3Payload {
            version: 3,
            controller_url: &controller_url,
            relay_endpoint,
            roots: &roots,
            relays: &relays,
            stun_servers: &stun_servers,
            issued_at_unix_seconds,
            expires_at_unix_seconds,
            controller_public_key: &controller_public_key,
        };
        let bytes =
            serde_json::to_vec(&payload).map_err(|_| CryptoError::CertificateEncodingFailed)?;
        Ok(Self {
            version: 3,
            controller_url,
            relay_endpoint,
            roots,
            relays,
            tls_relays: Vec::new(),
            turn_servers: Vec::new(),
            stun_servers,
            issued_at_unix_seconds,
            expires_at_unix_seconds,
            controller_public_key,
            signature: signing_key.sign(&bytes).to_bytes().to_vec(),
        })
    }

    pub fn sign_v4(
        controller_url: String,
        roots: Vec<PlanetRoot>,
        relays: Vec<PlanetRelay>,
        mut tls_relays: Vec<PlanetTlsRelay>,
        stun_servers: Vec<String>,
        issued_at_unix_seconds: u64,
        expires_at_unix_seconds: Option<u64>,
        signing_key: &SigningKey,
    ) -> Result<Self, CryptoError> {
        let mut manifest = Self::sign_v3(
            controller_url,
            roots,
            relays,
            stun_servers,
            issued_at_unix_seconds,
            expires_at_unix_seconds,
            signing_key,
        )?;
        tls_relays.sort_by_key(|relay| relay.priority);
        validate_tls_relays(&tls_relays, &manifest.relays)?;
        let payload = PlanetManifestV4Payload {
            version: 4,
            controller_url: &manifest.controller_url,
            relay_endpoint: manifest.relay_endpoint,
            roots: &manifest.roots,
            relays: &manifest.relays,
            tls_relays: &tls_relays,
            stun_servers: &manifest.stun_servers,
            issued_at_unix_seconds: manifest.issued_at_unix_seconds,
            expires_at_unix_seconds: manifest.expires_at_unix_seconds,
            controller_public_key: &manifest.controller_public_key,
        };
        let bytes =
            serde_json::to_vec(&payload).map_err(|_| CryptoError::CertificateEncodingFailed)?;
        manifest.version = 4;
        manifest.tls_relays = tls_relays;
        manifest.signature = signing_key.sign(&bytes).to_bytes().to_vec();
        Ok(manifest)
    }

    /// Creates a Planet V5 manifest with controller-signed public TURN
    /// endpoints. TURN credentials themselves deliberately remain outside the
    /// manifest because they are short lived and device specific.
    pub fn sign_v5(
        controller_url: String,
        roots: Vec<PlanetRoot>,
        relays: Vec<PlanetRelay>,
        tls_relays: Vec<PlanetTlsRelay>,
        mut turn_servers: Vec<PlanetTurnServer>,
        stun_servers: Vec<String>,
        issued_at_unix_seconds: u64,
        expires_at_unix_seconds: Option<u64>,
        signing_key: &SigningKey,
    ) -> Result<Self, CryptoError> {
        let mut manifest = Self::sign_v4(
            controller_url,
            roots,
            relays,
            tls_relays,
            stun_servers,
            issued_at_unix_seconds,
            expires_at_unix_seconds,
            signing_key,
        )?;
        turn_servers
            .sort_by_key(|server| (server.priority, server.endpoint, server.transport as u8));
        validate_turn_servers(&turn_servers)?;
        let payload = PlanetManifestV5Payload {
            version: 5,
            controller_url: &manifest.controller_url,
            relay_endpoint: manifest.relay_endpoint,
            roots: &manifest.roots,
            relays: &manifest.relays,
            tls_relays: &manifest.tls_relays,
            turn_servers: &turn_servers,
            stun_servers: &manifest.stun_servers,
            issued_at_unix_seconds: manifest.issued_at_unix_seconds,
            expires_at_unix_seconds: manifest.expires_at_unix_seconds,
            controller_public_key: &manifest.controller_public_key,
        };
        let bytes =
            serde_json::to_vec(&payload).map_err(|_| CryptoError::CertificateEncodingFailed)?;
        manifest.version = 5;
        manifest.turn_servers = turn_servers;
        manifest.signature = signing_key.sign(&bytes).to_bytes().to_vec();
        Ok(manifest)
    }

    /// Validates both the signature and the out-of-band pinned controller key.
    /// A manifest downloaded from an arbitrary web server is never trusted just
    /// because it is self-consistent.
    pub fn verify_from_controller(
        &self,
        trusted_controller_public_key: &[u8],
        now_unix_seconds: u64,
    ) -> Result<(), CryptoError> {
        if !matches!(self.version, 1 | 2 | 3 | 4 | 5)
            || self.controller_public_key != trusted_controller_public_key
        {
            return Err(CryptoError::UntrustedController);
        }
        if self
            .expires_at_unix_seconds
            .is_some_and(|expiry| now_unix_seconds > expiry)
        {
            return Err(CryptoError::CertificateExpired);
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
        if self.version < 3
            && (self.roots.iter().any(|root| root.identity.is_some())
                || self.relays.iter().any(|relay| relay.identity.is_some()))
        {
            return Err(CryptoError::InvalidServiceIdentity);
        }
        if self.version >= 3 {
            if self.roots.iter().any(|root| root.identity.is_none())
                || self.relays.is_empty()
                || self.relays.iter().any(|relay| relay.identity.is_none())
            {
                return Err(CryptoError::InvalidServiceIdentity);
            }
            for root in &self.roots {
                let identity = root
                    .identity
                    .as_ref()
                    .ok_or(CryptoError::InvalidServiceIdentity)?;
                identity
                    .required_public_keys(now_unix_seconds)
                    .map_err(|_| CryptoError::InvalidServiceIdentity)?;
                if root.public_key != identity.current_public_key {
                    return Err(CryptoError::InvalidServiceIdentity);
                }
            }
            for relay in &self.relays {
                relay
                    .identity
                    .as_ref()
                    .ok_or(CryptoError::InvalidServiceIdentity)?
                    .required_public_keys(now_unix_seconds)
                    .map_err(|_| CryptoError::InvalidServiceIdentity)?;
            }
            if self.version >= 4 {
                validate_tls_relays(&self.tls_relays, &self.relays)?;
            } else if !self.tls_relays.is_empty() {
                return Err(CryptoError::InvalidCertificate);
            }
            if self.version == 5 {
                validate_turn_servers(&self.turn_servers)?;
            } else if !self.turn_servers.is_empty() {
                return Err(CryptoError::InvalidCertificate);
            }
        }
        let bytes = if self.version == 1 {
            serde_json::to_vec(&PlanetManifestPayload {
                version: self.version,
                controller_url: &self.controller_url,
                relay_endpoint: self.relay_endpoint,
                stun_servers: &self.stun_servers,
                issued_at_unix_seconds: self.issued_at_unix_seconds,
                expires_at_unix_seconds: self.expires_at_unix_seconds,
                controller_public_key: &self.controller_public_key,
            })
        } else if self.version == 2 {
            serde_json::to_vec(&PlanetManifestV2Payload {
                version: self.version,
                controller_url: &self.controller_url,
                relay_endpoint: self.relay_endpoint,
                roots: &self.roots,
                relays: &self.relays,
                stun_servers: &self.stun_servers,
                issued_at_unix_seconds: self.issued_at_unix_seconds,
                expires_at_unix_seconds: self.expires_at_unix_seconds,
                controller_public_key: &self.controller_public_key,
            })
        } else if self.version == 3 {
            serde_json::to_vec(&PlanetManifestV3Payload {
                version: self.version,
                controller_url: &self.controller_url,
                relay_endpoint: self.relay_endpoint,
                roots: &self.roots,
                relays: &self.relays,
                stun_servers: &self.stun_servers,
                issued_at_unix_seconds: self.issued_at_unix_seconds,
                expires_at_unix_seconds: self.expires_at_unix_seconds,
                controller_public_key: &self.controller_public_key,
            })
        } else if self.version == 4 {
            serde_json::to_vec(&PlanetManifestV4Payload {
                version: self.version,
                controller_url: &self.controller_url,
                relay_endpoint: self.relay_endpoint,
                roots: &self.roots,
                relays: &self.relays,
                tls_relays: &self.tls_relays,
                stun_servers: &self.stun_servers,
                issued_at_unix_seconds: self.issued_at_unix_seconds,
                expires_at_unix_seconds: self.expires_at_unix_seconds,
                controller_public_key: &self.controller_public_key,
            })
        } else {
            serde_json::to_vec(&PlanetManifestV5Payload {
                version: self.version,
                controller_url: &self.controller_url,
                relay_endpoint: self.relay_endpoint,
                roots: &self.roots,
                relays: &self.relays,
                tls_relays: &self.tls_relays,
                turn_servers: &self.turn_servers,
                stun_servers: &self.stun_servers,
                issued_at_unix_seconds: self.issued_at_unix_seconds,
                expires_at_unix_seconds: self.expires_at_unix_seconds,
                controller_public_key: &self.controller_public_key,
            })
        }
        .map_err(|_| CryptoError::CertificateEncodingFailed)?;
        let key =
            VerifyingKey::from_bytes(&public_key).map_err(|_| CryptoError::InvalidCertificate)?;
        key.verify(&bytes, &ed25519_dalek::Signature::from_bytes(&signature))
            .map_err(|_| CryptoError::InvalidCertificate)
    }
}

fn validate_tls_relays(
    tls_relays: &[PlanetTlsRelay],
    relays: &[PlanetRelay],
) -> Result<(), CryptoError> {
    let mut relay_ids = std::collections::BTreeSet::new();
    let mut endpoints = std::collections::BTreeSet::new();
    for relay in tls_relays {
        if relay.relay_id.is_nil()
            || relay.server_name.is_empty()
            || relay.server_name.len() > 253
            || relay
                .server_name
                .bytes()
                .any(|byte| byte.is_ascii_control())
            || relay.certificate_sha256.len() != 32
            || !relay_ids.insert(relay.relay_id)
            || !endpoints.insert(relay.endpoint)
            || !relays.iter().any(|udp_relay| {
                udp_relay
                    .identity
                    .as_ref()
                    .is_some_and(|identity| identity.service_id == relay.relay_id)
            })
        {
            return Err(CryptoError::InvalidCertificate);
        }
    }
    Ok(())
}

fn validate_turn_servers(turn_servers: &[PlanetTurnServer]) -> Result<(), CryptoError> {
    let mut endpoints = std::collections::BTreeSet::new();
    for server in turn_servers {
        if !is_public_unicast_endpoint(server.endpoint)
            || !endpoints.insert((server.endpoint, server.transport as u8))
        {
            return Err(CryptoError::InvalidCertificate);
        }
        match server.transport {
            TurnTransport::Udp | TurnTransport::Tcp => {
                if server.server_name.is_some() || !server.certificate_sha256.is_empty() {
                    return Err(CryptoError::InvalidCertificate);
                }
            }
            TurnTransport::Tls => {
                let Some(server_name) = server.server_name.as_deref() else {
                    return Err(CryptoError::InvalidCertificate);
                };
                if server_name.is_empty()
                    || server_name.len() > 253
                    || server_name
                        .bytes()
                        .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
                    || server.certificate_sha256.len() != 32
                {
                    return Err(CryptoError::InvalidCertificate);
                }
            }
        }
    }
    Ok(())
}

fn is_public_unicast_endpoint(endpoint: SocketAddr) -> bool {
    if endpoint.port() == 0 {
        return false;
    }
    match endpoint.ip() {
        IpAddr::V4(address) => {
            !address.is_unspecified()
                && !address.is_loopback()
                && !address.is_multicast()
                && !address.is_broadcast()
                && !address.is_private()
                && !address.is_link_local()
        }
        IpAddr::V6(address) => {
            !address.is_unspecified()
                && !address.is_loopback()
                && !address.is_multicast()
                && !address.is_unique_local()
                && !address.is_unicast_link_local()
        }
    }
}

impl MembershipCertificate {
    pub fn sign(claims: MembershipClaims, signing_key: &SigningKey) -> Result<Self, CryptoError> {
        Self::sign_authorized(claims, uuid::Uuid::new_v4(), 1, signing_key)
    }

    pub fn sign_authorized(
        claims: MembershipClaims,
        certificate_id: uuid::Uuid,
        network_key_epoch: u64,
        signing_key: &SigningKey,
    ) -> Result<Self, CryptoError> {
        let payload = MembershipCertificatePayload {
            version: 1,
            certificate_id,
            network_key_epoch,
            claims: &claims,
        };
        let bytes =
            serde_json::to_vec(&payload).map_err(|_| CryptoError::CertificateEncodingFailed)?;
        Ok(Self {
            version: 1,
            certificate_id,
            network_key_epoch,
            claims,
            controller_public_key: signing_key.verifying_key().to_bytes().to_vec(),
            signature: signing_key.sign(&bytes).to_bytes().to_vec(),
        })
    }

    pub fn verify(&self, now_unix_seconds: u64) -> Result<(), CryptoError> {
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
        if self
            .claims
            .expires_at_unix_seconds
            .is_some_and(|expiry| now_unix_seconds > expiry)
        {
            return Err(CryptoError::CertificateExpired);
        }
        let key =
            VerifyingKey::from_bytes(&public_key).map_err(|_| CryptoError::InvalidCertificate)?;
        let bytes = if self.version == 0 {
            serde_json::to_vec(&self.claims)
        } else if self.version == 1 && !self.certificate_id.is_nil() && self.network_key_epoch > 0 {
            serde_json::to_vec(&MembershipCertificatePayload {
                version: self.version,
                certificate_id: self.certificate_id,
                network_key_epoch: self.network_key_epoch,
                claims: &self.claims,
            })
        } else {
            return Err(CryptoError::InvalidCertificate);
        }
        .map_err(|_| CryptoError::CertificateEncodingFailed)?;
        key.verify(&bytes, &ed25519_dalek::Signature::from_bytes(&signature))
            .map_err(|_| CryptoError::InvalidCertificate)
    }

    /// Verifies both the signature and the controller trust anchor distributed out of band.
    /// A valid self-signed certificate is not sufficient for enrollment.
    pub fn verify_from_controller(
        &self,
        trusted_controller_public_key: &[u8],
        now_unix_seconds: u64,
    ) -> Result<(), CryptoError> {
        if self.controller_public_key != trusted_controller_public_key {
            return Err(CryptoError::UntrustedController);
        }
        self.verify(now_unix_seconds)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packet_round_trip_authenticates_outer_metadata() {
        let key = NetworkKey::from_bytes([7; 32]);
        let packet = key
            .seal(b"an IP packet", b"network-a:node-a:node-b")
            .unwrap();
        assert_eq!(
            key.open(&packet, b"network-a:node-a:node-b").unwrap(),
            b"an IP packet"
        );
        assert_eq!(
            key.open(&packet, b"network-a:node-a:node-c"),
            Err(CryptoError::AuthenticationFailed)
        );
    }

    #[test]
    fn membership_certificate_rejects_tampering() {
        let signing_key = SigningKey::from_bytes(&[9; 32]);
        let claims = MembershipClaims {
            network_id: NetworkId(uuid::Uuid::nil()),
            device_id: DeviceId(uuid::Uuid::nil()),
            device_public_key: vec![],
            assigned_addresses: vec!["100.64.1.2".parse().unwrap()],
            allowed_routes: vec!["100.64.1.0/24".into()],
            issued_at_unix_seconds: 1,
            expires_at_unix_seconds: Some(10),
        };
        let mut certificate = MembershipCertificate::sign(claims, &signing_key).unwrap();
        assert_eq!(certificate.verify(5), Ok(()));
        certificate.claims.allowed_routes.push("0.0.0.0/0".into());
        assert_eq!(certificate.verify(5), Err(CryptoError::InvalidCertificate));
    }

    #[test]
    fn membership_certificate_requires_the_pinned_controller_key() {
        let signing_key = SigningKey::from_bytes(&[8; 32]);
        let claims = MembershipClaims {
            network_id: NetworkId(uuid::Uuid::nil()),
            device_id: DeviceId(uuid::Uuid::nil()),
            device_public_key: vec![],
            assigned_addresses: vec![],
            allowed_routes: vec![],
            issued_at_unix_seconds: 1,
            expires_at_unix_seconds: None,
        };
        let certificate = MembershipCertificate::sign(claims, &signing_key).unwrap();
        assert_eq!(
            certificate.verify_from_controller(&[3; 32], 5),
            Err(CryptoError::UntrustedController)
        );
        assert_eq!(
            certificate.verify_from_controller(&signing_key.verifying_key().to_bytes(), 5),
            Ok(())
        );
    }

    #[test]
    fn planet_manifest_requires_the_pinned_controller_key() {
        let signing_key = SigningKey::from_bytes(&[3; 32]);
        let manifest = PlanetManifest::sign(
            "https://planet.example/v1".into(),
            "203.0.113.10:51820".parse().unwrap(),
            vec!["stun.example:3478".into()],
            10,
            None,
            &signing_key,
        )
        .unwrap();
        assert_eq!(
            manifest.verify_from_controller(&signing_key.verifying_key().to_bytes(), 11),
            Ok(())
        );
        assert_eq!(
            manifest.verify_from_controller(&[4; 32], 11),
            Err(CryptoError::UntrustedController)
        );
    }

    #[test]
    fn planet_v2_signs_roots_and_relay_order() {
        let signing_key = SigningKey::from_bytes(&[4; 32]);
        let manifest = PlanetManifest::sign_v2(
            "https://planet.example".into(),
            vec![PlanetRoot {
                public_key: vec![7; 32],
                endpoints: vec!["203.0.113.5:51819".parse().unwrap()],
                priority: 0,
                identity: None,
            }],
            vec![PlanetRelay {
                endpoint: "203.0.113.6:51820".parse().unwrap(),
                priority: 0,
                identity: None,
            }],
            vec!["stun.example:3478".into()],
            20,
            Some(120),
            &signing_key,
        )
        .unwrap();
        assert_eq!(manifest.version, 2);
        assert_eq!(manifest.roots.len(), 1);
        assert_eq!(
            manifest.verify_from_controller(&signing_key.verifying_key().to_bytes(), 30),
            Ok(())
        );
    }

    #[test]
    fn planet_v3_requires_explicit_service_identities() {
        let controller = SigningKey::from_bytes(&[5; 32]);
        let root = SigningKey::from_bytes(&[6; 32]);
        let relay = SigningKey::from_bytes(&[7; 32]);
        let manifest = PlanetManifest::sign_v3(
            "https://planet.example".into(),
            vec![PlanetRoot {
                public_key: root.verifying_key().to_bytes().to_vec(),
                endpoints: vec!["203.0.113.7:51819".parse().unwrap()],
                priority: 0,
                identity: Some(ServiceIdentityPolicy::stable(
                    uuid::Uuid::from_u128(8),
                    root.verifying_key().to_bytes().to_vec(),
                )),
            }],
            vec![PlanetRelay {
                endpoint: "203.0.113.8:51820".parse().unwrap(),
                priority: 0,
                identity: Some(ServiceIdentityPolicy::stable(
                    uuid::Uuid::from_u128(9),
                    relay.verifying_key().to_bytes().to_vec(),
                )),
            }],
            vec![],
            100,
            Some(200),
            &controller,
        )
        .unwrap();
        assert_eq!(
            manifest.verify_from_controller(&controller.verifying_key().to_bytes(), 150),
            Ok(())
        );

        let mut downgraded = manifest;
        downgraded.version = 2;
        assert_eq!(
            downgraded.verify_from_controller(&controller.verifying_key().to_bytes(), 150),
            Err(CryptoError::InvalidServiceIdentity)
        );
    }

    #[test]
    fn planet_v4_binds_tls_relay_to_a_signed_service_identity_and_certificate_pin() {
        let controller = SigningKey::from_bytes(&[15; 32]);
        let root = SigningKey::from_bytes(&[16; 32]);
        let relay = SigningKey::from_bytes(&[17; 32]);
        let relay_id = uuid::Uuid::from_u128(18);
        let manifest = PlanetManifest::sign_v4(
            "https://planet.example".into(),
            vec![PlanetRoot {
                public_key: root.verifying_key().to_bytes().to_vec(),
                endpoints: vec!["203.0.113.17:51819".parse().unwrap()],
                priority: 0,
                identity: Some(ServiceIdentityPolicy::stable(
                    uuid::Uuid::from_u128(19),
                    root.verifying_key().to_bytes().to_vec(),
                )),
            }],
            vec![PlanetRelay {
                endpoint: "203.0.113.18:51820".parse().unwrap(),
                priority: 0,
                identity: Some(ServiceIdentityPolicy::stable(
                    relay_id,
                    relay.verifying_key().to_bytes().to_vec(),
                )),
            }],
            vec![PlanetTlsRelay {
                relay_id,
                endpoint: "203.0.113.18:443".parse().unwrap(),
                server_name: "relay.example".into(),
                certificate_sha256: vec![20; 32],
                priority: 0,
            }],
            vec![],
            100,
            Some(200),
            &controller,
        )
        .unwrap();
        assert_eq!(manifest.version, 4);
        assert_eq!(
            manifest.verify_from_controller(&controller.verifying_key().to_bytes(), 150),
            Ok(())
        );
        let mut tampered = manifest;
        tampered.tls_relays[0].certificate_sha256[0] ^= 1;
        assert_eq!(
            tampered.verify_from_controller(&controller.verifying_key().to_bytes(), 150),
            Err(CryptoError::InvalidCertificate)
        );
    }

    #[test]
    fn planet_v5_signs_public_turn_endpoints_and_rejects_tampering() {
        let controller = SigningKey::from_bytes(&[21; 32]);
        let root = SigningKey::from_bytes(&[22; 32]);
        let relay = SigningKey::from_bytes(&[23; 32]);
        let relay_id = uuid::Uuid::from_u128(24);
        let manifest = PlanetManifest::sign_v5(
            "https://planet.example".into(),
            vec![PlanetRoot {
                public_key: root.verifying_key().to_bytes().to_vec(),
                endpoints: vec!["203.0.113.21:51819".parse().unwrap()],
                priority: 0,
                identity: Some(ServiceIdentityPolicy::stable(
                    uuid::Uuid::from_u128(25),
                    root.verifying_key().to_bytes().to_vec(),
                )),
            }],
            vec![PlanetRelay {
                endpoint: "203.0.113.22:51820".parse().unwrap(),
                priority: 0,
                identity: Some(ServiceIdentityPolicy::stable(
                    relay_id,
                    relay.verifying_key().to_bytes().to_vec(),
                )),
            }],
            vec![],
            vec![
                PlanetTurnServer {
                    endpoint: "203.0.113.23:3478".parse().unwrap(),
                    transport: TurnTransport::Udp,
                    server_name: None,
                    certificate_sha256: Vec::new(),
                    priority: 2,
                },
                PlanetTurnServer {
                    endpoint: "203.0.113.24:443".parse().unwrap(),
                    transport: TurnTransport::Tls,
                    server_name: Some("turn.example".into()),
                    certificate_sha256: vec![26; 32],
                    priority: 1,
                },
            ],
            vec![],
            100,
            Some(200),
            &controller,
        )
        .unwrap();
        assert_eq!(manifest.version, 5);
        assert_eq!(manifest.turn_servers[0].priority, 1);
        assert_eq!(
            manifest.verify_from_controller(&controller.verifying_key().to_bytes(), 150),
            Ok(())
        );
        let mut tampered = manifest;
        tampered.turn_servers[0].certificate_sha256[0] ^= 1;
        assert_eq!(
            tampered.verify_from_controller(&controller.verifying_key().to_bytes(), 150),
            Err(CryptoError::InvalidCertificate)
        );
    }
}
