//! Authenticated ephemeral pairwise sessions for MeshLake members.
//!
//! Device Ed25519 identities authenticate an ephemeral X25519 exchange. HKDF
//! mixes the resulting shared secret with the controller-distributed network
//! key, producing independent keys for each traffic direction. Data packets
//! use a monotonically increasing sequence and a 64-packet replay window.

use crate::{
    CryptoError, DeviceId, NetworkId, NetworkKey, RELAY_DATA_HEADER_LEN, RELAY_MAGIC,
    RELAY_SESSION_DATA, RELAY_SESSION_INIT, RELAY_SESSION_RESPONSE,
};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

pub const SESSION_PROTOCOL_VERSION: u8 = 1;
pub const SESSION_DATA_HEADER_LEN: usize = RELAY_DATA_HEADER_LEN + 16 + 8;

const INIT_SIGNATURE_DOMAIN: &[u8] = b"MeshLake session init v1\0";
const RESPONSE_SIGNATURE_DOMAIN: &[u8] = b"MeshLake session response v1\0";
const KDF_DOMAIN: &[u8] = b"MeshLake pairwise traffic keys v1\0";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SessionInitPayload {
    version: u8,
    network_id: NetworkId,
    initiator: DeviceId,
    responder: DeviceId,
    session_id: [u8; 16],
    initiator_ephemeral_public_key: [u8; 32],
    issued_at_unix_seconds: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SessionInit {
    payload: SessionInitPayload,
    signature: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SessionResponsePayload {
    version: u8,
    network_id: NetworkId,
    initiator: DeviceId,
    responder: DeviceId,
    session_id: [u8; 16],
    initiator_ephemeral_public_key: [u8; 32],
    responder_ephemeral_public_key: [u8; 32],
    issued_at_unix_seconds: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SessionResponse {
    payload: SessionResponsePayload,
    signature: Vec<u8>,
}

/// Initiator-only state containing the ephemeral X25519 secret until a valid
/// response is received. It must never be persisted or logged.
pub struct InitiatorHandshake {
    init: SessionInit,
    secret: StaticSecret,
}

impl std::fmt::Debug for InitiatorHandshake {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("InitiatorHandshake")
            .field("network_id", &self.init.payload.network_id)
            .field("initiator", &self.init.payload.initiator)
            .field("responder", &self.init.payload.responder)
            .field("session_id", &self.init.payload.session_id)
            .field("secret", &"[redacted]")
            .finish()
    }
}

impl InitiatorHandshake {
    pub fn start(
        network_id: NetworkId,
        initiator: DeviceId,
        responder: DeviceId,
        identity: &SigningKey,
        issued_at_unix_seconds: u64,
    ) -> Result<(Self, Vec<u8>), CryptoError> {
        let session_id = random_bytes()?;
        let secret = StaticSecret::from(random_bytes()?);
        let ephemeral_public_key = PublicKey::from(&secret).to_bytes();
        let payload = SessionInitPayload {
            version: SESSION_PROTOCOL_VERSION,
            network_id,
            initiator,
            responder,
            session_id,
            initiator_ephemeral_public_key: ephemeral_public_key,
            issued_at_unix_seconds,
        };
        let signature = sign_payload(INIT_SIGNATURE_DOMAIN, &payload, identity)?;
        let init = SessionInit { payload, signature };
        let packet =
            encode_routed_json(RELAY_SESSION_INIT, network_id, initiator, responder, &init)?;
        Ok((Self { init, secret }, packet))
    }

    pub fn session_id(&self) -> [u8; 16] {
        self.init.payload.session_id
    }

    pub fn complete(
        &self,
        response_packet: &[u8],
        expected_responder_public_key: &[u8],
        network_key: &NetworkKey,
        now_unix_seconds: u64,
        maximum_clock_skew_seconds: u64,
    ) -> Result<PairwiseSessionKeys, CryptoError> {
        let response: SessionResponse = parse_routed_json(
            response_packet,
            RELAY_SESSION_RESPONSE,
            self.init.payload.network_id,
            self.init.payload.responder,
            self.init.payload.initiator,
        )?;
        verify_fresh(
            response.payload.version,
            response.payload.issued_at_unix_seconds,
            now_unix_seconds,
            maximum_clock_skew_seconds,
        )?;
        if response.payload.network_id != self.init.payload.network_id
            || response.payload.initiator != self.init.payload.initiator
            || response.payload.responder != self.init.payload.responder
            || response.payload.session_id != self.init.payload.session_id
            || response.payload.initiator_ephemeral_public_key
                != self.init.payload.initiator_ephemeral_public_key
        {
            return Err(CryptoError::SessionIdentityMismatch);
        }
        verify_payload(
            RESPONSE_SIGNATURE_DOMAIN,
            &response.payload,
            &response.signature,
            expected_responder_public_key,
        )?;
        let remote_public = PublicKey::from(response.payload.responder_ephemeral_public_key);
        let shared = self.secret.diffie_hellman(&remote_public);
        derive_session_keys(network_key, &response.payload, shared.as_bytes(), true)
    }
}

#[derive(Clone)]
pub struct PairwiseSessionKeys {
    session_id: [u8; 16],
    send_key: [u8; 32],
    receive_key: [u8; 32],
}

impl std::fmt::Debug for PairwiseSessionKeys {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PairwiseSessionKeys")
            .field("session_id", &self.session_id)
            .field("send_key", &"[redacted]")
            .field("receive_key", &"[redacted]")
            .finish()
    }
}

impl PairwiseSessionKeys {
    pub fn session_id(&self) -> [u8; 16] {
        self.session_id
    }

    pub fn seal(
        &self,
        network_id: NetworkId,
        source: DeviceId,
        destination: DeviceId,
        sequence: u64,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let header =
            session_data_header(network_id, source, destination, self.session_id, sequence);
        let cipher = XChaCha20Poly1305::new((&self.send_key).into());
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&session_nonce(self.session_id, sequence)),
                Payload {
                    msg: plaintext,
                    aad: &header,
                },
            )
            .map_err(|_| CryptoError::EncryptionFailed)?;
        let mut packet = Vec::with_capacity(SESSION_DATA_HEADER_LEN + ciphertext.len());
        packet.extend_from_slice(&header);
        packet.extend_from_slice(&ciphertext);
        Ok(packet)
    }

    pub fn open(
        &self,
        replay_window: &mut ReplayWindow,
        packet: &[u8],
    ) -> Result<SessionPacket, CryptoError> {
        let (network_id, source, destination, session_id, sequence) =
            parse_session_data_header(packet)?;
        if session_id != self.session_id || !replay_window.can_accept(sequence) {
            return Err(CryptoError::SessionReplayDetected);
        }
        let cipher = XChaCha20Poly1305::new((&self.receive_key).into());
        let plaintext = cipher
            .decrypt(
                XNonce::from_slice(&session_nonce(session_id, sequence)),
                Payload {
                    msg: &packet[SESSION_DATA_HEADER_LEN..],
                    aad: &packet[..SESSION_DATA_HEADER_LEN],
                },
            )
            .map_err(|_| CryptoError::AuthenticationFailed)?;
        replay_window.mark(sequence);
        Ok(SessionPacket {
            network_id,
            source,
            destination,
            session_id,
            sequence,
            plaintext,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionPacket {
    pub network_id: NetworkId,
    pub source: DeviceId,
    pub destination: DeviceId,
    pub session_id: [u8; 16],
    pub sequence: u64,
    pub plaintext: Vec<u8>,
}

#[derive(Debug, Default, Clone)]
pub struct ReplayWindow {
    highest: Option<u64>,
    bitmap: u64,
}

impl ReplayWindow {
    fn can_accept(&self, sequence: u64) -> bool {
        let Some(highest) = self.highest else {
            return true;
        };
        if sequence > highest {
            return true;
        }
        let distance = highest - sequence;
        distance < 64 && self.bitmap & (1_u64 << distance) == 0
    }

    fn mark(&mut self, sequence: u64) {
        let Some(highest) = self.highest else {
            self.highest = Some(sequence);
            self.bitmap = 1;
            return;
        };
        if sequence > highest {
            let distance = sequence - highest;
            self.bitmap = if distance >= 64 {
                1
            } else {
                (self.bitmap << distance) | 1
            };
            self.highest = Some(sequence);
            return;
        }
        self.bitmap |= 1_u64 << (highest - sequence);
    }
}

pub fn accept_pairwise_handshake(
    init_packet: &[u8],
    expected_initiator_public_key: &[u8],
    responder_identity: &SigningKey,
    network_key: &NetworkKey,
    now_unix_seconds: u64,
    maximum_clock_skew_seconds: u64,
) -> Result<(PairwiseSessionKeys, Vec<u8>), CryptoError> {
    let (network_id, initiator, responder) =
        parse_session_routing_header(init_packet, RELAY_SESSION_INIT)?;
    let init: SessionInit = parse_routed_json(
        init_packet,
        RELAY_SESSION_INIT,
        network_id,
        initiator,
        responder,
    )?;
    if init.payload.network_id != network_id
        || init.payload.initiator != initiator
        || init.payload.responder != responder
    {
        return Err(CryptoError::SessionIdentityMismatch);
    }
    verify_fresh(
        init.payload.version,
        init.payload.issued_at_unix_seconds,
        now_unix_seconds,
        maximum_clock_skew_seconds,
    )?;
    verify_payload(
        INIT_SIGNATURE_DOMAIN,
        &init.payload,
        &init.signature,
        expected_initiator_public_key,
    )?;

    let responder_secret = StaticSecret::from(random_bytes()?);
    let responder_public = PublicKey::from(&responder_secret).to_bytes();
    let response_payload = SessionResponsePayload {
        version: SESSION_PROTOCOL_VERSION,
        network_id,
        initiator,
        responder,
        session_id: init.payload.session_id,
        initiator_ephemeral_public_key: init.payload.initiator_ephemeral_public_key,
        responder_ephemeral_public_key: responder_public,
        issued_at_unix_seconds: now_unix_seconds,
    };
    let response = SessionResponse {
        signature: sign_payload(
            RESPONSE_SIGNATURE_DOMAIN,
            &response_payload,
            responder_identity,
        )?,
        payload: response_payload.clone(),
    };
    let remote_public = PublicKey::from(init.payload.initiator_ephemeral_public_key);
    let shared = responder_secret.diffie_hellman(&remote_public);
    let keys = derive_session_keys(network_key, &response_payload, shared.as_bytes(), false)?;
    let packet = encode_routed_json(
        RELAY_SESSION_RESPONSE,
        network_id,
        responder,
        initiator,
        &response,
    )?;
    Ok((keys, packet))
}

pub fn parse_session_routing_header(
    packet: &[u8],
    expected_kind: u8,
) -> Result<(NetworkId, DeviceId, DeviceId), CryptoError> {
    if packet.len() < RELAY_DATA_HEADER_LEN
        || packet[..4] != RELAY_MAGIC
        || packet[4] != expected_kind
    {
        return Err(CryptoError::InvalidSessionPacket);
    }
    Ok((
        NetworkId(
            uuid::Uuid::from_slice(&packet[5..21])
                .map_err(|_| CryptoError::InvalidSessionPacket)?,
        ),
        DeviceId(
            uuid::Uuid::from_slice(&packet[21..37])
                .map_err(|_| CryptoError::InvalidSessionPacket)?,
        ),
        DeviceId(
            uuid::Uuid::from_slice(&packet[37..53])
                .map_err(|_| CryptoError::InvalidSessionPacket)?,
        ),
    ))
}

pub fn session_handshake_id(packet: &[u8], expected_kind: u8) -> Result<[u8; 16], CryptoError> {
    let (network_id, source, destination) = parse_session_routing_header(packet, expected_kind)?;
    match expected_kind {
        RELAY_SESSION_INIT => {
            let init: SessionInit =
                parse_routed_json(packet, expected_kind, network_id, source, destination)?;
            if init.payload.network_id != network_id
                || init.payload.initiator != source
                || init.payload.responder != destination
            {
                return Err(CryptoError::SessionIdentityMismatch);
            }
            Ok(init.payload.session_id)
        }
        RELAY_SESSION_RESPONSE => {
            let response: SessionResponse =
                parse_routed_json(packet, expected_kind, network_id, source, destination)?;
            if response.payload.network_id != network_id
                || response.payload.responder != source
                || response.payload.initiator != destination
            {
                return Err(CryptoError::SessionIdentityMismatch);
            }
            Ok(response.payload.session_id)
        }
        _ => Err(CryptoError::InvalidSessionPacket),
    }
}

fn parse_session_data_header(
    packet: &[u8],
) -> Result<(NetworkId, DeviceId, DeviceId, [u8; 16], u64), CryptoError> {
    if packet.len() < SESSION_DATA_HEADER_LEN + 16 {
        return Err(CryptoError::InvalidSessionPacket);
    }
    let (network_id, source, destination) =
        parse_session_routing_header(packet, RELAY_SESSION_DATA)?;
    let session_id = packet[53..69]
        .try_into()
        .map_err(|_| CryptoError::InvalidSessionPacket)?;
    let sequence = u64::from_be_bytes(
        packet[69..77]
            .try_into()
            .map_err(|_| CryptoError::InvalidSessionPacket)?,
    );
    Ok((network_id, source, destination, session_id, sequence))
}

fn derive_session_keys(
    network_key: &NetworkKey,
    response: &SessionResponsePayload,
    shared_secret: &[u8; 32],
    local_is_initiator: bool,
) -> Result<PairwiseSessionKeys, CryptoError> {
    if shared_secret == &[0_u8; 32] {
        return Err(CryptoError::InvalidSessionKey);
    }
    let mut info = Vec::with_capacity(KDF_DOMAIN.len() + 16 * 4 + 64);
    info.extend_from_slice(KDF_DOMAIN);
    info.extend_from_slice(response.network_id.0.as_bytes());
    info.extend_from_slice(response.initiator.0.as_bytes());
    info.extend_from_slice(response.responder.0.as_bytes());
    info.extend_from_slice(&response.session_id);
    info.extend_from_slice(&response.initiator_ephemeral_public_key);
    info.extend_from_slice(&response.responder_ephemeral_public_key);
    let salt = network_key.to_bytes();
    let hkdf = Hkdf::<Sha256>::new(Some(&salt), shared_secret);
    let mut output = [0_u8; 64];
    hkdf.expand(&info, &mut output)
        .map_err(|_| CryptoError::InvalidSessionKey)?;
    let initiator_to_responder: [u8; 32] = output[..32]
        .try_into()
        .map_err(|_| CryptoError::InvalidSessionKey)?;
    let responder_to_initiator: [u8; 32] = output[32..]
        .try_into()
        .map_err(|_| CryptoError::InvalidSessionKey)?;
    let (send_key, receive_key) = if local_is_initiator {
        (initiator_to_responder, responder_to_initiator)
    } else {
        (responder_to_initiator, initiator_to_responder)
    };
    Ok(PairwiseSessionKeys {
        session_id: response.session_id,
        send_key,
        receive_key,
    })
}

fn encode_routed_json(
    kind: u8,
    network_id: NetworkId,
    source: DeviceId,
    destination: DeviceId,
    value: &impl Serialize,
) -> Result<Vec<u8>, CryptoError> {
    let encoded = serde_json::to_vec(value).map_err(|_| CryptoError::InvalidSessionPacket)?;
    let mut packet = Vec::with_capacity(RELAY_DATA_HEADER_LEN + encoded.len());
    packet.extend_from_slice(&routing_header(kind, network_id, source, destination));
    packet.extend_from_slice(&encoded);
    Ok(packet)
}

fn parse_routed_json<T: for<'de> Deserialize<'de>>(
    packet: &[u8],
    kind: u8,
    network_id: NetworkId,
    source: DeviceId,
    destination: DeviceId,
) -> Result<T, CryptoError> {
    if parse_session_routing_header(packet, kind)? != (network_id, source, destination) {
        return Err(CryptoError::SessionIdentityMismatch);
    }
    serde_json::from_slice(&packet[RELAY_DATA_HEADER_LEN..])
        .map_err(|_| CryptoError::InvalidSessionPacket)
}

fn routing_header(
    kind: u8,
    network_id: NetworkId,
    source: DeviceId,
    destination: DeviceId,
) -> [u8; RELAY_DATA_HEADER_LEN] {
    let mut header = [0_u8; RELAY_DATA_HEADER_LEN];
    header[..4].copy_from_slice(&RELAY_MAGIC);
    header[4] = kind;
    header[5..21].copy_from_slice(network_id.0.as_bytes());
    header[21..37].copy_from_slice(source.0.as_bytes());
    header[37..53].copy_from_slice(destination.0.as_bytes());
    header
}

fn session_data_header(
    network_id: NetworkId,
    source: DeviceId,
    destination: DeviceId,
    session_id: [u8; 16],
    sequence: u64,
) -> [u8; SESSION_DATA_HEADER_LEN] {
    let mut header = [0_u8; SESSION_DATA_HEADER_LEN];
    header[..RELAY_DATA_HEADER_LEN].copy_from_slice(&routing_header(
        RELAY_SESSION_DATA,
        network_id,
        source,
        destination,
    ));
    header[53..69].copy_from_slice(&session_id);
    header[69..77].copy_from_slice(&sequence.to_be_bytes());
    header
}

fn session_nonce(session_id: [u8; 16], sequence: u64) -> [u8; 24] {
    let mut nonce = [0_u8; 24];
    nonce[..16].copy_from_slice(&session_id);
    nonce[16..].copy_from_slice(&sequence.to_be_bytes());
    nonce
}

fn sign_payload(
    domain: &[u8],
    payload: &impl Serialize,
    identity: &SigningKey,
) -> Result<Vec<u8>, CryptoError> {
    let message = signature_message(domain, payload)?;
    Ok(identity.sign(&message).to_bytes().to_vec())
}

fn verify_payload(
    domain: &[u8],
    payload: &impl Serialize,
    signature: &[u8],
    public_key: &[u8],
) -> Result<(), CryptoError> {
    let public_key: [u8; 32] = public_key
        .try_into()
        .map_err(|_| CryptoError::InvalidIdentityKey)?;
    let signature: [u8; 64] = signature
        .try_into()
        .map_err(|_| CryptoError::InvalidSessionSignature)?;
    let message = signature_message(domain, payload)?;
    VerifyingKey::from_bytes(&public_key)
        .map_err(|_| CryptoError::InvalidIdentityKey)?
        .verify(&message, &ed25519_dalek::Signature::from_bytes(&signature))
        .map_err(|_| CryptoError::InvalidSessionSignature)
}

fn signature_message(domain: &[u8], payload: &impl Serialize) -> Result<Vec<u8>, CryptoError> {
    let encoded = serde_json::to_vec(payload).map_err(|_| CryptoError::InvalidSessionPacket)?;
    let mut message = Vec::with_capacity(domain.len() + encoded.len());
    message.extend_from_slice(domain);
    message.extend_from_slice(&encoded);
    Ok(message)
}

fn verify_fresh(
    version: u8,
    issued_at_unix_seconds: u64,
    now_unix_seconds: u64,
    maximum_clock_skew_seconds: u64,
) -> Result<(), CryptoError> {
    if version != SESSION_PROTOCOL_VERSION {
        return Err(CryptoError::InvalidSessionPacket);
    }
    if now_unix_seconds.abs_diff(issued_at_unix_seconds) > maximum_clock_skew_seconds {
        return Err(CryptoError::StaleSessionHandshake);
    }
    Ok(())
}

fn random_bytes<const N: usize>() -> Result<[u8; N], CryptoError> {
    let mut bytes = [0_u8; N];
    getrandom::fill(&mut bytes).map_err(|_| CryptoError::RandomnessUnavailable)?;
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn signed_x25519_handshake_derives_directional_keys() {
        let initiator_identity = SigningKey::from_bytes(&[1_u8; 32]);
        let responder_identity = SigningKey::from_bytes(&[2_u8; 32]);
        let network = NetworkId(Uuid::from_u128(1));
        let initiator = DeviceId(Uuid::from_u128(2));
        let responder = DeviceId(Uuid::from_u128(3));
        let network_key = NetworkKey::from_bytes([4_u8; 32]);
        let (pending, init_packet) =
            InitiatorHandshake::start(network, initiator, responder, &initiator_identity, 100)
                .unwrap();
        let (responder_keys, response_packet) = accept_pairwise_handshake(
            &init_packet,
            &initiator_identity.verifying_key().to_bytes(),
            &responder_identity,
            &network_key,
            100,
            120,
        )
        .unwrap();
        let initiator_keys = pending
            .complete(
                &response_packet,
                &responder_identity.verifying_key().to_bytes(),
                &network_key,
                100,
                120,
            )
            .unwrap();

        let packet = initiator_keys
            .seal(network, initiator, responder, 0, b"pairwise packet")
            .unwrap();
        let opened = responder_keys
            .open(&mut ReplayWindow::default(), &packet)
            .unwrap();
        assert_eq!(opened.plaintext, b"pairwise packet");
        assert_eq!(opened.source, initiator);
        assert_eq!(opened.destination, responder);
    }

    #[test]
    fn handshake_rejects_identity_tampering() {
        let initiator_identity = SigningKey::from_bytes(&[5_u8; 32]);
        let responder_identity = SigningKey::from_bytes(&[6_u8; 32]);
        let attacker = SigningKey::from_bytes(&[7_u8; 32]);
        let network = NetworkId(Uuid::from_u128(8));
        let initiator = DeviceId(Uuid::from_u128(9));
        let responder = DeviceId(Uuid::from_u128(10));
        let (_, init_packet) =
            InitiatorHandshake::start(network, initiator, responder, &initiator_identity, 200)
                .unwrap();
        assert_eq!(
            accept_pairwise_handshake(
                &init_packet,
                &attacker.verifying_key().to_bytes(),
                &responder_identity,
                &NetworkKey::from_bytes([8_u8; 32]),
                200,
                120,
            )
            .unwrap_err(),
            CryptoError::InvalidSessionSignature
        );
    }

    #[test]
    fn authenticated_sequence_window_rejects_replays_and_old_packets() {
        let initiator_identity = SigningKey::from_bytes(&[9_u8; 32]);
        let responder_identity = SigningKey::from_bytes(&[10_u8; 32]);
        let network = NetworkId(Uuid::from_u128(11));
        let initiator = DeviceId(Uuid::from_u128(12));
        let responder = DeviceId(Uuid::from_u128(13));
        let network_key = NetworkKey::from_bytes([11_u8; 32]);
        let (pending, init_packet) =
            InitiatorHandshake::start(network, initiator, responder, &initiator_identity, 300)
                .unwrap();
        let (responder_keys, response_packet) = accept_pairwise_handshake(
            &init_packet,
            &initiator_identity.verifying_key().to_bytes(),
            &responder_identity,
            &network_key,
            300,
            120,
        )
        .unwrap();
        let initiator_keys = pending
            .complete(
                &response_packet,
                &responder_identity.verifying_key().to_bytes(),
                &network_key,
                300,
                120,
            )
            .unwrap();
        let packet_zero = initiator_keys
            .seal(network, initiator, responder, 0, b"zero")
            .unwrap();
        let packet_sixty_four = initiator_keys
            .seal(network, initiator, responder, 64, b"sixty-four")
            .unwrap();
        let mut replay = ReplayWindow::default();
        responder_keys.open(&mut replay, &packet_zero).unwrap();
        assert_eq!(
            responder_keys.open(&mut replay, &packet_zero),
            Err(CryptoError::SessionReplayDetected)
        );
        responder_keys
            .open(&mut replay, &packet_sixty_four)
            .unwrap();
        assert_eq!(
            responder_keys.open(&mut replay, &packet_zero),
            Err(CryptoError::SessionReplayDetected)
        );
    }
}
