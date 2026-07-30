//! Authenticated encrypted payload format transported by a MeshLake UDP relay.

use crate::{
    relay_associated_data, CryptoError, DeviceId, NetworkId, NetworkKey, RELAY_DATA,
    RELAY_DATA_HEADER_LEN, RELAY_MAGIC,
};
use uuid::Uuid;

const NONCE_LENGTH: usize = 24;

/// Encrypts one IPv4 or IPv6 packet and prefixes it with the relay routing header.
pub fn seal_relay_packet(
    key: &NetworkKey,
    network_id: NetworkId,
    source: DeviceId,
    destination: DeviceId,
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let header = relay_associated_data(network_id, source, destination);
    let sealed = key.seal(plaintext, &header)?;
    let mut packet =
        Vec::with_capacity(RELAY_DATA_HEADER_LEN + NONCE_LENGTH + sealed.ciphertext.len());
    packet.extend_from_slice(&header);
    packet.extend_from_slice(&sealed.nonce);
    packet.extend_from_slice(&sealed.ciphertext);
    Ok(packet)
}

/// Validates routing metadata and decrypts one relay packet.
pub fn open_relay_packet(
    key: &NetworkKey,
    packet: &[u8],
) -> Result<(NetworkId, DeviceId, DeviceId, Vec<u8>), CryptoError> {
    if packet.len() < RELAY_DATA_HEADER_LEN + NONCE_LENGTH
        || packet[..4] != RELAY_MAGIC
        || packet[4] != RELAY_DATA
    {
        return Err(CryptoError::InvalidOverlayPacket);
    }
    let network_id =
        NetworkId(Uuid::from_slice(&packet[5..21]).map_err(|_| CryptoError::InvalidOverlayPacket)?);
    let source =
        DeviceId(Uuid::from_slice(&packet[21..37]).map_err(|_| CryptoError::InvalidOverlayPacket)?);
    let destination =
        DeviceId(Uuid::from_slice(&packet[37..53]).map_err(|_| CryptoError::InvalidOverlayPacket)?);
    let nonce: [u8; NONCE_LENGTH] = packet
        [RELAY_DATA_HEADER_LEN..RELAY_DATA_HEADER_LEN + NONCE_LENGTH]
        .try_into()
        .map_err(|_| CryptoError::InvalidOverlayPacket)?;
    let ciphertext = packet[RELAY_DATA_HEADER_LEN + NONCE_LENGTH..].to_vec();
    let plaintext = key.open(
        &crate::SealedPacket { nonce, ciphertext },
        &packet[..RELAY_DATA_HEADER_LEN],
    )?;
    Ok((network_id, source, destination, plaintext))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_packet_round_trip_rejects_header_tampering() {
        let key = NetworkKey::from_bytes([5; 32]);
        let mut packet = seal_relay_packet(
            &key,
            NetworkId(Uuid::from_u128(1)),
            DeviceId(Uuid::from_u128(2)),
            DeviceId(Uuid::from_u128(3)),
            b"ip packet",
        )
        .unwrap();
        assert_eq!(open_relay_packet(&key, &packet).unwrap().3, b"ip packet");
        packet[40] ^= 1;
        assert_eq!(
            open_relay_packet(&key, &packet),
            Err(CryptoError::AuthenticationFailed)
        );
    }
}
