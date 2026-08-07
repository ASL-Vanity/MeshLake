//! Certificate-pin validation for Planet V4 TLS Relay endpoints.

use anyhow::{bail, Result};
use meshlake_core::PlanetTlsRelay;
use sha2::{Digest, Sha256};

pub(crate) fn verify_leaf_certificate_pin(
    relay: &PlanetTlsRelay,
    certificate_der: &[u8],
) -> Result<()> {
    if certificate_der.is_empty() || relay.certificate_sha256.len() != 32 {
        bail!("TLS Relay certificate pin is invalid");
    }
    let actual = Sha256::digest(certificate_der);
    if actual.as_slice() != relay.certificate_sha256.as_slice() {
        bail!("TLS Relay leaf certificate does not match the controller-signed pin");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use meshlake_core::PlanetTlsRelay;
    use uuid::Uuid;

    #[test]
    fn accepts_only_the_exact_signed_leaf_certificate() {
        let certificate = b"test certificate DER";
        let relay = PlanetTlsRelay {
            relay_id: Uuid::from_u128(1),
            endpoint: "198.51.100.1:443".parse().unwrap(),
            server_name: "relay.example".into(),
            certificate_sha256: Sha256::digest(certificate).to_vec(),
            priority: 0,
        };
        assert!(verify_leaf_certificate_pin(&relay, certificate).is_ok());
        assert!(verify_leaf_certificate_pin(&relay, b"other certificate").is_err());
    }
}
