//! TLS-framed transport for a controller-pinned MeshLake Relay.
//!
//! This module validates the exact DER leaf-certificate hash carried in a
//! verified Planet V4 manifest. It never consults platform root stores.

use anyhow::{anyhow, bail, Context, Result};
use meshlake_core::PlanetTlsRelay;
use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::{ring, CryptoProvider},
    pki_types::{CertificateDer, ServerName, UnixTime},
    DigitallySignedStruct, Error as RustlsError, SignatureScheme,
};
use std::{
    collections::HashMap,
    fmt,
    net::SocketAddr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
    sync::{mpsc, watch},
};
use tokio_rustls::TlsConnector;

const MAX_TCP_FRAME_BYTES: usize = u16::MAX as usize;
const OUTBOUND_QUEUE_CAPACITY: usize = 256;
const RECONNECT_DELAY: Duration = Duration::from_secs(2);

/// Associates a public TLS listener with the already-authorized UDP Relay
/// endpoint. The latter remains the service identity used by Relay frames.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TlsRelayRoute {
    pub(crate) relay: PlanetTlsRelay,
    pub(crate) relay_endpoint: SocketAddr,
}

#[derive(Debug)]
pub(crate) struct TlsRelayInbound {
    pub(crate) relay_endpoint: SocketAddr,
    pub(crate) packet: Vec<u8>,
}

#[derive(Default)]
pub(crate) struct TlsRelayTelemetry {
    configured: std::sync::atomic::AtomicU64,
    connected: std::sync::atomic::AtomicU64,
    connection_failures: std::sync::atomic::AtomicU64,
    frames_sent: std::sync::atomic::AtomicU64,
    frames_received: std::sync::atomic::AtomicU64,
    queue_drops: std::sync::atomic::AtomicU64,
}

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct TlsRelayTelemetrySnapshot {
    pub(crate) configured: u64,
    pub(crate) connected: u64,
    pub(crate) connection_failures: u64,
    pub(crate) frames_sent: u64,
    pub(crate) frames_received: u64,
    pub(crate) queue_drops: u64,
}

impl TlsRelayTelemetry {
    pub(crate) fn reset(&self, configured: usize) {
        use std::sync::atomic::Ordering;
        self.configured.store(configured as u64, Ordering::Relaxed);
        self.connected.store(0, Ordering::Relaxed);
        self.connection_failures.store(0, Ordering::Relaxed);
        self.frames_sent.store(0, Ordering::Relaxed);
        self.frames_received.store(0, Ordering::Relaxed);
        self.queue_drops.store(0, Ordering::Relaxed);
    }

    pub(crate) fn snapshot(&self) -> TlsRelayTelemetrySnapshot {
        use std::sync::atomic::Ordering;
        TlsRelayTelemetrySnapshot {
            configured: self.configured.load(Ordering::Relaxed),
            connected: self.connected.load(Ordering::Relaxed),
            connection_failures: self.connection_failures.load(Ordering::Relaxed),
            frames_sent: self.frames_sent.load(Ordering::Relaxed),
            frames_received: self.frames_received.load(Ordering::Relaxed),
            queue_drops: self.queue_drops.load(Ordering::Relaxed),
        }
    }
}

#[derive(Clone)]
struct OutboundRelay {
    sender: mpsc::Sender<Vec<u8>>,
    connected: Arc<AtomicBool>,
}

/// One bounded, reconnecting TLS stream per configured Relay. A full queue or
/// disconnected stream is a transport failure, never a successful send.
pub(crate) struct TlsRelayTransport {
    relays: HashMap<SocketAddr, OutboundRelay>,
    incoming: mpsc::Receiver<TlsRelayInbound>,
    shutdown: watch::Sender<bool>,
    telemetry: Arc<TlsRelayTelemetry>,
}

impl TlsRelayTransport {
    pub(crate) fn start(
        routes: Vec<TlsRelayRoute>,
        telemetry: Arc<TlsRelayTelemetry>,
    ) -> Result<Self> {
        let provider = Arc::new(ring::default_provider());
        let (incoming_tx, incoming) = mpsc::channel(OUTBOUND_QUEUE_CAPACITY);
        let (shutdown, shutdown_rx) = watch::channel(false);
        let mut relays = HashMap::new();

        telemetry.reset(routes.len());
        for route in routes {
            if relays.contains_key(&route.relay_endpoint) {
                continue;
            }
            let (sender, receiver) = mpsc::channel(OUTBOUND_QUEUE_CAPACITY);
            let connected = Arc::new(AtomicBool::new(false));
            tokio::spawn(run_relay_connection(
                route.clone(),
                receiver,
                incoming_tx.clone(),
                connected.clone(),
                shutdown_rx.clone(),
                provider.clone(),
                telemetry.clone(),
            ));
            relays.insert(route.relay_endpoint, OutboundRelay { sender, connected });
        }
        Ok(Self {
            relays,
            incoming,
            shutdown,
            telemetry,
        })
    }

    pub(crate) fn try_send(&self, relay_endpoint: SocketAddr, packet: &[u8]) -> bool {
        if packet.is_empty() || packet.len() > MAX_TCP_FRAME_BYTES {
            return false;
        }
        let Some(relay) = self.relays.get(&relay_endpoint) else {
            return false;
        };
        if !relay.connected.load(Ordering::Acquire) {
            self.telemetry.queue_drops.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        if relay.sender.try_send(packet.to_vec()).is_err() {
            self.telemetry.queue_drops.fetch_add(1, Ordering::Relaxed);
            return false;
        }
        true
    }

    pub(crate) async fn receive(&mut self) -> Option<TlsRelayInbound> {
        self.incoming.recv().await
    }
}

impl Drop for TlsRelayTransport {
    fn drop(&mut self) {
        let _ = self.shutdown.send(true);
    }
}

async fn run_relay_connection(
    route: TlsRelayRoute,
    mut outbound: mpsc::Receiver<Vec<u8>>,
    incoming: mpsc::Sender<TlsRelayInbound>,
    connected: Arc<AtomicBool>,
    mut shutdown: watch::Receiver<bool>,
    provider: Arc<CryptoProvider>,
    telemetry: Arc<TlsRelayTelemetry>,
) {
    loop {
        if *shutdown.borrow() {
            return;
        }
        let result = connect_and_forward(
            &route,
            &mut outbound,
            &incoming,
            &connected,
            &mut shutdown,
            provider.clone(),
            telemetry.clone(),
        )
        .await;
        if connected.swap(false, Ordering::AcqRel) {
            telemetry.connected.fetch_sub(1, Ordering::Relaxed);
        }
        if *shutdown.borrow() || outbound.is_closed() {
            return;
        }
        if let Err(error) = result {
            telemetry
                .connection_failures
                .fetch_add(1, Ordering::Relaxed);
            trace_tls_relay(format!(
                "pinned TLS relay connection changed state: {error:#}"
            ));
        }
        tokio::select! {
            _ = tokio::time::sleep(RECONNECT_DELAY) => {}
            result = shutdown.changed() => {
                if result.is_err() || *shutdown.borrow() { return; }
            }
        }
    }
}

async fn connect_and_forward(
    route: &TlsRelayRoute,
    outbound: &mut mpsc::Receiver<Vec<u8>>,
    incoming: &mpsc::Sender<TlsRelayInbound>,
    connected: &AtomicBool,
    shutdown: &mut watch::Receiver<bool>,
    provider: Arc<CryptoProvider>,
    telemetry: Arc<TlsRelayTelemetry>,
) -> Result<()> {
    let stream = connect_pinned_tls(
        route.relay.endpoint,
        &route.relay.server_name,
        &route.relay.certificate_sha256,
        provider,
    )
    .await?;
    if !connected.swap(true, Ordering::AcqRel) {
        telemetry.connected.fetch_add(1, Ordering::Relaxed);
    }
    let (mut reader, mut writer) = tokio::io::split(stream);
    let mut read_buffer = vec![0_u8; MAX_TCP_FRAME_BYTES];
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() { return Ok(()); }
            }
            outbound_packet = outbound.recv() => {
                let Some(packet) = outbound_packet else { return Ok(()); };
                write_tcp_frame(&mut writer, &packet).await?;
                telemetry.frames_sent.fetch_add(1, Ordering::Relaxed);
            }
            packet = read_tcp_frame(&mut reader, &mut read_buffer) => {
                let Some(packet) = packet? else { return Ok(()); };
                if incoming.send(TlsRelayInbound {
                    relay_endpoint: route.relay_endpoint,
                    packet: packet.to_vec(),
                }).await.is_err() {
                    return Ok(());
                }
                telemetry.frames_received.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

/// Opens one TLS stream using an exact controller-signed leaf-certificate
/// fingerprint. This is shared by MeshLake's custom TLS Relay and standard
/// TURN-over-TLS transport; neither path consults the platform trust store.
pub(crate) async fn connect_pinned_tls(
    endpoint: SocketAddr,
    server_name: &str,
    certificate_sha256: &[u8],
    provider: Arc<CryptoProvider>,
) -> Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let server_name = ServerName::try_from(server_name.to_owned())
        .map_err(|_| anyhow!("controller-signed TLS server name is invalid"))?;
    let verifier = Arc::new(PinnedCertificateVerifier {
        certificate_sha256: certificate_sha256.to_vec(),
    });
    let config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));
    let stream = TcpStream::connect(endpoint)
        .await
        .context("cannot establish controller-pinned TLS TCP connection")?;
    connector
        .connect(server_name, stream)
        .await
        .context("TLS leaf certificate pin verification failed")
}

async fn read_tcp_frame<'a>(
    reader: &mut (impl AsyncRead + Unpin),
    buffer: &'a mut Vec<u8>,
) -> Result<Option<&'a [u8]>> {
    let mut length = [0_u8; 4];
    match reader.read_exact(&mut length).await {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error.into()),
    }
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > MAX_TCP_FRAME_BYTES {
        bail!("TLS relay frame length is outside the accepted range");
    }
    buffer.resize(length, 0);
    reader.read_exact(buffer).await?;
    Ok(Some(buffer.as_slice()))
}

async fn write_tcp_frame(writer: &mut (impl AsyncWrite + Unpin), frame: &[u8]) -> Result<()> {
    if frame.is_empty() || frame.len() > MAX_TCP_FRAME_BYTES {
        bail!("TLS relay frame length is outside the accepted range");
    }
    writer
        .write_all(&(frame.len() as u32).to_be_bytes())
        .await?;
    writer.write_all(frame).await?;
    writer.flush().await?;
    Ok(())
}

#[derive(Debug)]
struct PinnedCertificateVerifier {
    certificate_sha256: Vec<u8>,
}

impl ServerCertVerifier for PinnedCertificateVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, RustlsError> {
        verify_leaf_certificate_pin_bytes(&self.certificate_sha256, end_entity.as_ref())
            .map_err(|_| RustlsError::General("TLS relay leaf certificate pin mismatch".into()))?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, RustlsError> {
        verify_handshake_signature(message, cert, dss, false)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, RustlsError> {
        verify_handshake_signature(message, cert, dss, true)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        supported_verify_schemes()
    }
}

fn verify_handshake_signature(
    message: &[u8],
    cert: &CertificateDer<'_>,
    dss: &DigitallySignedStruct,
    tls13: bool,
) -> std::result::Result<HandshakeSignatureValid, RustlsError> {
    if tls13
        && !matches!(
            dss.scheme,
            SignatureScheme::ECDSA_NISTP384_SHA384
                | SignatureScheme::ECDSA_NISTP256_SHA256
                | SignatureScheme::ED25519
                | SignatureScheme::RSA_PSS_SHA512
                | SignatureScheme::RSA_PSS_SHA384
                | SignatureScheme::RSA_PSS_SHA256
        )
    {
        return Err(RustlsError::PeerMisbehaved(
            rustls::PeerMisbehaved::SignedHandshakeWithUnadvertisedSigScheme,
        ));
    }
    let certificate = webpki::EndEntityCert::try_from(cert)
        .map_err(|_| RustlsError::General("TLS relay certificate encoding is invalid".into()))?;
    let algorithms = signature_algorithms(dss.scheme)
        .ok_or_else(|| RustlsError::General("TLS relay signature scheme is unsupported".into()))?;
    for algorithm in algorithms {
        if certificate
            .verify_signature(*algorithm, message, dss.signature())
            .is_ok()
        {
            return Ok(HandshakeSignatureValid::assertion());
        }
    }
    Err(RustlsError::General(
        "TLS relay handshake signature is invalid".into(),
    ))
}

fn signature_algorithms(
    scheme: SignatureScheme,
) -> Option<&'static [&'static dyn rustls::pki_types::SignatureVerificationAlgorithm]> {
    match scheme {
        SignatureScheme::ECDSA_NISTP384_SHA384 => Some(ECDSA_NISTP384_SHA384_ALGORITHMS),
        SignatureScheme::ECDSA_NISTP256_SHA256 => Some(ECDSA_NISTP256_SHA256_ALGORITHMS),
        SignatureScheme::ED25519 => Some(ED25519_ALGORITHMS),
        SignatureScheme::RSA_PSS_SHA512 => Some(RSA_PSS_SHA512_ALGORITHMS),
        SignatureScheme::RSA_PSS_SHA384 => Some(RSA_PSS_SHA384_ALGORITHMS),
        SignatureScheme::RSA_PSS_SHA256 => Some(RSA_PSS_SHA256_ALGORITHMS),
        SignatureScheme::RSA_PKCS1_SHA512 => Some(RSA_PKCS1_SHA512_ALGORITHMS),
        SignatureScheme::RSA_PKCS1_SHA384 => Some(RSA_PKCS1_SHA384_ALGORITHMS),
        SignatureScheme::RSA_PKCS1_SHA256 => Some(RSA_PKCS1_SHA256_ALGORITHMS),
        _ => None,
    }
}

use webpki::ring as webpki_algorithms;

static ECDSA_NISTP384_SHA384_ALGORITHMS:
    &[&dyn rustls::pki_types::SignatureVerificationAlgorithm] = &[
    webpki_algorithms::ECDSA_P384_SHA384,
    webpki_algorithms::ECDSA_P256_SHA384,
];
static ECDSA_NISTP256_SHA256_ALGORITHMS:
    &[&dyn rustls::pki_types::SignatureVerificationAlgorithm] = &[
    webpki_algorithms::ECDSA_P256_SHA256,
    webpki_algorithms::ECDSA_P384_SHA256,
];
static ED25519_ALGORITHMS: &[&dyn rustls::pki_types::SignatureVerificationAlgorithm] =
    &[webpki_algorithms::ED25519];
static RSA_PSS_SHA512_ALGORITHMS: &[&dyn rustls::pki_types::SignatureVerificationAlgorithm] =
    &[webpki_algorithms::RSA_PSS_2048_8192_SHA512_LEGACY_KEY];
static RSA_PSS_SHA384_ALGORITHMS: &[&dyn rustls::pki_types::SignatureVerificationAlgorithm] =
    &[webpki_algorithms::RSA_PSS_2048_8192_SHA384_LEGACY_KEY];
static RSA_PSS_SHA256_ALGORITHMS: &[&dyn rustls::pki_types::SignatureVerificationAlgorithm] =
    &[webpki_algorithms::RSA_PSS_2048_8192_SHA256_LEGACY_KEY];
static RSA_PKCS1_SHA512_ALGORITHMS: &[&dyn rustls::pki_types::SignatureVerificationAlgorithm] =
    &[webpki_algorithms::RSA_PKCS1_2048_8192_SHA512];
static RSA_PKCS1_SHA384_ALGORITHMS: &[&dyn rustls::pki_types::SignatureVerificationAlgorithm] =
    &[webpki_algorithms::RSA_PKCS1_2048_8192_SHA384];
static RSA_PKCS1_SHA256_ALGORITHMS: &[&dyn rustls::pki_types::SignatureVerificationAlgorithm] =
    &[webpki_algorithms::RSA_PKCS1_2048_8192_SHA256];

fn supported_verify_schemes() -> Vec<SignatureScheme> {
    vec![
        SignatureScheme::ECDSA_NISTP384_SHA384,
        SignatureScheme::ECDSA_NISTP256_SHA256,
        SignatureScheme::ED25519,
        SignatureScheme::RSA_PSS_SHA512,
        SignatureScheme::RSA_PSS_SHA384,
        SignatureScheme::RSA_PSS_SHA256,
        SignatureScheme::RSA_PKCS1_SHA512,
        SignatureScheme::RSA_PKCS1_SHA384,
        SignatureScheme::RSA_PKCS1_SHA256,
    ]
}

#[cfg(test)]
pub(crate) fn verify_leaf_certificate_pin(
    relay: &PlanetTlsRelay,
    certificate_der: &[u8],
) -> Result<()> {
    verify_leaf_certificate_pin_bytes(&relay.certificate_sha256, certificate_der)
}

fn verify_leaf_certificate_pin_bytes(
    certificate_sha256: &[u8],
    certificate_der: &[u8],
) -> Result<()> {
    use sha2::{Digest, Sha256};
    if certificate_der.is_empty() || certificate_sha256.len() != 32 {
        bail!("TLS Relay certificate pin is invalid");
    }
    let actual = Sha256::digest(certificate_der);
    if actual.as_slice() != certificate_sha256 {
        bail!("TLS Relay leaf certificate does not match the controller-signed pin");
    }
    Ok(())
}

fn trace_tls_relay(message: impl fmt::Display) {
    if std::env::var_os("MESHLAKE_TRACE").is_some() {
        eprintln!("[meshlake tls relay] {message}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{generate_simple_self_signed, CertifiedKey};
    use sha2::{Digest, Sha256};
    use tokio::{net::TcpListener, time::timeout};
    use tokio_rustls::TlsAcceptor;
    use uuid::Uuid;

    fn relay(pin: Vec<u8>) -> PlanetTlsRelay {
        PlanetTlsRelay {
            relay_id: Uuid::from_u128(1),
            endpoint: "198.51.100.1:443".parse().unwrap(),
            server_name: "relay.example".into(),
            certificate_sha256: pin,
            priority: 0,
        }
    }

    #[test]
    fn accepts_only_the_exact_signed_leaf_certificate() {
        let certificate = b"test certificate DER";
        let relay = relay(Sha256::digest(certificate).to_vec());
        assert!(verify_leaf_certificate_pin(&relay, certificate).is_ok());
        assert!(verify_leaf_certificate_pin(&relay, b"other certificate").is_err());
    }

    #[test]
    fn rejects_an_invalid_pin_length_before_tls_validation() {
        assert!(verify_leaf_certificate_pin(&relay(vec![0; 31]), b"certificate").is_err());
    }

    #[tokio::test]
    async fn pinned_tls_transport_forwards_only_framed_ciphertext() {
        let CertifiedKey { cert, signing_key } =
            generate_simple_self_signed(vec!["relay.test".into()]).unwrap();
        let server = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_address = server.local_addr().unwrap();
        let private_key =
            rustls::pki_types::PrivateKeyDer::Pkcs8(signing_key.serialize_der().into());
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert.der().clone()], private_key)
        .unwrap();
        let relay_task = tokio::spawn(async move {
            let (stream, _) = server.accept().await.unwrap();
            let stream = TlsAcceptor::from(Arc::new(config))
                .accept(stream)
                .await
                .unwrap();
            let (mut reader, mut writer) = tokio::io::split(stream);
            let mut buffer = Vec::new();
            let frame = read_tcp_frame(&mut reader, &mut buffer)
                .await
                .unwrap()
                .unwrap();
            write_tcp_frame(&mut writer, frame).await.unwrap();
        });
        let logical_endpoint: SocketAddr = "127.0.0.1:51999".parse().unwrap();
        let relay = PlanetTlsRelay {
            relay_id: Uuid::from_u128(7),
            endpoint: server_address,
            server_name: "relay.test".into(),
            certificate_sha256: Sha256::digest(cert.der().as_ref()).to_vec(),
            priority: 0,
        };
        let telemetry = Arc::new(TlsRelayTelemetry::default());
        let mut transport = TlsRelayTransport::start(
            vec![TlsRelayRoute {
                relay,
                relay_endpoint: logical_endpoint,
            }],
            telemetry.clone(),
        )
        .unwrap();
        timeout(Duration::from_secs(2), async {
            while telemetry.snapshot().connected != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("pinned TLS transport did not connect");
        let encrypted_frame = vec![0x4d, 0x4c, 0x52, 0x31, 12, 7, 8, 9];
        assert!(transport.try_send(logical_endpoint, &encrypted_frame));
        let inbound = timeout(Duration::from_secs(2), transport.receive())
            .await
            .expect("pinned TLS transport did not return a frame")
            .unwrap();
        assert_eq!(inbound.relay_endpoint, logical_endpoint);
        assert_eq!(inbound.packet, encrypted_frame);
        assert_eq!(telemetry.snapshot().frames_sent, 1);
        assert_eq!(telemetry.snapshot().frames_received, 1);
        relay_task.await.unwrap();
    }
}
