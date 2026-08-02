//! Platform-neutral types shared by the MeshLake agent, controller, relay and UI.

mod authorization;
mod crypto;
mod model;
mod overlay;
mod policy;
mod relay;
mod root;
mod secret_file;
mod service_identity;
mod session;
mod session_observation;
mod state_backup;
mod state_protection;

pub use authorization::{
    AuthorizationEpochHint, AuthorizedMembership, MembershipRefreshRequest,
    MembershipRefreshResponse, NetworkAuthorizationManifest, AUTHORIZATION_EPOCH_HINT_VERSION,
    AUTHORIZATION_MANIFEST_VERSION,
};
pub use crypto::{
    CryptoError, EnrollmentResponse, MembershipCertificate, MembershipClaims, NetworkKey,
    PlanetManifest, PlanetRelay, PlanetRoot, SealedPacket,
};
pub use model::{
    AgentStatus, DeviceId, EnrollmentRequest, JoinedNetwork, Membership, NetworkControlPlane,
    NetworkId, PeerPathStatus, RelayPolicy, TransportStatus, UpsertNetworkRequest, VirtualNetwork,
};
pub use overlay::{open_relay_packet, seal_relay_packet};
pub use policy::{
    DnsPolicy, NetworkPolicyManifest, PolicyError, PolicyRoute, NETWORK_POLICY_MANIFEST_VERSION,
};
pub use relay::{
    parse_peer_identity, peer_identity_announcement, relay_associated_data, RelayProtocolError,
    RelayReceiverEndpoint, RelayRegistrationAckPayload, SignedRelayRegistrationAck,
    RELAY_ACK_PROTOCOL_VERSION, RELAY_CANDIDATE, RELAY_DATA, RELAY_DATA_HEADER_LEN, RELAY_MAGIC,
    RELAY_MAX_ASSIGNED_ADDRESSES, RELAY_PEER, RELAY_PEER_IDENTITY, RELAY_PUNCH, RELAY_PUNCH_ACK,
    RELAY_REGISTER, RELAY_REGISTER_ACK, RELAY_REGISTER_ACK_SIGNED, RELAY_REGISTER_SIGNED,
    RELAY_SESSION_DATA, RELAY_SESSION_INIT, RELAY_SESSION_RESPONSE,
};
pub use root::{
    RootPeer, RootProtocolError, RootRegistration, RootRegistrationPayload, RootResponse,
    SignedRootResponse,
};
pub use secret_file::{
    create_restricted_secret_file, read_restricted_secret_file, read_restricted_secret_string_file,
    verify_restricted_secret_file, SecretFileError,
};
pub use service_identity::{
    load_or_create_service_identity, ServiceIdentityError, ServiceIdentityFileError,
    ServiceIdentityPolicy, ServiceSignature, ServiceSigningIdentity,
};
pub use session::{
    accept_pairwise_handshake, parse_session_routing_header, session_handshake_id,
    InitiatorHandshake, PairwiseSessionKeys, ReplayWindow, SessionPacket, SESSION_DATA_HEADER_LEN,
    SESSION_PROTOCOL_VERSION,
};
pub use session_observation::{
    SessionList, SessionObservation, SessionPath, SessionQueueCounters, SessionSecurityCounters,
    SessionState, SESSION_API_SCHEMA_VERSION,
};
pub use state_backup::{
    decode_state_backup, encode_state_backup, resolve_state_backup_path, write_state_backup_file,
    StateBackupError, StateBackupKind,
};
pub use state_protection::{
    cleanup_stale_state_backup, decode_protected_state, decode_protected_state_with,
    encode_protected_state, encode_protected_state_with, recover_protected_state_file,
    restrict_state_file_permissions, write_protected_state_file, write_protected_state_file_with,
    DecodedState, StateFileError, StateFileLock, StateKeyProvider, StateProtection,
    StateProtectionError, StateProtectionLevel, AGENT_STATE_PROTECTION_PURPOSE,
    CONTROLLER_STATE_PROTECTION_PURPOSE,
};
