//! Platform-neutral types shared by the MeshLake agent, controller, relay and UI.

mod authorization;
mod crypto;
mod model;
mod overlay;
mod relay;
mod root;
mod session;

pub use authorization::{
    AuthorizedMembership, MembershipRefreshRequest, MembershipRefreshResponse,
    NetworkAuthorizationManifest, AUTHORIZATION_MANIFEST_VERSION,
};
pub use crypto::{
    CryptoError, EnrollmentResponse, MembershipCertificate, MembershipClaims, NetworkKey,
    PlanetManifest, PlanetRelay, PlanetRoot, SealedPacket,
};
pub use model::{
    AgentStatus, DeviceId, EnrollmentRequest, JoinedNetwork, Membership, NetworkId, PeerPathStatus,
    RelayPolicy, TransportStatus, UpsertNetworkRequest, VirtualNetwork,
};
pub use overlay::{open_relay_packet, seal_relay_packet};
pub use relay::{
    parse_peer_identity, peer_identity_announcement, relay_associated_data, RELAY_CANDIDATE,
    RELAY_DATA, RELAY_DATA_HEADER_LEN, RELAY_MAGIC, RELAY_MAX_ASSIGNED_ADDRESSES, RELAY_PEER,
    RELAY_PEER_IDENTITY, RELAY_PUNCH, RELAY_PUNCH_ACK, RELAY_REGISTER, RELAY_REGISTER_ACK,
    RELAY_REGISTER_SIGNED, RELAY_SESSION_DATA, RELAY_SESSION_INIT, RELAY_SESSION_RESPONSE,
};
pub use root::{
    RootPeer, RootProtocolError, RootRegistration, RootRegistrationPayload, RootResponse,
    SignedRootResponse,
};
pub use session::{
    accept_pairwise_handshake, parse_session_routing_header, session_handshake_id,
    InitiatorHandshake, PairwiseSessionKeys, ReplayWindow, SessionPacket, SESSION_DATA_HEADER_LEN,
    SESSION_PROTOCOL_VERSION,
};
