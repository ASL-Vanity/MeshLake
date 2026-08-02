//! Pure IP packet classification shared by the platform adapters and transport loop.

use ipnet::{Ipv4Net, Ipv6Net};
use meshlake_core::JoinedNetwork;

/// Selects exactly one virtual network for an outbound IP packet.
///
/// The packet source must be one of the addresses assigned to this device on
/// the selected network. This prevents overlapping virtual prefixes from
/// selecting whichever network happens to appear first in persisted state.
/// Ambiguous assignments fail closed.
pub(crate) fn network_for_ip_packet<'a>(
    networks: &'a [JoinedNetwork],
    packet: &[u8],
) -> Option<&'a JoinedNetwork> {
    let (source, destination) = packet_addresses(packet)?;
    let mut matches = networks.iter().filter(|network| {
        network.network_key.len() == 32
            && network.assigned_addresses.contains(&source)
            && (address_belongs_to_network(network, destination)
                || is_group_destination(network, destination))
    });
    let selected = matches.next()?;
    matches.next().is_none().then_some(selected)
}

pub(crate) fn packet_addresses(packet: &[u8]) -> Option<(std::net::IpAddr, std::net::IpAddr)> {
    match packet.first().map(|byte| byte >> 4) {
        Some(4) if packet.len() >= 20 => Some((
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                packet[12], packet[13], packet[14], packet[15],
            )),
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                packet[16], packet[17], packet[18], packet[19],
            )),
        )),
        Some(6) if packet.len() >= 40 => Some((
            std::net::IpAddr::V6(std::net::Ipv6Addr::from(
                <[u8; 16]>::try_from(&packet[8..24]).ok()?,
            )),
            std::net::IpAddr::V6(std::net::Ipv6Addr::from(
                <[u8; 16]>::try_from(&packet[24..40]).ok()?,
            )),
        )),
        _ => None,
    }
}

pub(crate) fn address_belongs_to_network(
    network: &JoinedNetwork,
    address: std::net::IpAddr,
) -> bool {
    match address {
        std::net::IpAddr::V4(address) => network
            .network
            .ipv4_prefix
            .parse::<Ipv4Net>()
            .is_ok_and(|prefix| prefix.contains(&address)),
        std::net::IpAddr::V6(address) => network
            .network
            .ipv6_prefix
            .as_deref()
            .and_then(|prefix| prefix.parse::<Ipv6Net>().ok())
            .is_some_and(|prefix| prefix.contains(&address)),
    }
}

pub(crate) fn is_group_destination(network: &JoinedNetwork, destination: std::net::IpAddr) -> bool {
    match destination {
        std::net::IpAddr::V4(destination) => {
            destination == std::net::Ipv4Addr::BROADCAST
                || destination.is_multicast()
                || network
                    .network
                    .ipv4_prefix
                    .parse::<Ipv4Net>()
                    .is_ok_and(|prefix| destination == prefix.broadcast())
        }
        std::net::IpAddr::V6(destination) => destination.is_multicast(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use meshlake_core::{NetworkControlPlane, NetworkId, RelayPolicy, VirtualNetwork};
    use uuid::Uuid;

    fn network(id: u128, assigned: &[&str]) -> JoinedNetwork {
        JoinedNetwork {
            network: VirtualNetwork {
                id: NetworkId(Uuid::from_u128(id)),
                name: format!("network-{id}"),
                ipv4_prefix: "100.64.0.0/24".into(),
                ipv6_prefix: Some("fd42:4d4c::/64".into()),
                relay_policy: RelayPolicy::Preferred,
            },
            assigned_addresses: assigned
                .iter()
                .map(|address| address.parse().unwrap())
                .collect(),
            certificate: None,
            network_key: vec![id as u8; 32],
            control_plane: NetworkControlPlane::default(),
        }
    }

    fn ipv4_packet(source: [u8; 4], destination: [u8; 4]) -> Vec<u8> {
        let mut packet = vec![0_u8; 20];
        packet[0] = 0x45;
        packet[12..16].copy_from_slice(&source);
        packet[16..20].copy_from_slice(&destination);
        packet
    }

    fn ipv6_packet(source: &str, destination: &str) -> Vec<u8> {
        let mut packet = vec![0_u8; 40];
        packet[0] = 0x60;
        packet[8..24].copy_from_slice(&source.parse::<std::net::Ipv6Addr>().unwrap().octets());
        packet[24..40]
            .copy_from_slice(&destination.parse::<std::net::Ipv6Addr>().unwrap().octets());
        packet
    }

    #[test]
    fn packet_addresses_rejects_truncated_or_unknown_packets() {
        assert!(packet_addresses(&[]).is_none());
        assert!(packet_addresses(&[0x45; 19]).is_none());
        assert!(packet_addresses(&[0x60; 39]).is_none());
        assert!(packet_addresses(&[0x70; 40]).is_none());
    }

    #[test]
    fn overlapping_prefixes_are_selected_by_the_assigned_source() {
        let first = network(1, &["100.64.0.1"]);
        let second = network(2, &["100.64.0.2"]);
        let networks = [first, second];
        let packet = ipv4_packet([100, 64, 0, 2], [100, 64, 0, 99]);
        assert_eq!(
            network_for_ip_packet(&networks, &packet).map(|network| network.network.id),
            Some(NetworkId(Uuid::from_u128(2)))
        );
    }

    #[test]
    fn ambiguous_or_spoofed_sources_fail_closed() {
        let first = network(1, &["100.64.0.1"]);
        let second = network(2, &["100.64.0.1"]);
        let packet = ipv4_packet([100, 64, 0, 1], [100, 64, 0, 99]);
        assert!(network_for_ip_packet(&[first, second], &packet).is_none());

        let only = network(3, &["100.64.0.3"]);
        let spoofed = ipv4_packet([100, 64, 0, 77], [100, 64, 0, 99]);
        assert!(network_for_ip_packet(&[only], &spoofed).is_none());
    }

    #[test]
    fn group_traffic_uses_the_unique_assigned_source_network() {
        let first = network(1, &["fd42:4d4c::1"]);
        let second = network(2, &["fd42:4d4c::2"]);
        let networks = [first, second];
        let packet = ipv6_packet("fd42:4d4c::2", "ff02::1");
        assert_eq!(
            network_for_ip_packet(&networks, &packet).map(|network| network.network.id),
            Some(NetworkId(Uuid::from_u128(2)))
        );
    }
}
