//! Best-effort UPnP IGD UDP mapping.  Failure is deliberately non-fatal:
//! MeshLake still uses UDP hole punching and relay fallback when a gateway does
//! not expose UPnP.

use igd_next::{search_gateway, PortMappingProtocol, SearchOptions};
use std::{net::SocketAddr, time::Duration};

pub struct Mapping {
    gateway: igd_next::Gateway,
    local: SocketAddr,
    external_port: u16,
}

impl Mapping {
    pub fn establish(local: SocketAddr) -> Result<(Self, SocketAddr), String> {
        if !local.is_ipv4() {
            return Err("UPnP IGD currently maps IPv4 UDP endpoints only".into());
        }
        let options = SearchOptions {
            timeout: Some(Duration::from_secs(3)),
            single_search_timeout: Some(Duration::from_secs(1)),
            ..Default::default()
        };
        let gateway = search_gateway(options).map_err(|error| error.to_string())?;
        // Request the same external port as the UDP socket. This lets the
        // relay-observed endpoint and the UPnP mapping describe one path.
        gateway
            .add_port(
                PortMappingProtocol::UDP,
                local.port(),
                local,
                1_800,
                "MeshLake UDP",
            )
            .map_err(|error| error.to_string())?;
        let external_ip = gateway
            .get_external_ip()
            .map_err(|error| error.to_string())?;
        Ok((
            Self {
                gateway,
                local,
                external_port: local.port(),
            },
            SocketAddr::new(external_ip, local.port()),
        ))
    }

    pub fn renew(&mut self) -> Result<SocketAddr, String> {
        self.gateway
            .add_port(
                PortMappingProtocol::UDP,
                self.external_port,
                self.local,
                1_800,
                "MeshLake UDP",
            )
            .map_err(|error| error.to_string())?;
        let external_ip = self
            .gateway
            .get_external_ip()
            .map_err(|error| error.to_string())?;
        Ok(SocketAddr::new(external_ip, self.external_port))
    }
}

impl Drop for Mapping {
    fn drop(&mut self) {
        let _ = self
            .gateway
            .remove_port(PortMappingProtocol::UDP, self.external_port);
    }
}

/// Gets the local IPv4 address selected by the OS for the coordinator route.
pub fn route_local_address(remote: SocketAddr, port: u16) -> Result<SocketAddr, String> {
    let socket = std::net::UdpSocket::bind("0.0.0.0:0").map_err(|error| error.to_string())?;
    socket.connect(remote).map_err(|error| error.to_string())?;
    let address = socket.local_addr().map_err(|error| error.to_string())?;
    Ok(SocketAddr::new(address.ip(), port))
}
