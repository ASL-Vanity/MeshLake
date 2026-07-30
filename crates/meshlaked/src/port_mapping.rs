//! Best-effort automatic UDP port mapping.
//!
//! PCP is preferred, NAT-PMP is the compatibility fallback, and UPnP IGD is
//! retained for consumer routers that implement neither standardized gateway
//! protocol. Failure is non-fatal because STUN, UDP punching and encrypted
//! relay transport remain available.

use crate::upnp;
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket},
    process::Command,
    time::Duration,
};

const GATEWAY_PORT: u16 = 5351;
const MAPPING_LIFETIME_SECONDS: u32 = 7_200;

pub enum Mapping {
    Pcp(PcpMapping),
    NatPmp(NatPmpMapping),
    Upnp(upnp::Mapping),
}

impl Mapping {
    pub fn establish(remote: SocketAddr, internal_port: u16) -> Result<(Self, SocketAddr), String> {
        let local = upnp::route_local_address(remote, internal_port)?;
        let mut errors = Vec::new();
        if let Some(gateway) = default_ipv4_gateway() {
            match PcpMapping::establish(local, gateway) {
                Ok((mapping, external)) => return Ok((Self::Pcp(mapping), external)),
                Err(error) => errors.push(format!("PCP: {error}")),
            }
            match NatPmpMapping::establish(local, gateway) {
                Ok((mapping, external)) => return Ok((Self::NatPmp(mapping), external)),
                Err(error) => errors.push(format!("NAT-PMP: {error}")),
            }
        } else {
            errors.push("PCP/NAT-PMP: default IPv4 gateway was not found".into());
        }
        match upnp::Mapping::establish(local) {
            Ok((mapping, external)) => Ok((Self::Upnp(mapping), external)),
            Err(error) => {
                errors.push(format!("UPnP: {error}"));
                Err(errors.join("; "))
            }
        }
    }

    pub fn protocol_name(&self) -> &'static str {
        match self {
            Self::Pcp(mapping) => {
                let _ = mapping;
                "PCP"
            }
            Self::NatPmp(mapping) => {
                let _ = mapping;
                "NAT-PMP"
            }
            Self::Upnp(mapping) => {
                let _ = mapping;
                "UPnP"
            }
        }
    }

    pub fn renew(&mut self) -> Result<SocketAddr, String> {
        match self {
            Self::Pcp(mapping) => mapping.renew(),
            Self::NatPmp(mapping) => mapping.renew(),
            Self::Upnp(mapping) => mapping.renew(),
        }
    }
}

pub struct NatPmpMapping {
    gateway: Ipv4Addr,
    local_ip: Ipv4Addr,
    external_ip: Ipv4Addr,
    internal_port: u16,
    external_port: u16,
}

impl NatPmpMapping {
    fn establish(local: SocketAddr, gateway: Ipv4Addr) -> Result<(Self, SocketAddr), String> {
        let local_ip = match local.ip() {
            IpAddr::V4(ip) => ip,
            IpAddr::V6(_) => return Err("NAT-PMP supports IPv4 mappings only".into()),
        };
        let socket = gateway_socket(local_ip, gateway)?;
        socket
            .send(&[0, 0])
            .map_err(|error| format!("cannot request public address: {error}"))?;
        let mut response = [0_u8; 32];
        let size = socket
            .recv(&mut response)
            .map_err(|error| format!("public-address response failed: {error}"))?;
        let external_ip = parse_nat_pmp_public_address(&response[..size])?;

        let request = nat_pmp_map_request(local.port(), local.port(), MAPPING_LIFETIME_SECONDS);
        socket
            .send(&request)
            .map_err(|error| format!("cannot request UDP mapping: {error}"))?;
        let size = socket
            .recv(&mut response)
            .map_err(|error| format!("UDP mapping response failed: {error}"))?;
        let external_port = parse_nat_pmp_map_response(&response[..size], local.port())?;
        Ok((
            Self {
                gateway,
                local_ip,
                external_ip,
                internal_port: local.port(),
                external_port,
            },
            SocketAddr::new(IpAddr::V4(external_ip), external_port),
        ))
    }

    fn renew(&mut self) -> Result<SocketAddr, String> {
        let socket = gateway_socket(self.local_ip, self.gateway)?;
        let request = nat_pmp_map_request(
            self.internal_port,
            self.external_port,
            MAPPING_LIFETIME_SECONDS,
        );
        socket
            .send(&request)
            .map_err(|error| format!("cannot renew UDP mapping: {error}"))?;
        let mut response = [0_u8; 32];
        let size = socket
            .recv(&mut response)
            .map_err(|error| format!("UDP renewal response failed: {error}"))?;
        self.external_port = parse_nat_pmp_map_response(&response[..size], self.internal_port)?;
        Ok(SocketAddr::new(
            IpAddr::V4(self.external_ip),
            self.external_port,
        ))
    }
}

impl Drop for NatPmpMapping {
    fn drop(&mut self) {
        if let Ok(socket) = gateway_socket(Ipv4Addr::UNSPECIFIED, self.gateway) {
            let _ = socket.send(&nat_pmp_map_request(
                self.internal_port,
                self.external_port,
                0,
            ));
        }
    }
}

pub struct PcpMapping {
    gateway: Ipv4Addr,
    local_ip: Ipv4Addr,
    internal_port: u16,
    external_port: u16,
    nonce: [u8; 12],
}

impl PcpMapping {
    fn establish(local: SocketAddr, gateway: Ipv4Addr) -> Result<(Self, SocketAddr), String> {
        let local_ip = match local.ip() {
            IpAddr::V4(ip) => ip,
            IpAddr::V6(_) => return Err("PCP IPv6 mapping is not implemented yet".into()),
        };
        let mut nonce = [0_u8; 12];
        getrandom::fill(&mut nonce)
            .map_err(|error| format!("cannot generate PCP nonce: {error:?}"))?;
        let request = pcp_map_request(
            local_ip,
            local.port(),
            local.port(),
            MAPPING_LIFETIME_SECONDS,
            nonce,
        );
        let socket = gateway_socket(local_ip, gateway)?;
        socket
            .send(&request)
            .map_err(|error| format!("cannot request UDP mapping: {error}"))?;
        let mut response = [0_u8; 128];
        let size = socket
            .recv(&mut response)
            .map_err(|error| format!("UDP mapping response failed: {error}"))?;
        let (external_ip, external_port) =
            parse_pcp_map_response(&response[..size], local.port(), nonce)?;
        Ok((
            Self {
                gateway,
                local_ip,
                internal_port: local.port(),
                external_port,
                nonce,
            },
            SocketAddr::new(external_ip, external_port),
        ))
    }

    fn renew(&mut self) -> Result<SocketAddr, String> {
        let request = pcp_map_request(
            self.local_ip,
            self.internal_port,
            self.external_port,
            MAPPING_LIFETIME_SECONDS,
            self.nonce,
        );
        let socket = gateway_socket(self.local_ip, self.gateway)?;
        socket
            .send(&request)
            .map_err(|error| format!("cannot renew UDP mapping: {error}"))?;
        let mut response = [0_u8; 128];
        let size = socket
            .recv(&mut response)
            .map_err(|error| format!("UDP renewal response failed: {error}"))?;
        let (external_ip, external_port) =
            parse_pcp_map_response(&response[..size], self.internal_port, self.nonce)?;
        self.external_port = external_port;
        Ok(SocketAddr::new(external_ip, external_port))
    }
}

impl Drop for PcpMapping {
    fn drop(&mut self) {
        if let Ok(socket) = gateway_socket(self.local_ip, self.gateway) {
            let _ = socket.send(&pcp_map_request(
                self.local_ip,
                self.internal_port,
                self.external_port,
                0,
                self.nonce,
            ));
        }
    }
}

fn gateway_socket(local_ip: Ipv4Addr, gateway: Ipv4Addr) -> Result<UdpSocket, String> {
    let bind_ip = if local_ip.is_unspecified() {
        Ipv4Addr::UNSPECIFIED
    } else {
        local_ip
    };
    let socket = UdpSocket::bind((bind_ip, 0)).map_err(|error| error.to_string())?;
    socket
        .set_read_timeout(Some(Duration::from_millis(900)))
        .map_err(|error| error.to_string())?;
    socket
        .set_write_timeout(Some(Duration::from_millis(900)))
        .map_err(|error| error.to_string())?;
    socket
        .connect((gateway, GATEWAY_PORT))
        .map_err(|error| error.to_string())?;
    Ok(socket)
}

fn nat_pmp_map_request(internal_port: u16, external_port: u16, lifetime: u32) -> [u8; 12] {
    let mut request = [0_u8; 12];
    request[1] = 1; // UDP mapping
    request[4..6].copy_from_slice(&internal_port.to_be_bytes());
    request[6..8].copy_from_slice(&external_port.to_be_bytes());
    request[8..12].copy_from_slice(&lifetime.to_be_bytes());
    request
}

fn parse_nat_pmp_public_address(response: &[u8]) -> Result<Ipv4Addr, String> {
    if response.len() < 12 || response[0] != 0 || response[1] != 128 {
        return Err("malformed public-address response".into());
    }
    let result = u16::from_be_bytes([response[2], response[3]]);
    if result != 0 {
        return Err(format!("gateway returned result code {result}"));
    }
    Ok(Ipv4Addr::new(
        response[8],
        response[9],
        response[10],
        response[11],
    ))
}

fn parse_nat_pmp_map_response(response: &[u8], internal_port: u16) -> Result<u16, String> {
    if response.len() < 16 || response[0] != 0 || response[1] != 129 {
        return Err("malformed UDP mapping response".into());
    }
    let result = u16::from_be_bytes([response[2], response[3]]);
    if result != 0 {
        return Err(format!("gateway returned result code {result}"));
    }
    if u16::from_be_bytes([response[8], response[9]]) != internal_port {
        return Err("gateway returned a different internal port".into());
    }
    Ok(u16::from_be_bytes([response[10], response[11]]))
}

fn pcp_map_request(
    local_ip: Ipv4Addr,
    internal_port: u16,
    external_port: u16,
    lifetime: u32,
    nonce: [u8; 12],
) -> [u8; 60] {
    let mut request = [0_u8; 60];
    request[0] = 2;
    request[1] = 1; // MAP opcode
    request[4..8].copy_from_slice(&lifetime.to_be_bytes());
    request[18..20].copy_from_slice(&[0xff, 0xff]);
    request[20..24].copy_from_slice(&local_ip.octets());
    request[24..36].copy_from_slice(&nonce);
    request[36] = 17; // UDP
    request[40..42].copy_from_slice(&internal_port.to_be_bytes());
    request[42..44].copy_from_slice(&external_port.to_be_bytes());
    request
}

fn parse_pcp_map_response(
    response: &[u8],
    internal_port: u16,
    nonce: [u8; 12],
) -> Result<(IpAddr, u16), String> {
    if response.len() < 60 || response[0] != 2 || response[1] != 0x81 {
        return Err("malformed MAP response".into());
    }
    if response[3] != 0 {
        return Err(format!("gateway returned result code {}", response[3]));
    }
    if response[24..36] != nonce || response[36] != 17 {
        return Err("MAP response does not match this UDP request".into());
    }
    if u16::from_be_bytes([response[40], response[41]]) != internal_port {
        return Err("gateway returned a different internal port".into());
    }
    let external_port = u16::from_be_bytes([response[42], response[43]]);
    let address = if response[44..56] == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff] {
        IpAddr::V4(Ipv4Addr::new(
            response[56],
            response[57],
            response[58],
            response[59],
        ))
    } else {
        let octets: [u8; 16] = response[44..60]
            .try_into()
            .map_err(|_| "invalid external address".to_string())?;
        IpAddr::V6(std::net::Ipv6Addr::from(octets))
    };
    Ok((address, external_port))
}

#[cfg(windows)]
fn default_ipv4_gateway() -> Option<Ipv4Addr> {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    let output = Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "Get-NetRoute -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' | Sort-Object RouteMetric | Select-Object -First 1 -ExpandProperty NextHop",
        ])
        .creation_flags(CREATE_NO_WINDOW)
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().parse().ok())
        .flatten()
}

#[cfg(unix)]
fn default_ipv4_gateway() -> Option<Ipv4Addr> {
    let output = Command::new("ip")
        .args(["-4", "route", "show", "default"])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let mut words = text.split_whitespace();
    while let Some(word) = words.next() {
        if word == "via" {
            return words.next()?.parse().ok();
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_nat_pmp_mapping_response() {
        let mut response = [0_u8; 16];
        response[1] = 129;
        response[8..10].copy_from_slice(&30_000_u16.to_be_bytes());
        response[10..12].copy_from_slice(&40_000_u16.to_be_bytes());
        assert_eq!(
            parse_nat_pmp_map_response(&response, 30_000).unwrap(),
            40_000
        );
    }

    #[test]
    fn pcp_response_is_bound_to_nonce_and_port() {
        let nonce = [7_u8; 12];
        let mut response = [0_u8; 60];
        response[0] = 2;
        response[1] = 0x81;
        response[24..36].copy_from_slice(&nonce);
        response[36] = 17;
        response[40..42].copy_from_slice(&30_000_u16.to_be_bytes());
        response[42..44].copy_from_slice(&40_000_u16.to_be_bytes());
        response[54..56].copy_from_slice(&[0xff, 0xff]);
        response[56..60].copy_from_slice(&[203, 0, 113, 9]);
        assert_eq!(
            parse_pcp_map_response(&response, 30_000, nonce).unwrap(),
            ("203.0.113.9".parse().unwrap(), 40_000)
        );
        assert!(parse_pcp_map_response(&response, 30_000, [8_u8; 12]).is_err());
    }
}
