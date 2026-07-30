//! Linux TUN adapter implementation used by the headless MeshLake agent.

use anyhow::{anyhow, bail, Context, Result};
use meshlake_core::JoinedNetwork;
use std::{
    fs::{File, OpenOptions},
    io::{ErrorKind, Read, Write},
    os::{fd::AsRawFd, unix::fs::OpenOptionsExt},
    path::PathBuf,
    process::Command,
    sync::Mutex,
};

const INTERFACE_NAME: &str = "meshlake0";
const TUNSETIFF: libc::c_ulong = 0x4004_54ca;
const IFF_TUN: libc::c_short = 0x0001;
const IFF_NO_PI: libc::c_short = 0x1000;

#[repr(C)]
struct TunIfReq {
    name: [libc::c_char; libc::IFNAMSIZ],
    flags: libc::c_short,
    padding: [u8; 22],
}

pub struct AdapterController {
    session: Mutex<Option<File>>,
}

impl AdapterController {
    pub fn new(_: PathBuf) -> Self {
        Self {
            session: Mutex::new(None),
        }
    }

    pub fn status(&self) -> String {
        if self.is_active() {
            "active".into()
        } else if std::path::Path::new("/dev/net/tun").exists() {
            "ready".into()
        } else {
            "driver-missing".into()
        }
    }

    pub fn activate(&self) -> Result<()> {
        let mut guard = self.session.lock().expect("adapter lock poisoned");
        if guard.is_some() {
            return Ok(());
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NONBLOCK)
            .open("/dev/net/tun")
            .context("cannot open /dev/net/tun; load the tun module and run MeshLake as root")?;
        let mut request = TunIfReq {
            name: [0; libc::IFNAMSIZ],
            flags: IFF_TUN | IFF_NO_PI,
            padding: [0; 22],
        };
        for (destination, source) in request
            .name
            .iter_mut()
            .zip(INTERFACE_NAME.as_bytes().iter().copied())
        {
            *destination = source as libc::c_char;
        }
        let result = unsafe { libc::ioctl(file.as_raw_fd(), TUNSETIFF, &mut request) };
        if result < 0 {
            return Err(anyhow!(
                "cannot create Linux TUN interface {INTERFACE_NAME}: {}",
                std::io::Error::last_os_error()
            ));
        }
        *guard = Some(file);
        run_ip(&["link", "set", "dev", INTERFACE_NAME, "up"])?;
        Ok(())
    }

    pub fn deactivate(&self) {
        self.session.lock().expect("adapter lock poisoned").take();
    }

    pub fn is_active(&self) -> bool {
        self.session
            .lock()
            .expect("adapter lock poisoned")
            .is_some()
    }

    pub fn try_read_packet(&self) -> Result<Option<Vec<u8>>> {
        let guard = self.session.lock().expect("adapter lock poisoned");
        let mut file = guard
            .as_ref()
            .ok_or_else(|| anyhow!("MeshLake adapter is not active"))?;
        let mut packet = vec![0_u8; u16::MAX as usize];
        match file.read(&mut packet) {
            Ok(0) => Ok(None),
            Ok(size) => {
                packet.truncate(size);
                Ok(Some(packet))
            }
            Err(error) if error.kind() == ErrorKind::WouldBlock => Ok(None),
            Err(error) => Err(error).context("cannot read Linux TUN packet"),
        }
    }

    pub fn write_packet(&self, packet: &[u8]) -> Result<()> {
        if packet.is_empty() || packet.len() > u16::MAX as usize {
            bail!("invalid Linux TUN packet length");
        }
        let guard = self.session.lock().expect("adapter lock poisoned");
        let mut file = guard
            .as_ref()
            .ok_or_else(|| anyhow!("MeshLake adapter is not active"))?;
        file.write_all(packet)
            .context("cannot write packet to Linux TUN")
    }

    pub fn configure_networks(&self, networks: &[JoinedNetwork]) -> Result<()> {
        if !self.is_active() {
            bail!("MeshLake adapter is not active");
        }
        for joined in networks {
            for address in &joined.assigned_addresses {
                let prefix_length = match address {
                    std::net::IpAddr::V4(_) => prefix_length(&joined.network.ipv4_prefix)?,
                    std::net::IpAddr::V6(_) => joined
                        .network
                        .ipv6_prefix
                        .as_deref()
                        .map(prefix_length)
                        .transpose()?
                        .unwrap_or(128),
                };
                run_ip(&[
                    "address",
                    "replace",
                    &format!("{address}/{prefix_length}"),
                    "dev",
                    INTERFACE_NAME,
                ])?;
            }
        }
        Ok(())
    }

    pub fn remove_network(&self, joined: &JoinedNetwork) -> Result<()> {
        if !self.is_active() {
            return Ok(());
        }
        for address in &joined.assigned_addresses {
            let prefix_length = match address {
                std::net::IpAddr::V4(_) => prefix_length(&joined.network.ipv4_prefix)?,
                std::net::IpAddr::V6(_) => joined
                    .network
                    .ipv6_prefix
                    .as_deref()
                    .map(prefix_length)
                    .transpose()?
                    .unwrap_or(128),
            };
            let _ = run_ip(&[
                "address",
                "del",
                &format!("{address}/{prefix_length}"),
                "dev",
                INTERFACE_NAME,
            ]);
        }
        Ok(())
    }
}

fn prefix_length(prefix: &str) -> Result<u8> {
    prefix
        .split_once('/')
        .and_then(|(_, length)| length.parse::<u8>().ok())
        .ok_or_else(|| anyhow!("invalid network prefix: {prefix}"))
}

fn run_ip(arguments: &[&str]) -> Result<()> {
    let output = Command::new("ip")
        .args(arguments)
        .output()
        .context("cannot start iproute2 command 'ip'")?;
    if output.status.success() {
        return Ok(());
    }
    Err(anyhow!(
        "ip {} failed ({}): {}{}",
        arguments.join(" "),
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    ))
}

/// Kept for a stable constructor interface shared with Windows. Linux ignores it.
pub fn default_wintun_path() -> PathBuf {
    PathBuf::new()
}

#[cfg(test)]
mod tests {
    use super::prefix_length;

    #[test]
    fn parses_linux_interface_prefixes() {
        assert_eq!(prefix_length("100.64.0.0/24").unwrap(), 24);
        assert_eq!(prefix_length("fd00::/64").unwrap(), 64);
    }
}
