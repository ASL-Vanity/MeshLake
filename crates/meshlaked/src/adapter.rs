mod kill_switch;
#[cfg(target_os = "linux")]
mod linux;
mod policy;
#[cfg(windows)]
mod windows;

pub(crate) use kill_switch::{BootstrapEndpoint, BootstrapTransport, KillSwitchPlan};
#[cfg(target_os = "linux")]
pub use linux::{default_wintun_path, AdapterController};
#[cfg(windows)]
pub use windows::{default_wintun_path, AdapterController};

#[cfg(not(any(target_os = "linux", windows)))]
compile_error!("meshlaked currently supports Windows and Linux only");
