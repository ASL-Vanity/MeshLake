#[cfg(unix)]
mod linux;
#[cfg(windows)]
mod windows;

#[cfg(unix)]
pub use linux::{default_wintun_path, AdapterController};
#[cfg(windows)]
pub use windows::{default_wintun_path, AdapterController};

#[cfg(not(any(unix, windows)))]
compile_error!("meshlaked currently supports Windows and Unix-like platforms only");
