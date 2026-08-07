//! Validation helpers for values embedded in generated systemd unit files.
//!
//! MeshLake's service installers deliberately fail closed instead of trying to
//! implement every systemd escaping rule. A privileged installer must not let
//! a user-controlled file name alter an `ExecStart`, `LoadCredential`, or
//! sandbox directive.

use std::path::Path;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SystemdUnitArgumentError {
    #[error("{label} must be valid UTF-8")]
    NonUtf8 { label: &'static str },
    #[error("{label} must be an absolute path")]
    Relative { label: &'static str },
    #[error("{label} contains characters that are unsafe in a generated systemd unit")]
    Unsafe { label: &'static str },
}

/// Returns a safe absolute-path value for an installer-generated systemd unit.
///
/// The caller should canonicalize the path before calling this function. Paths
/// containing whitespace, control characters, quotes, backslashes, systemd
/// specifiers, variable markers, comments, or command separators are rejected
/// rather than ambiguously escaped.
pub fn systemd_unit_path(
    path: &Path,
    label: &'static str,
) -> Result<String, SystemdUnitArgumentError> {
    #[cfg(unix)]
    if !path.is_absolute() {
        return Err(SystemdUnitArgumentError::Relative { label });
    }
    let value = path
        .to_str()
        .ok_or(SystemdUnitArgumentError::NonUtf8 { label })?;
    validate_systemd_unit_value(value, label)?;
    Ok(value.to_owned())
}

/// Returns a safe simple name for a `LoadCredential=` entry.
pub fn systemd_credential_name(
    value: &str,
    label: &'static str,
) -> Result<String, SystemdUnitArgumentError> {
    if value.is_empty()
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(SystemdUnitArgumentError::Unsafe { label });
    }
    Ok(value.to_owned())
}

fn validate_systemd_unit_value(
    value: &str,
    label: &'static str,
) -> Result<(), SystemdUnitArgumentError> {
    if value.is_empty()
        || value.chars().any(|character| {
            character.is_whitespace()
                || character.is_control()
                || matches!(character, '"' | '\\' | '$' | '%' | '#' | ';')
        })
    {
        return Err(SystemdUnitArgumentError::Unsafe { label });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_plain_absolute_paths_and_credential_names() {
        assert_eq!(
            systemd_unit_path(Path::new("/opt/meshlake/meshlaked"), "executable").unwrap(),
            "/opt/meshlake/meshlaked"
        );
        assert_eq!(
            systemd_credential_name("meshlake-state-key", "credential").unwrap(),
            "meshlake-state-key"
        );
    }

    #[test]
    fn rejects_unit_control_and_expansion_characters() {
        for value in [
            "/opt/mesh lake/meshlaked",
            "/opt/mesh\nExecStart=/bin/sh",
            "/opt/mesh\"quoted",
            "/opt/mesh\\escaped",
            "/opt/$variable",
            "/opt/%n",
            "/opt/#comment",
            "/opt/;separator",
        ] {
            assert!(
                systemd_unit_path(Path::new(value), "path").is_err(),
                "{value}"
            );
        }
        for value in ["", "state key", "../credential", "credential\nnext"] {
            assert!(
                systemd_credential_name(value, "credential").is_err(),
                "{value:?}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn rejects_relative_paths() {
        assert!(matches!(
            systemd_unit_path(Path::new("relative/state.json"), "state path"),
            Err(SystemdUnitArgumentError::Relative { .. })
        ));
    }
}
