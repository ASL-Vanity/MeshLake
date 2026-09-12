use anyhow::{Context, Result};
use clap::Subcommand;
use meshlake_core::{
    cleanup_stale_state_backup, decode_protected_state_with, decode_state_backup,
    encode_state_backup, recover_protected_state_file, resolve_state_backup_path,
    restrict_state_file_permissions, write_state_backup_file, StateBackupKind, StateFileLock,
    StateProtection, AGENT_STATE_PROTECTION_PURPOSE,
};
use std::{
    collections::HashSet,
    fs,
    io::{self, BufRead},
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

use super::{migrate_and_validate_agent_state, write_state_with_protection, PersistedState};

#[cfg(test)]
use super::write_state;

#[derive(Subcommand)]
pub(crate) enum StateCommand {
    /// Export agent state into a password-protected, machine-portable backup.
    Backup {
        #[arg(value_name = "BACKUP_FILE")]
        output: PathBuf,
        /// Read one password line from standard input instead of prompting.
        #[arg(long)]
        password_stdin: bool,
        /// Replace an existing backup file.
        #[arg(long)]
        force: bool,
    },
    /// Restore agent state from a password-protected backup.
    Restore {
        #[arg(value_name = "BACKUP_FILE")]
        input: PathBuf,
        /// Read one password line from standard input instead of prompting.
        #[arg(long)]
        password_stdin: bool,
        /// Replace an existing agent state file after full validation.
        #[arg(long)]
        force: bool,
    },
    /// Remove only locally persisted networks whose traffic key is malformed.
    /// This recovers state written by older agent builds.
    RepairInvalidNetworks {
        /// Required acknowledgement because affected local network records and
        /// their local authorization/exit configuration are removed.
        #[arg(long)]
        yes: bool,
    },
}

pub(crate) fn run(
    command: StateCommand,
    state_path: &Path,
    protection: &StateProtection,
) -> Result<()> {
    match command {
        StateCommand::Backup {
            output,
            password_stdin,
            force,
        } => {
            let password = read_password(password_stdin, true)?;
            backup_with_password_with_protection(
                state_path,
                &output,
                password.as_bytes(),
                force,
                protection,
            )?;
            println!("Agent state backup written to {}", output.display());
        }
        StateCommand::Restore {
            input,
            password_stdin,
            force,
        } => {
            let password = read_password(password_stdin, false)?;
            restore_with_password_with_protection(
                state_path,
                &input,
                password.as_bytes(),
                force,
                protection,
            )?;
            println!("Agent state restored to {}", state_path.display());
        }
        StateCommand::RepairInvalidNetworks { yes } => {
            if !yes {
                anyhow::bail!(
                    "refusing to modify agent state; rerun with --yes after reviewing the affected local networks"
                );
            }
            let removed = repair_invalid_networks_with_protection(state_path, protection)?;
            println!(
                "Removed {removed} persisted network record(s) with malformed traffic keys from {}",
                state_path.display()
            );
        }
    }
    Ok(())
}

/// Repairs only the legacy failure mode where an agent persisted an empty or
/// malformed network traffic key. The state stays platform-protected during the
/// whole operation, including Windows DPAPI LocalMachine state.
fn repair_invalid_networks_with_protection(
    state_path: &Path,
    protection: &StateProtection,
) -> Result<usize> {
    let _state_lock = StateFileLock::acquire(state_path)?;
    recover_protected_state_file(state_path)?;
    if !state_path.exists() {
        anyhow::bail!("agent state file does not exist: {}", state_path.display());
    }
    restrict_state_file_permissions(state_path)?;
    let bytes = fs::read(state_path)
        .with_context(|| format!("cannot read agent state {}", state_path.display()))?;
    let decoded = decode_protected_state_with(&bytes, AGENT_STATE_PROTECTION_PURPOSE, protection)
        .with_context(|| {
        format!("invalid or unreadable agent state {}", state_path.display())
    })?;
    let mut state: PersistedState = decoded.value;
    let invalid_network_ids: HashSet<_> = state
        .networks
        .iter()
        .filter(|network| meshlake_core::NetworkKey::from_slice(&network.network_key).is_err())
        .map(|network| network.network.id)
        .collect();
    if invalid_network_ids.is_empty() {
        return Ok(0);
    }
    state
        .networks
        .retain(|network| !invalid_network_ids.contains(&network.network.id));
    state
        .authorizations
        .retain(|network_id, _| !invalid_network_ids.contains(network_id));
    state
        .exit_gateways
        .retain(|gateway| !invalid_network_ids.contains(&gateway.network_id));
    // Validation after removal intentionally fails closed on every unrelated
    // corruption; this command never silently repairs or discards other data.
    migrate_and_validate_agent_state(&mut state)?;
    write_state_with_protection(state_path, &state, protection)?;
    cleanup_stale_state_backup(state_path)?;
    Ok(invalid_network_ids.len())
}

#[cfg(test)]
pub(crate) fn backup_with_password(
    state_path: &Path,
    output: &Path,
    password: &[u8],
    force: bool,
) -> Result<()> {
    backup_with_password_with_protection(
        state_path,
        output,
        password,
        force,
        &StateProtection::platform_default(),
    )
}

fn backup_with_password_with_protection(
    state_path: &Path,
    output: &Path,
    password: &[u8],
    force: bool,
    protection: &StateProtection,
) -> Result<()> {
    let _state_lock = StateFileLock::acquire(state_path)?;
    let output = resolve_state_backup_path(state_path, output)?;
    recover_protected_state_file(state_path)?;
    if !state_path.exists() {
        anyhow::bail!("agent state file does not exist: {}", state_path.display());
    }
    restrict_state_file_permissions(state_path)?;
    let bytes = fs::read(state_path)
        .with_context(|| format!("cannot read agent state {}", state_path.display()))?;
    let decoded = decode_protected_state_with(&bytes, AGENT_STATE_PROTECTION_PURPOSE, protection)
        .with_context(|| {
        format!("invalid or unreadable agent state {}", state_path.display())
    })?;
    let mut state: PersistedState = decoded.value;
    let migrated = migrate_and_validate_agent_state(&mut state)?;
    if decoded.needs_protection_upgrade || migrated {
        write_state_with_protection(state_path, &state, protection)?;
    }
    cleanup_stale_state_backup(state_path)?;
    let encrypted = Zeroizing::new(encode_state_backup(
        &state,
        password,
        StateBackupKind::Agent,
    )?);
    write_state_backup_file(&output, &encrypted, force)?;
    Ok(())
}

#[cfg(test)]
pub(crate) fn restore_with_password(
    state_path: &Path,
    input: &Path,
    password: &[u8],
    force: bool,
) -> Result<()> {
    restore_with_password_with_protection(
        state_path,
        input,
        password,
        force,
        &StateProtection::platform_default(),
    )
}

fn restore_with_password_with_protection(
    state_path: &Path,
    input: &Path,
    password: &[u8],
    force: bool,
    protection: &StateProtection,
) -> Result<()> {
    let _state_lock = StateFileLock::acquire(state_path)?;
    let input = resolve_state_backup_path(state_path, input)?;
    recover_protected_state_file(state_path)?;
    let bytes = fs::read(&input)
        .with_context(|| format!("cannot read agent state backup {}", input.display()))?;
    let mut state: PersistedState = decode_state_backup(&bytes, password, StateBackupKind::Agent)?;
    migrate_and_validate_agent_state(&mut state)?;
    if state_path.exists() && !force {
        anyhow::bail!(
            "agent state file already exists: {}; pass --force to replace it",
            state_path.display()
        );
    }
    write_state_with_protection(state_path, &state, protection)?;
    Ok(())
}

fn read_password(from_stdin: bool, confirm: bool) -> Result<Zeroizing<String>> {
    let password = if from_stdin {
        let mut line = String::new();
        io::stdin()
            .lock()
            .read_line(&mut line)
            .context("cannot read backup password from standard input")?;
        while line.ends_with(['\r', '\n']) {
            line.pop();
        }
        Zeroizing::new(line)
    } else {
        Zeroizing::new(
            rpassword::prompt_password("Backup password: ")
                .context("cannot read backup password from terminal")?,
        )
    };
    if password.is_empty() {
        anyhow::bail!("backup password must not be empty");
    }
    if confirm && !from_stdin {
        let repeated = Zeroizing::new(
            rpassword::prompt_password("Confirm backup password: ")
                .context("cannot confirm backup password from terminal")?,
        );
        if password.as_str() != repeated.as_str() {
            anyhow::bail!("backup passwords do not match");
        }
    }
    Ok(password)
}

#[cfg(test)]
mod tests {
    use super::*;
    use meshlake_core::{decode_protected_state, encode_state_backup, StateBackupKind};
    use uuid::Uuid;

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new(name: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "meshlake-agent-state-backup-{name}-{}",
                Uuid::new_v4()
            ));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        fn file(&self, name: &str) -> PathBuf {
            self.0.join(name)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn agent_backup_round_trips_and_uses_the_state_lock() {
        let directory = TestDirectory::new("round-trip");
        let source = directory.file("agent.json");
        let backup = directory.file("agent.mlb");
        let restored = directory.file("restored.json");
        let original = PersistedState::new();
        write_state(&source, &original).unwrap();

        let held_lock = StateFileLock::acquire(&source).unwrap();
        assert!(backup_with_password(&source, &backup, b"portable password", false).is_err());
        drop(held_lock);

        backup_with_password(&source, &backup, b"portable password", false).unwrap();
        restore_with_password(&restored, &backup, b"portable password", false).unwrap();
        let decoded: PersistedState = decode_protected_state(
            &fs::read(&restored).unwrap(),
            AGENT_STATE_PROTECTION_PURPOSE,
        )
        .unwrap()
        .value;
        assert_eq!(decoded.device_id, original.device_id);
        assert_eq!(decoded.identity_secret_key, original.identity_secret_key);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&backup).unwrap().permissions().mode() & 0o777,
                0o600
            );
            assert_eq!(
                fs::metadata(&restored).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn agent_restore_rejects_wrong_password_and_unknown_schema_without_overwrite() {
        let directory = TestDirectory::new("fail-closed");
        let backup = directory.file("agent.mlb");
        let restored = directory.file("restored.json");
        let original = PersistedState::new();
        write_state(&restored, &original).unwrap();
        let before = fs::read(&restored).unwrap();

        let valid = encode_state_backup(&original, b"right", StateBackupKind::Agent).unwrap();
        fs::write(&backup, valid).unwrap();
        assert!(restore_with_password(&restored, &backup, b"wrong", true).is_err());
        assert_eq!(fs::read(&restored).unwrap(), before);

        let mut unknown = PersistedState::new();
        unknown.schema_version = super::super::AGENT_STATE_SCHEMA_VERSION + 1;
        let invalid = encode_state_backup(&unknown, b"right", StateBackupKind::Agent).unwrap();
        fs::write(&backup, invalid).unwrap();
        assert!(restore_with_password(&restored, &backup, b"right", true).is_err());
        assert_eq!(fs::read(&restored).unwrap(), before);
    }

    #[test]
    fn repair_invalid_networks_removes_only_malformed_records_and_associations() {
        let directory = TestDirectory::new("repair-invalid-networks");
        let state_path = directory.file("agent.json");
        let mut state = PersistedState::new();
        let valid_id = meshlake_core::NetworkId(Uuid::from_u128(90));
        let invalid_id = meshlake_core::NetworkId(Uuid::from_u128(91));
        let valid = meshlake_core::JoinedNetwork {
            network: meshlake_core::VirtualNetwork {
                id: valid_id,
                name: "valid".into(),
                ipv4_prefix: "100.64.90.0/24".into(),
                ipv6_prefix: None,
                relay_policy: meshlake_core::RelayPolicy::Disabled,
            },
            assigned_addresses: Vec::new(),
            certificate: None,
            network_key: vec![7; 32],
            control_plane: meshlake_core::NetworkControlPlane::default(),
        };
        let mut invalid = valid.clone();
        invalid.network.id = invalid_id;
        invalid.network_key.clear();
        state.networks = vec![valid, invalid];
        state.authorizations.insert(
            invalid_id,
            meshlake_core::NetworkAuthorizationManifest {
                version: 1,
                network_id: invalid_id,
                authorization_epoch: 1,
                network_key_epoch: 1,
                active_members: Vec::new(),
                revoked_certificate_ids: Vec::new(),
                issued_at_unix_seconds: 0,
                expires_at_unix_seconds: 1,
                controller_public_key: vec![0; 32],
                signature: vec![0; 64],
                epoch_hint: None,
            },
        );
        state.exit_gateways.push(super::super::ExitGatewayConfig {
            network_id: invalid_id,
            egress_interface: "test-egress".into(),
            enable_ipv4: true,
            enable_ipv6: false,
        });
        write_state(&state_path, &state).unwrap();

        assert_eq!(
            repair_invalid_networks_with_protection(
                &state_path,
                &StateProtection::platform_default(),
            )
            .unwrap(),
            1
        );
        let repaired: PersistedState = decode_protected_state(
            &fs::read(&state_path).unwrap(),
            AGENT_STATE_PROTECTION_PURPOSE,
        )
        .unwrap()
        .value;
        assert_eq!(repaired.networks.len(), 1);
        assert_eq!(repaired.networks[0].network.id, valid_id);
        assert!(!repaired.authorizations.contains_key(&invalid_id));
        assert!(repaired.exit_gateways.is_empty());
    }

    #[test]
    fn traversal_alias_cannot_replace_agent_state_even_with_force() {
        let directory = TestDirectory::new("traversal-alias");
        let source = directory.file("agent.json");
        let alias = directory.file("missing").join("..").join("agent.json");
        write_state(&source, &PersistedState::new()).unwrap();
        let before = fs::read(&source).unwrap();

        let error = backup_with_password(&source, &alias, b"portable password", true)
            .expect_err("reserved traversal alias must fail before writing");
        assert!(error
            .to_string()
            .contains("backup path conflicts with a reserved state path"));
        assert_eq!(fs::read(&source).unwrap(), before);
        assert!(!directory.file("missing").exists());
    }

    #[cfg(unix)]
    #[test]
    fn agent_backup_requires_explicit_plaintext_migration_and_rewrites_once() {
        use meshlake_core::{
            create_restricted_secret_file, decode_protected_state_with, StateKeyProvider,
        };

        let directory = TestDirectory::new("provider-migration");
        let state_directory = directory.file("state");
        let key_directory = directory.file("keys");
        fs::create_dir_all(&state_directory).unwrap();
        fs::create_dir_all(&key_directory).unwrap();
        let source = state_directory.join("agent.json");
        let backup = directory.file("agent.mlb");
        let second_backup = directory.file("agent-second.mlb");
        let restored = state_directory.join("restored-agent.json");
        let key_path = key_directory.join("state.key");
        let original = PersistedState::new();
        fs::write(&source, serde_json::to_vec_pretty(&original).unwrap()).unwrap();
        create_restricted_secret_file(&key_path, &[31; 32]).unwrap();

        let protection = StateProtection::from_provider(
            &source,
            StateKeyProvider::RestrictedFile(key_path.clone()),
        )
        .unwrap();
        let error = backup_with_password_with_protection(
            &source,
            &backup,
            b"portable password",
            false,
            &protection,
        )
        .expect_err("provider mode must reject plaintext without one-run authorization");
        assert!(format!("{error:#}").contains("allow-plaintext-state-migration"));
        assert!(!backup.exists());

        let migration = StateProtection::from_provider_with_plaintext_migration(
            &source,
            StateKeyProvider::RestrictedFile(key_path.clone()),
            true,
        )
        .unwrap();
        backup_with_password_with_protection(
            &source,
            &backup,
            b"portable password",
            false,
            &migration,
        )
        .unwrap();

        let protection = StateProtection::from_provider(
            &source,
            StateKeyProvider::RestrictedFile(key_path.clone()),
        )
        .unwrap();
        backup_with_password_with_protection(
            &source,
            &second_backup,
            b"portable password",
            false,
            &protection,
        )
        .expect("rewritten state must not need migration authorization again");

        let restore_protection =
            StateProtection::from_provider(&restored, StateKeyProvider::RestrictedFile(key_path))
                .unwrap();
        restore_with_password_with_protection(
            &restored,
            &backup,
            b"portable password",
            false,
            &restore_protection,
        )
        .unwrap();
        let decoded: meshlake_core::DecodedState<PersistedState> = decode_protected_state_with(
            &fs::read(&restored).unwrap(),
            AGENT_STATE_PROTECTION_PURPOSE,
            &restore_protection,
        )
        .unwrap();
        assert_eq!(decoded.value.device_id, original.device_id);
        assert_eq!(
            decoded.value.identity_secret_key,
            original.identity_secret_key
        );
        assert!(!decoded.needs_protection_upgrade);
    }
}
