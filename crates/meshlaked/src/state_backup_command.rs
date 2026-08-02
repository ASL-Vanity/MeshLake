use anyhow::{Context, Result};
use clap::Subcommand;
use meshlake_core::{
    cleanup_stale_state_backup, decode_protected_state, decode_state_backup, encode_state_backup,
    recover_protected_state_file, resolve_state_backup_path, restrict_state_file_permissions,
    write_state_backup_file, StateBackupKind, StateFileLock, AGENT_STATE_PROTECTION_PURPOSE,
};
use std::{
    fs,
    io::{self, BufRead},
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

use super::{migrate_and_validate_agent_state, write_state, PersistedState};

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
}

pub(crate) fn run(command: StateCommand, state_path: &Path) -> Result<()> {
    match command {
        StateCommand::Backup {
            output,
            password_stdin,
            force,
        } => {
            let password = read_password(password_stdin, true)?;
            backup_with_password(state_path, &output, password.as_bytes(), force)?;
            println!("Agent state backup written to {}", output.display());
        }
        StateCommand::Restore {
            input,
            password_stdin,
            force,
        } => {
            let password = read_password(password_stdin, false)?;
            restore_with_password(state_path, &input, password.as_bytes(), force)?;
            println!("Agent state restored to {}", state_path.display());
        }
    }
    Ok(())
}

pub(crate) fn backup_with_password(
    state_path: &Path,
    output: &Path,
    password: &[u8],
    force: bool,
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
    let mut state: PersistedState = decode_protected_state(&bytes, AGENT_STATE_PROTECTION_PURPOSE)
        .with_context(|| format!("invalid or unreadable agent state {}", state_path.display()))?
        .value;
    migrate_and_validate_agent_state(&mut state)?;
    cleanup_stale_state_backup(state_path)?;
    let encrypted = Zeroizing::new(encode_state_backup(
        &state,
        password,
        StateBackupKind::Agent,
    )?);
    write_state_backup_file(&output, &encrypted, force)?;
    Ok(())
}

pub(crate) fn restore_with_password(
    state_path: &Path,
    input: &Path,
    password: &[u8],
    force: bool,
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
    write_state(state_path, &state)?;
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
}
