use anyhow::{Context, Result};
use clap::Subcommand;
use meshlake_core::{
    cleanup_stale_state_backup, decode_protected_state, decode_state_backup, encode_state_backup,
    recover_protected_state_file, restrict_state_file_permissions, write_state_backup_file,
    StateBackupKind, StateFileLock, CONTROLLER_STATE_PROTECTION_PURPOSE,
};
use std::{
    fs,
    io::{self, BufRead},
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

use super::{migrate_and_validate_controller_state, write_state, ControllerState};

#[derive(Subcommand)]
pub(crate) enum StateCommand {
    /// Export controller state into a password-protected, machine-portable backup.
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
    /// Restore controller state from a password-protected backup.
    Restore {
        #[arg(value_name = "BACKUP_FILE")]
        input: PathBuf,
        /// Read one password line from standard input instead of prompting.
        #[arg(long)]
        password_stdin: bool,
        /// Replace an existing controller state file after full validation.
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
            println!("Controller state backup written to {}", output.display());
        }
        StateCommand::Restore {
            input,
            password_stdin,
            force,
        } => {
            let password = read_password(password_stdin, false)?;
            restore_with_password(state_path, &input, password.as_bytes(), force)?;
            println!("Controller state restored to {}", state_path.display());
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
    ensure_safe_backup_path(state_path, output)?;
    recover_protected_state_file(state_path)?;
    if !state_path.exists() {
        anyhow::bail!(
            "controller state file does not exist: {}",
            state_path.display()
        );
    }
    restrict_state_file_permissions(state_path)?;
    let bytes = fs::read(state_path)
        .with_context(|| format!("cannot read controller state {}", state_path.display()))?;
    let mut state: ControllerState =
        decode_protected_state(&bytes, CONTROLLER_STATE_PROTECTION_PURPOSE)
            .with_context(|| {
                format!(
                    "invalid or unreadable controller state {}",
                    state_path.display()
                )
            })?
            .value;
    migrate_and_validate_controller_state(&mut state)?;
    cleanup_stale_state_backup(state_path)?;
    let encrypted = Zeroizing::new(encode_state_backup(
        &state,
        password,
        StateBackupKind::Controller,
    )?);
    write_state_backup_file(output, &encrypted, force)?;
    Ok(())
}

pub(crate) fn restore_with_password(
    state_path: &Path,
    input: &Path,
    password: &[u8],
    force: bool,
) -> Result<()> {
    let _state_lock = StateFileLock::acquire(state_path)?;
    ensure_safe_backup_path(state_path, input)?;
    recover_protected_state_file(state_path)?;
    let bytes = fs::read(input)
        .with_context(|| format!("cannot read controller state backup {}", input.display()))?;
    let mut state: ControllerState =
        decode_state_backup(&bytes, password, StateBackupKind::Controller)?;
    migrate_and_validate_controller_state(&mut state)?;
    if state_path.exists() && !force {
        anyhow::bail!(
            "controller state file already exists: {}; pass --force to replace it",
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

fn ensure_safe_backup_path(state_path: &Path, backup_path: &Path) -> Result<()> {
    let backup = resolved_path(backup_path)?;
    for reserved in [
        state_path.to_path_buf(),
        suffixed_path(state_path, ".lock"),
        suffixed_path(state_path, ".bak"),
    ] {
        if backup == resolved_path(&reserved)? {
            anyhow::bail!("backup path conflicts with a reserved state path");
        }
    }
    Ok(())
}

fn resolved_path(path: &Path) -> Result<PathBuf> {
    if path.exists() {
        return fs::canonicalize(path)
            .with_context(|| format!("cannot resolve path {}", path.display()));
    }
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let parent = absolute.parent().unwrap_or_else(|| Path::new("."));
    let parent = if parent.exists() {
        fs::canonicalize(parent)
            .with_context(|| format!("cannot resolve directory {}", parent.display()))?
    } else {
        parent.to_path_buf()
    };
    Ok(parent.join(
        absolute
            .file_name()
            .context("state or backup path has no file name")?,
    ))
}

fn suffixed_path(path: &Path, suffix: &str) -> PathBuf {
    let mut value = path.as_os_str().to_os_string();
    value.push(suffix);
    value.into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use meshlake_core::{decode_protected_state, encode_state_backup, StateBackupKind};
    use std::collections::HashMap;
    use uuid::Uuid;

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new(name: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "meshlake-controller-state-backup-{name}-{}",
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

    fn state(schema_version: u32) -> ControllerState {
        ControllerState {
            schema_version,
            signing_key: vec![7; 32],
            admin_token: "backup-test-administrator-token".into(),
            networks: HashMap::new(),
            enrollment_tokens: HashMap::new(),
        }
    }

    #[test]
    fn controller_backup_round_trips_and_refuses_overwrite_by_default() {
        let directory = TestDirectory::new("round-trip");
        let source = directory.file("controller.json");
        let backup = directory.file("controller.mlb");
        let restored = directory.file("restored.json");
        let original = state(super::super::CONTROLLER_STATE_SCHEMA_VERSION);
        write_state(&source, &original).unwrap();

        backup_with_password(&source, &backup, b"portable password", false).unwrap();
        let encrypted = fs::read(&backup).unwrap();
        assert!(!String::from_utf8_lossy(&encrypted).contains(&original.admin_token));
        assert!(backup_with_password(&source, &backup, b"portable password", false).is_err());
        assert_eq!(fs::read(&backup).unwrap(), encrypted);

        restore_with_password(&restored, &backup, b"portable password", false).unwrap();
        let restored_bytes = fs::read(&restored).unwrap();
        #[cfg(windows)]
        assert!(!String::from_utf8_lossy(&restored_bytes).contains(&original.admin_token));
        let decoded: ControllerState =
            decode_protected_state(&restored_bytes, CONTROLLER_STATE_PROTECTION_PURPOSE)
                .unwrap()
                .value;
        assert_eq!(decoded.signing_key, original.signing_key);
        assert_eq!(decoded.admin_token, original.admin_token);

        let before = fs::read(&restored).unwrap();
        assert!(restore_with_password(&restored, &backup, b"portable password", false).is_err());
        assert_eq!(fs::read(&restored).unwrap(), before);

        restore_with_password(&restored, &backup, b"portable password", true).unwrap();
        let forced: ControllerState = decode_protected_state(
            &fs::read(&restored).unwrap(),
            CONTROLLER_STATE_PROTECTION_PURPOSE,
        )
        .unwrap()
        .value;
        assert_eq!(forced.admin_token, original.admin_token);
    }

    #[test]
    fn controller_restore_validates_unknown_schema_before_creating_state() {
        let directory = TestDirectory::new("unknown-schema");
        let backup = directory.file("controller.mlb");
        let restored = directory.file("restored.json");
        let encrypted = encode_state_backup(
            &state(super::super::CONTROLLER_STATE_SCHEMA_VERSION + 1),
            b"portable password",
            StateBackupKind::Controller,
        )
        .unwrap();
        fs::write(&backup, encrypted).unwrap();

        assert!(restore_with_password(&restored, &backup, b"portable password", false).is_err());
        assert!(!restored.exists());
    }
}
