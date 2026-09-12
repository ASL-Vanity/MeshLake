//! Native lifecycle commands stay in their owning executable so platform state
//! protection, locking, prompting and service registration retain one implementation.
use anyhow::{Context, Result};
use clap::{Args, Subcommand, ValueEnum};
use std::{ffi::OsString, path::PathBuf, process::Stdio};

#[derive(Args, Default)]
pub(crate) struct DaemonArgs {
    #[arg(long)]
    state_file: Option<PathBuf>,
    #[arg(long, conflicts_with = "state_key_systemd_credential")]
    state_key_file: Option<PathBuf>,
    #[arg(long)]
    state_key_systemd_credential: Option<String>,
    #[arg(long)]
    allow_plaintext_state_migration: bool,
    #[arg(long)]
    wintun_dll: Option<PathBuf>,
}

impl DaemonArgs {
    fn arguments(self) -> Vec<OsString> {
        let mut args = Vec::new();
        for (flag, value) in [
            ("--state-file", self.state_file),
            ("--state-key-file", self.state_key_file),
            ("--wintun-dll", self.wintun_dll),
        ] {
            if let Some(value) = value {
                args.extend([OsString::from(flag), value.into_os_string()]);
            }
        }
        if let Some(value) = self.state_key_systemd_credential {
            args.extend(["--state-key-systemd-credential".into(), value.into()]);
        }
        if self.allow_plaintext_state_migration {
            args.push("--allow-plaintext-state-migration".into());
        }
        args
    }
}

#[derive(Args)]
pub(crate) struct BackupArgs {
    /// Encrypted backup path; passwords are never accepted in command arguments.
    file: PathBuf,
    #[arg(long)]
    password_stdin: bool,
    #[arg(long)]
    force: bool,
}

impl BackupArgs {
    fn arguments(self, operation: &str) -> Vec<OsString> {
        let mut args = vec!["state".into(), operation.into(), self.file.into_os_string()];
        if self.password_stdin {
            args.push("--password-stdin".into());
        }
        if self.force {
            args.push("--force".into());
        }
        args
    }
}

#[derive(Subcommand)]
pub(crate) enum BackupCommand {
    Backup(BackupArgs),
    Restore(BackupArgs),
}
impl BackupCommand {
    fn arguments(self) -> Vec<OsString> {
        match self {
            Self::Backup(args) => args.arguments("backup"),
            Self::Restore(args) => args.arguments("restore"),
        }
    }
}

#[derive(Subcommand)]
pub(crate) enum StateCommand {
    Backup(BackupArgs),
    Restore(BackupArgs),
    /// Remove only malformed local network records; native validation remains enforced.
    RepairInvalidNetworks {
        #[arg(long, required = true)]
        yes: bool,
    },
}

#[derive(Args)]
pub(crate) struct StateArgs {
    #[command(flatten)]
    options: DaemonArgs,
    #[command(subcommand)]
    command: StateCommand,
}

#[derive(Args)]
pub(crate) struct ControllerStateArgs {
    #[arg(long)]
    state_file: Option<PathBuf>,
    #[arg(long, conflicts_with = "state_key_systemd_credential")]
    state_key_file: Option<PathBuf>,
    #[arg(long)]
    state_key_systemd_credential: Option<String>,
    #[arg(long)]
    allow_plaintext_state_migration: bool,
    #[command(subcommand)]
    command: BackupCommand,
}

#[derive(Subcommand)]
pub(crate) enum AutostartCommand {
    Install,
    Status,
    Uninstall,
}

#[derive(Args)]
pub(crate) struct AutostartArgs {
    #[command(flatten)]
    options: DaemonArgs,
    #[command(subcommand)]
    command: AutostartCommand,
}

#[derive(Clone, Copy, ValueEnum)]
pub(crate) enum ServiceKind {
    Agent,
    Controller,
    Root,
    Relay,
}
impl ServiceKind {
    fn binary(self) -> &'static str {
        match self {
            Self::Agent => "meshlaked",
            Self::Controller => "meshlake-controller",
            Self::Root => "meshlake-root",
            Self::Relay => "meshlake-relay",
        }
    }
}

#[derive(Args)]
pub(crate) struct ServiceArgs {
    #[arg(value_enum)]
    kind: ServiceKind,
    /// Native arguments after --; use -- --help to inspect the installed service's options.
    #[arg(last = true, allow_hyphen_values = true)]
    arguments: Vec<OsString>,
}

fn sibling(binary: &str) -> Result<PathBuf> {
    let current = std::env::current_exe().context("cannot locate CLI executable")?;
    let directory = current
        .parent()
        .context("CLI executable has no parent directory")?;
    let filename = format!("{binary}{}", std::env::consts::EXE_SUFFIX);
    let path = directory.join(filename);
    anyhow::ensure!(
        path.is_file(),
        "matching service executable is missing beside the CLI: {}",
        path.display()
    );
    Ok(path)
}

async fn execute(binary: &str, args: Vec<OsString>, json: bool) -> Result<()> {
    let path = sibling(binary)?;
    if json {
        let output = tokio::task::spawn_blocking(move || {
            std::process::Command::new(path)
                .args(args)
                .stdin(Stdio::inherit())
                .output()
        })
        .await
        .context("service process worker failed")?
        .context("could not execute matching service")?;
        let code = output.status.code().unwrap_or(1);
        println!(
            "{}",
            serde_json::json!({"ok":output.status.success(),"exit_code":code,
            "stdout":String::from_utf8_lossy(&output.stdout),"stderr":String::from_utf8_lossy(&output.stderr)})
        );
        if !output.status.success() {
            std::process::exit(code);
        }
        return Ok(());
    }
    let status = tokio::task::spawn_blocking(move || {
        std::process::Command::new(path)
            .args(args)
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .status()
    })
    .await
    .context("service process worker failed")?
    .context("could not execute the matching MeshLake service")?;
    if !status.success() {
        std::process::exit(status.code().unwrap_or(1));
    }
    Ok(())
}

pub(crate) async fn daemon(options: DaemonArgs, operation: &str, json: bool) -> Result<()> {
    anyhow::ensure!(
        !json || operation != "run",
        "foreground services stream native output; omit --json"
    );
    let mut args = options.arguments();
    args.push(operation.into());
    execute("meshlaked", args, json).await
}
pub(crate) async fn state(command: StateArgs, json: bool) -> Result<()> {
    let mut args = command.options.arguments();
    args.extend(match command.command {
        StateCommand::Backup(args) => args.arguments("backup"),
        StateCommand::Restore(args) => args.arguments("restore"),
        StateCommand::RepairInvalidNetworks { yes: _ } => vec![
            "state".into(),
            "repair-invalid-networks".into(),
            "--yes".into(),
        ],
    });
    execute("meshlaked", args, json).await
}
pub(crate) async fn controller_state(command: ControllerStateArgs, json: bool) -> Result<()> {
    let options = DaemonArgs {
        state_file: command.state_file,
        state_key_file: command.state_key_file,
        state_key_systemd_credential: command.state_key_systemd_credential,
        allow_plaintext_state_migration: command.allow_plaintext_state_migration,
        wintun_dll: None,
    };
    let mut args = options.arguments();
    args.extend(command.command.arguments());
    execute("meshlake-controller", args, json).await
}
pub(crate) async fn autostart(command: AutostartArgs, json: bool) -> Result<()> {
    let mut args = command.options.arguments();
    args.extend([
        "autostart".into(),
        match command.command {
            AutostartCommand::Install => "install",
            AutostartCommand::Status => "status",
            AutostartCommand::Uninstall => "uninstall",
        }
        .into(),
    ]);
    execute("meshlaked", args, json).await
}
pub(crate) async fn service(command: ServiceArgs, json: bool) -> Result<()> {
    anyhow::ensure!(
        !json,
        "native service commands own their output format; omit --json"
    );
    execute(command.kind.binary(), command.arguments, false).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn backup_keeps_spaces_unicode_and_shell_characters_as_literal_arguments() {
        let cli = crate::Cli::try_parse_from([
            "meshlake",
            "state",
            "--state-file",
            "C:/状态目录/a & b.json",
            "backup",
            "C:/备份/$file.bin",
            "--password-stdin",
            "--force",
        ])
        .unwrap();
        let crate::Command::State(command) = cli.command else {
            panic!()
        };
        assert_eq!(
            command.options.arguments(),
            vec![
                OsString::from("--state-file"),
                "C:/状态目录/a & b.json".into()
            ]
        );
        let StateCommand::Backup(backup) = command.command else {
            panic!()
        };
        assert_eq!(
            backup.arguments("backup"),
            [
                "state",
                "backup",
                "C:/备份/$file.bin",
                "--password-stdin",
                "--force"
            ]
            .map(OsString::from)
        );
    }

    #[test]
    fn repair_requires_acknowledgement_and_controller_rejects_agent_only_repair() {
        assert!(
            crate::Cli::try_parse_from(["meshlake", "state", "repair-invalid-networks"]).is_err()
        );
        assert!(crate::Cli::try_parse_from([
            "meshlake",
            "state",
            "repair-invalid-networks",
            "--yes"
        ])
        .is_ok());
        assert!(crate::Cli::try_parse_from([
            "meshlake",
            "controller",
            "state",
            "repair-invalid-networks",
            "--yes"
        ])
        .is_err());
    }

    #[test]
    fn native_help_and_service_options_are_forwarded_unchanged() {
        let cli =
            crate::Cli::try_parse_from(["meshlake", "service", "relay", "--", "--help"]).unwrap();
        let crate::Command::Service(command) = cli.command else {
            panic!()
        };
        assert_eq!(command.kind.binary(), "meshlake-relay");
        assert_eq!(command.arguments, [OsString::from("--help")]);
    }
}
