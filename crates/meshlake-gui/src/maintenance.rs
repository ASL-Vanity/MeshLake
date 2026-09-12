use super::*;
use std::{
    io::{Read, Write},
    process::Stdio,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Instant,
};

#[derive(Default)]
pub(super) struct MaintenanceFields {
    pub controller_state: bool,
    pub state_file: String,
    state_key_file: String,
    state_key_credential: String,
    wintun_dll: String,
    allow_migration: bool,
    pub path: String,
    password: String,
    repeat: String,
    pub overwrite: bool,
}

impl MaintenanceFields {
    fn native_options(&self, controller: bool) -> Result<Vec<String>, String> {
        if !self.state_key_file.trim().is_empty() && !self.state_key_credential.trim().is_empty() {
            return Err("密钥文件与 systemd 凭据只能选择一项。 / Choose either a key file or a systemd credential.".into());
        }
        let mut args = Vec::new();
        for (flag, value) in [
            ("--state-file", &self.state_file),
            ("--state-key-file", &self.state_key_file),
            ("--state-key-systemd-credential", &self.state_key_credential),
        ] {
            if !value.trim().is_empty() {
                args.extend([flag.into(), value.trim().into()]);
            }
        }
        if self.allow_migration {
            args.push("--allow-plaintext-state-migration".into());
        }
        if !controller && !self.wintun_dll.trim().is_empty() {
            args.extend(["--wintun-dll".into(), self.wintun_dll.trim().into()]);
        }
        Ok(args)
    }
}

fn backup_arguments(path: &str, restore: bool, overwrite: bool) -> Result<Vec<String>, String> {
    if path.trim().is_empty() {
        return Err("请选择备份文件路径。 / Choose a backup file path.".into());
    }
    let mut args = vec![
        "state".into(),
        if restore { "restore" } else { "backup" }.into(),
        path.trim().into(),
        "--password-stdin".into(),
    ];
    if overwrite {
        args.push("--force".into());
    }
    Ok(args)
}

fn validate_password(password: &str, repeat: &str, restore: bool) -> Result<(), String> {
    if password.is_empty() || password.len() > 4096 || password.contains(['\r', '\n']) {
        return Err("密码不能为空、超过 4096 字节或包含换行。 / Password must be 1–4096 bytes without line breaks.".into());
    }
    if !restore && password != repeat {
        return Err("两次输入的密码不同。 / Passwords do not match.".into());
    }
    Ok(())
}

// Always drain child output, but retain at most 1 MiB per stream.
fn drain(mut stream: impl Read + Send + 'static) -> std::sync::mpsc::Receiver<Vec<u8>> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut output = Vec::new();
        let mut chunk = [0; 8192];
        loop {
            match stream.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let keep = n.min((1024 * 1024usize).saturating_sub(output.len()));
                    output.extend_from_slice(&chunk[..keep]);
                }
            }
        }
        let _ = tx.send(output);
    });
    rx
}

pub(super) fn execute_process(
    executable: &std::path::Path,
    args: &[String],
    mut input: Vec<u8>,
    cancel: Arc<AtomicBool>,
    timeout: Duration,
) -> Result<(bool, String), String> {
    let mut command = Command::new(executable);
    command
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000);
    }
    let spawned = command.spawn();
    let mut child = match spawned {
        Ok(child) => child,
        Err(error) => {
            input.fill(0);
            return Err(format!("无法启动程序 / Could not start process: {error}"));
        }
    };
    let stdout = drain(child.stdout.take().unwrap());
    let stderr = drain(child.stderr.take().unwrap());
    let input_result = child.stdin.take().unwrap().write_all(&input);
    input.fill(0);
    if let Err(error) = input_result {
        let _ = child.kill();
        let _ = child.wait();
        return Err(format!("无法传递输入 / Could not supply input: {error}"));
    }
    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error.to_string());
            }
            Ok(None) => {}
        }
        if cancel.load(Ordering::Relaxed) || Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err("操作已取消或超时；请核对目标文件/服务状态后重试。 / Cancelled or timed out; inspect target state before retrying.".into());
        }
        std::thread::sleep(Duration::from_millis(25));
    };
    let out = stdout
        .recv_timeout(Duration::from_secs(2))
        .unwrap_or_default();
    let err = stderr
        .recv_timeout(Duration::from_secs(2))
        .unwrap_or_default();
    Ok((
        status.success(),
        format!(
            "Exit: {}\n{}{}",
            status.code().unwrap_or(-1),
            String::from_utf8_lossy(&out),
            String::from_utf8_lossy(&err)
        ),
    ))
}

impl App {
    fn native_options_ui(&mut self, ui: &mut egui::Ui) {
        ui.collapsing(self.t("状态文件与运行参数", "State file and runtime options"), |ui| {
            ui.small(self.t("留空使用程序默认值。这些参数也用于下方客户端维护操作。", "Leave blank for native defaults. These options also apply to the agent maintenance actions below."));
            ui.label(self.t("状态文件路径（可选）", "State file path (optional)"));
            ui.add(design::input(&mut self.maintenance.state_file));
            let label = self.t("浏览…", "Browse…");
            file_picker::browse(ui, &mut self.maintenance.state_file, false, label, &mut self.message);
            ui.label(self.t("状态密钥文件（可选）", "State key file (optional)"));
            ui.add(design::input(&mut self.maintenance.state_key_file));
            file_picker::browse(ui, &mut self.maintenance.state_key_file, false, label, &mut self.message);
            ui.label(self.t("systemd 密钥凭据名称（Linux）", "systemd key credential name (Linux)"));
            ui.add(design::input(&mut self.maintenance.state_key_credential));
            let label = self.t("允许迁移旧明文状态", "Allow legacy plaintext state migration");
            ui.checkbox(&mut self.maintenance.allow_migration, label);
            if !self.maintenance.controller_state {
                ui.label(self.t("Wintun DLL 路径（Windows，可选）", "Wintun DLL path (Windows, optional)"));
                ui.add(design::input(&mut self.maintenance.wintun_dll));
                let label = self.t("浏览…", "Browse…");
                file_picker::browse(ui, &mut self.maintenance.wintun_dll, false, label, &mut self.message);
            }
        });
    }

    pub(super) fn agent_maintenance_ui(&mut self, ui: &mut egui::Ui) {
        design::card(ui, |ui| {
            ui.heading(self.t("客户端维护", "Agent maintenance"));
            #[cfg(target_os = "windows")]
            if !process_is_elevated() {
                ui.small(self.t("启动虚拟网卡或安装服务需要管理员权限。", "Starting a virtual adapter or installing a service requires administrator rights."));
                if ui
                    .button(self.t("以管理员权限重启界面", "Restart GUI as administrator"))
                    .clicked()
                {
                    match relaunch_with_administrator_rights() {
                        Ok(false) => exit_gui(),
                        Ok(true) => {}
                        Err(error) => self.message = error,
                    }
                }
            }
            ui.small(self.t("使用上方状态文件与运行参数。安装/卸载自启动和修复状态需要确认。", "Uses the state file and runtime options above. Autostart changes and state repair require confirmation."));
            ui.horizontal_wrapped(|ui| {
                for (zh, en, operation, confirm) in [
                    (
                        "查看自启动",
                        "Autostart status",
                        vec!["autostart", "status"],
                        false,
                    ),
                    (
                        "安装自启动",
                        "Install autostart",
                        vec!["autostart", "install"],
                        true,
                    ),
                    (
                        "卸载自启动",
                        "Uninstall autostart",
                        vec!["autostart", "uninstall"],
                        true,
                    ),
                    (
                        "查看状态路径",
                        "Show state path",
                        vec!["print-state-path"],
                        false,
                    ),
                    (
                        "修复无效网络记录",
                        "Repair invalid networks",
                        vec!["state", "repair-invalid-networks", "--yes"],
                        true,
                    ),
                ] {
                    if ui.button(self.t(zh, en)).clicked() {
                        match self.maintenance.native_options(false) {
                            Ok(mut args) => {
                                args.extend(operation.into_iter().map(str::to_owned));
                                if confirm {
                                    self.confirm_action(PendingAction::NativeTask {
                                        label: self.t(zh, en).into(),
                                        binary: "meshlaked".into(),
                                        args,
                                    });
                                } else {
                                    self.run_native_task("meshlaked".into(), args);
                                }
                            }
                            Err(error) => self.message = error,
                        }
                    }
                }
            });
        });
    }

    pub(super) fn run_native_task(&mut self, binary: String, args: Vec<String>) {
        if !self.can_start_action() {
            return;
        }
        let cancel = Arc::new(AtomicBool::new(false));
        self.process_cancel = Some(cancel.clone());
        self.start_job(move |app| {
            let path = std::env::current_exe().ok().and_then(|p| {
                p.parent()
                    .map(|dir| dir.join(format!("{binary}{}", std::env::consts::EXE_SUFFIX)))
            });
            let Some(path) = path else {
                app.message = "无法定位配套程序。 / Could not locate sibling executable.".into();
                return;
            };
            match execute_process(&path, &args, Vec::new(), cancel, Duration::from_secs(120)) {
                Ok((ok, output)) => {
                    app.cli_output = output;
                    app.message = if ok {
                        app.t("维护操作完成。", "Maintenance operation completed.")
                    } else {
                        app.t(
                            "维护操作失败，请查看结果。",
                            "Maintenance operation failed; inspect output.",
                        )
                    }
                    .into();
                }
                Err(error) => {
                    app.cli_output = error.clone();
                    app.message = error;
                }
            }
        });
    }

    pub(super) fn execute_backup(&mut self, restore: bool) {
        if !self.can_start_action() {
            return;
        }
        if let Err(error) = validate_password(
            &self.maintenance.password,
            &self.maintenance.repeat,
            restore,
        ) {
            self.message = error;
            return;
        }
        let backup_args =
            match backup_arguments(&self.maintenance.path, restore, self.maintenance.overwrite) {
                Ok(args) => args,
                Err(error) => {
                    self.message = error;
                    return;
                }
            };
        let controller = self.maintenance.controller_state;
        let mut args = match self.maintenance.native_options(controller) {
            Ok(args) => args,
            Err(error) => {
                self.message = error;
                return;
            }
        };
        args.extend(backup_args);
        let default_agent_state = !controller && self.maintenance.state_file.trim().is_empty();
        let mut input = std::mem::take(&mut self.maintenance.password).into_bytes();
        input.push(b'\n');
        self.maintenance.repeat.clear();
        let cancel = Arc::new(AtomicBool::new(false));
        self.process_cancel = Some(cancel.clone());
        self.start_job(move |worker| {
            // A listening local agent is an explicit restore blocker; never stop it implicitly.
            if restore
                && default_agent_state
                && TcpStream::connect_timeout(
                    &"127.0.0.1:51821".parse().unwrap(),
                    Duration::from_millis(200),
                )
                .is_ok()
            {
                input.fill(0);
                worker.message =
                    "后台仍在运行，请先通过维护页停止服务。 / Stop the agent before restoring."
                        .into();
                return;
            }
            let path = std::env::current_exe().ok().and_then(|p| {
                p.parent().map(|dir| {
                    dir.join(format!(
                        "{}{}",
                        if controller {
                            "meshlake-controller"
                        } else {
                            "meshlaked"
                        },
                        std::env::consts::EXE_SUFFIX
                    ))
                })
            });
            let Some(path) = path else {
                input.fill(0);
                worker.message = "无法定位后台程序。 / Agent executable not found.".into();
                return;
            };
            match execute_process(&path, &args, input, cancel, Duration::from_secs(120)) {
                Ok((success, output)) => {
                    worker.cli_output = output;
                    worker.message = if success {
                        "备份/恢复操作成功。 / Backup/restore succeeded."
                    } else {
                        "备份/恢复失败，请查看执行结果。 / Backup/restore failed; inspect output."
                    }
                    .into();
                }
                Err(error) => {
                    worker.cli_output = error.clone();
                    worker.message = error;
                }
            }
        });
    }

    pub(super) fn backup_ui(&mut self, ui: &mut egui::Ui) {
        design::card(ui, |ui| {
            ui.heading(self.t("状态备份与恢复", "State backup and restore"));
            ui.label(self.t("备份包含身份和网络配置，请保管密码。恢复前先停止对应服务。", "Backups contain identity and network configuration. Keep the password safe. Stop the matching service before restoring."));
            ui.horizontal(|ui| {
                let agent = self.t("客户端状态", "Agent state");
                let controller = self.t("控制器状态", "Controller state");
                ui.selectable_value(&mut self.maintenance.controller_state, false, agent);
                ui.selectable_value(&mut self.maintenance.controller_state, true, controller);
            });
            self.native_options_ui(ui);
            ui.label(self.t("备份文件路径", "Backup file path"));
            ui.add(design::input(&mut self.maintenance.path));
            ui.horizontal(|ui| {
                let open = self.t("选择已有备份…", "Open backup…");
                let save = self.t("选择保存位置…", "Choose destination…");
                file_picker::browse(
                    ui,
                    &mut self.maintenance.path,
                    false,
                    open,
                    &mut self.message,
                );
                file_picker::browse(
                    ui,
                    &mut self.maintenance.path,
                    true,
                    save,
                    &mut self.message,
                );
            });
            ui.label(self.t("密码", "Password"));
            ui.add(design::input(&mut self.maintenance.password).password(true));
            ui.label(self.t("再次输入密码（备份时）", "Confirm password (backup)"));
            ui.add(design::input(&mut self.maintenance.repeat).password(true));
            let overwrite = self.t(
                "允许覆盖现有目标文件",
                "Allow replacing the existing target file",
            );
            ui.checkbox(&mut self.maintenance.overwrite, overwrite);
            ui.horizontal(|ui| {
                if ui.button(self.t("加密备份", "Encrypted backup")).clicked() {
                    if self.maintenance.overwrite {
                        self.confirm_action(PendingAction::Backup(false));
                    } else {
                        self.execute_backup(false);
                    }
                }
                if ui.button(self.t("恢复状态", "Restore state")).clicked() {
                    self.confirm_action(PendingAction::Backup(true));
                }
            });
        });
        if !self.cli_output.is_empty() {
            ui.label(self.t("执行结果", "Execution result"));
            ui.add(
                egui::TextEdit::multiline(&mut self.cli_output)
                    .desired_rows(6)
                    .font(egui::TextStyle::Monospace)
                    .interactive(false),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn native_options_keep_paths_intact_and_reject_conflicting_key_sources() {
        let mut fields = MaintenanceFields {
            state_file: "C:\\Mesh Lake\\controller.json".into(),
            state_key_file: "C:\\Mesh Lake\\state.key".into(),
            wintun_dll: "C:\\Mesh Lake\\wintun.dll".into(),
            allow_migration: true,
            ..Default::default()
        };
        let controller = fields.native_options(true).unwrap();
        assert_eq!(
            controller,
            vec![
                "--state-file",
                "C:\\Mesh Lake\\controller.json",
                "--state-key-file",
                "C:\\Mesh Lake\\state.key",
                "--allow-plaintext-state-migration"
            ]
        );
        let agent = fields.native_options(false).unwrap();
        assert_eq!(&agent[5..], &["--wintun-dll", "C:\\Mesh Lake\\wintun.dll"]);
        fields.state_key_credential = "mesh-key".into();
        assert!(fields.native_options(true).is_err());
        fields.state_key_file.clear();
        assert!(fields
            .native_options(true)
            .unwrap()
            .contains(&"--state-key-systemd-credential".into()));
    }
    #[test]
    #[ignore = "child-process fixture; invoked explicitly by executor tests"]
    fn process_fixture() {
        let mut input = String::new();
        std::io::stdin().read_to_string(&mut input).unwrap();
        if input == "wait" {
            std::thread::sleep(Duration::from_secs(10));
        }
        assert_ne!(input, "fail", "deliberate test failure");
        println!("fixture completed");
    }
    fn fixture(input: &[u8], cancel: bool, timeout: Duration) -> Result<(bool, String), String> {
        let args = [
            "--ignored",
            "--exact",
            "maintenance::tests::process_fixture",
            "--nocapture",
        ]
        .map(str::to_owned);
        execute_process(
            &std::env::current_exe().unwrap(),
            &args,
            input.to_vec(),
            Arc::new(AtomicBool::new(cancel)),
            timeout,
        )
    }
    #[test]
    fn executor_closes_stdin_and_reports_nonzero_exit() {
        let (success, output) =
            fixture(b"test-only-password", false, Duration::from_secs(5)).unwrap();
        assert!(success);
        assert!(output.contains("fixture completed"));
        assert!(!output.contains("test-only-password"));
        assert!(!fixture(b"fail", false, Duration::from_secs(5)).unwrap().0);
    }
    #[test]
    fn executor_terminates_only_its_child_on_timeout_or_cancel() {
        assert!(fixture(b"wait", false, Duration::from_millis(100)).is_err());
        assert!(fixture(b"wait", true, Duration::from_secs(5)).is_err());
    }
    #[test]
    fn paths_with_spaces_are_one_argument_and_password_never_enters_argv() {
        let args = backup_arguments("C:\\My files\\backup.json", true, true).unwrap();
        assert_eq!(
            args,
            vec![
                "state",
                "restore",
                "C:\\My files\\backup.json",
                "--password-stdin",
                "--force"
            ]
        );
        assert!(backup_arguments(" ", false, false).is_err());
    }
    #[test]
    fn password_input_rejects_mismatch_empty_and_additional_lines() {
        assert!(validate_password("", "", false).is_err());
        assert!(validate_password("first", "second", false).is_err());
        assert!(validate_password("first\nsecond", "", true).is_err());
        assert!(validate_password("valid", "valid", false).is_ok());
        assert!(validate_password("valid", "", true).is_ok());
    }
}
