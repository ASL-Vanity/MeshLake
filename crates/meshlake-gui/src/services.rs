use super::*;
use std::{
    collections::{BTreeMap, BTreeSet},
    io::{Read, Seek, SeekFrom},
    process::Stdio,
    sync::mpsc::{self, Receiver, Sender, SyncSender, TryRecvError},
    time::Instant,
};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
enum Kind {
    #[default]
    Agent,
    Controller,
    Root,
    Relay,
}
impl Kind {
    fn binary(self) -> &'static str {
        match self {
            Self::Agent => "meshlaked",
            Self::Controller => "meshlake-controller",
            Self::Root => "meshlake-root",
            Self::Relay => "meshlake-relay",
        }
    }
    fn title(self) -> &'static str {
        match self {
            Self::Agent => "Agent",
            Self::Controller => "Controller",
            Self::Root => "Root",
            Self::Relay => "Relay",
        }
    }
}
#[derive(Clone, Copy)]
enum Input {
    Text,
    File,
    SaveFile,
    Lines,
    Socket,
    Number,
    Flag,
}
#[derive(Clone, Copy)]
struct Spec {
    flag: &'static str,
    zh: &'static str,
    en: &'static str,
    input: Input,
}
macro_rules! spec {
    ($f:literal,$z:literal,$e:literal,$i:ident) => {
        Spec {
            flag: $f,
            zh: $z,
            en: $e,
            input: Input::$i,
        }
    };
}
fn specs(kind: Kind) -> Vec<Spec> {
    let mut fields = Vec::new();
    if matches!(kind, Kind::Agent | Kind::Controller) {
        fields.extend([
            spec!("state-file", "状态文件", "State file", File),
            spec!(
                "state-key-file",
                "外部状态密钥文件（Linux）",
                "External state key file (Linux)",
                File
            ),
            spec!(
                "state-key-systemd-credential",
                "systemd 状态密钥凭据名称",
                "systemd state key credential name",
                Text
            ),
            spec!(
                "allow-plaintext-state-migration",
                "允许迁移旧明文状态",
                "Allow legacy plaintext state migration",
                Flag
            ),
        ]);
    }
    if kind == Kind::Agent {
        fields.push(spec!(
            "wintun-dll",
            "Wintun DLL 文件",
            "Wintun DLL file",
            File
        ));
    }
    if kind == Kind::Controller {
        fields.extend([
            spec!(
                "bind",
                "HTTP / HTTPS 监听地址",
                "HTTP / HTTPS listener",
                Socket
            ),
            spec!(
                "tls-certificate",
                "TLS 证书链 PEM",
                "TLS certificate chain PEM",
                File
            ),
            spec!(
                "tls-private-key",
                "TLS 私钥 PEM",
                "TLS private key PEM",
                File
            ),
            spec!(
                "tls-client-ca-certificate",
                "嵌入邀请的公共 CA PEM",
                "Public CA PEM embedded in invitations",
                File
            ),
            spec!(
                "allow-insecure-public-http",
                "允许公网明文 HTTP（仅隔离开发环境）",
                "Allow public plaintext HTTP (isolated development only)",
                Flag
            ),
            spec!(
                "initial-admin-token-file",
                "首次管理员令牌保存到新文件",
                "Save initial administrator token to a new file",
                SaveFile
            ),
            spec!(
                "planet-controller-url",
                "Planet 公布的控制器 URL",
                "Controller URL published by Planet",
                Text
            ),
            spec!(
                "planet-relay-endpoint",
                "UDP 中继地址（每行 IP:端口）",
                "UDP relays (one IP:port per line)",
                Lines
            ),
            spec!(
                "planet-relay-identity",
                "Relay 身份（每行 UUID@公钥@IP:端口，支持轮换格式）",
                "Relay identities (UUID@key@IP:port per line; rotation format supported)",
                Lines
            ),
            spec!(
                "planet-tls-relay",
                "TLS Relay（每行 UUID@IP:端口@服务器名@证书指纹）",
                "TLS relays (UUID@IP:port@server-name@certificate-pin per line)",
                Lines
            ),
            spec!(
                "planet-turn-server",
                "TURN（每行 udp/tcp@IP:端口，或 tls@IP:端口@服务器名@指纹）",
                "TURN (udp/tcp@IP:port or tls@IP:port@server-name@pin per line)",
                Lines
            ),
            spec!(
                "turn-static-auth-secret-file",
                "TURN REST 静态认证秘密文件",
                "TURN REST static authentication secret file",
                File
            ),
            spec!(
                "turn-credential-ttl-seconds",
                "TURN 凭据有效期（60–86400 秒）",
                "TURN credential lifetime (60–86400 seconds)",
                Number
            ),
            spec!(
                "planet-root",
                "Root 节点（每行 Base64公钥@IP:端口）",
                "Root nodes (Base64-key@IP:port per line)",
                Lines
            ),
            spec!(
                "planet-root-identity",
                "Root 身份（每行 UUID@公钥@IP:端口，支持轮换格式）",
                "Root identities (UUID@key@IP:port per line; rotation format supported)",
                Lines
            ),
            spec!(
                "planet-stun",
                "STUN 服务器（每行一个）",
                "STUN servers (one per line)",
                Lines
            ),
        ]);
    }
    if matches!(kind, Kind::Root | Kind::Relay) {
        fields.extend([
            spec!("bind", "UDP 监听地址", "UDP listener", Socket),
            spec!(
                "identity-file",
                "服务身份文件",
                "Service identity file",
                File
            ),
            spec!(
                "transition-identity-file",
                "轮换到的新身份文件",
                "Next identity file for rotation",
                File
            ),
            spec!(
                "allow-legacy-registration",
                "允许旧版注册（协议迁移期间）",
                "Allow legacy registration during protocol migration",
                Flag
            ),
        ]);
    }
    if kind == Kind::Root {
        fields.extend([
            spec!(
                "config",
                "Root JSON 配置文件",
                "Root JSON configuration file",
                File
            ),
            spec!(
                "controller-public-key-base64",
                "可信控制器公钥（每行一个 Base64）",
                "Trusted controller keys (one Base64 key per line)",
                Lines
            ),
            spec!(
                "peer-ttl-seconds",
                "节点过期时间（秒）",
                "Peer expiry (seconds)",
                Number
            ),
            spec!(
                "maximum-clock-skew-seconds",
                "最大时钟偏差（秒）",
                "Maximum clock skew (seconds)",
                Number
            ),
            spec!(
                "write-config",
                "配置导出文件",
                "Configuration export file",
                SaveFile
            ),
        ]);
    }
    if kind == Kind::Relay {
        fields.extend([
            spec!(
                "controller-public-key-base64",
                "可信控制器公钥（Base64，必填）",
                "Trusted controller key (Base64, required)",
                Text
            ),
            spec!(
                "tcp-bind",
                "TCP 监听地址（可选）",
                "TCP listener (optional)",
                Socket
            ),
            spec!(
                "tcp-tls-bind",
                "TLS TCP 监听地址（可选）",
                "TLS TCP listener (optional)",
                Socket
            ),
            spec!(
                "tcp-tls-certificate",
                "TLS TCP 证书链 PEM",
                "TLS TCP certificate chain PEM",
                File
            ),
            spec!(
                "tcp-tls-private-key",
                "TLS TCP 私钥 PEM",
                "TLS TCP private key PEM",
                File
            ),
        ]);
    }
    fields
}

#[derive(Default)]
struct Form {
    kind: Kind,
    values: BTreeMap<String, String>,
    flags: BTreeSet<String>,
}
impl Form {
    fn value(&self, flag: &str) -> &str {
        self.values.get(flag).map(|s| s.trim()).unwrap_or("")
    }
    fn arguments(&self, operation: &str) -> Result<Vec<String>, String> {
        if matches!(operation, "--help" | "--version") {
            return Ok(vec![operation.into()]);
        }
        if !self.value("state-key-file").is_empty()
            && !self.value("state-key-systemd-credential").is_empty()
        {
            return Err("密钥来源冲突 / Conflicting state key sources".into());
        }
        if self.kind == Kind::Relay && self.value("controller-public-key-base64").is_empty() {
            return Err("请填写可信控制器公钥 / Trusted controller key is required".into());
        }
        for (a, b) in if self.kind == Kind::Controller {
            vec![("tls-certificate", "tls-private-key")]
        } else {
            vec![]
        } {
            if self.value(a).is_empty() != self.value(b).is_empty() {
                return Err(
                    "TLS 证书和私钥必须成对提供 / Supply both TLS certificate and private key"
                        .into(),
                );
            }
        }
        if self.kind == Kind::Relay
            && !self.value("tcp-tls-bind").is_empty()
            && (self.value("tcp-tls-certificate").is_empty()
                || self.value("tcp-tls-private-key").is_empty())
        {
            return Err(
                "TLS 监听需要证书和私钥 / TLS listener requires certificate and private key".into(),
            );
        }
        if self.kind == Kind::Controller
            && !self.value("planet-turn-server").is_empty()
            && self.value("turn-static-auth-secret-file").is_empty()
        {
            return Err("TURN 节点需要静态认证秘密文件 / TURN servers require an authentication secret file".into());
        }
        if operation == "write-config" && self.value("write-config").is_empty() {
            return Err("请选择配置导出路径 / Choose a configuration export path".into());
        }
        let mut args = Vec::new();
        for spec in specs(self.kind) {
            if spec.flag == "write-config" && operation != "write-config" {
                continue;
            }
            if matches!(spec.input, Input::Flag) {
                if self.flags.contains(spec.flag) {
                    args.push(format!("--{}", spec.flag));
                }
                continue;
            }
            let value = self.value(spec.flag);
            if value.is_empty() {
                continue;
            }
            if matches!(spec.input, Input::Socket) && value.parse::<std::net::SocketAddr>().is_err()
            {
                return Err(format!("{}: IP:port 无效 / Invalid IP:port", spec.flag));
            }
            if matches!(spec.input, Input::Number) {
                let n = value.parse::<u64>().map_err(|_| {
                    format!("{}: 请输入非负整数 / Enter an unsigned integer", spec.flag)
                })?;
                if spec.flag == "turn-credential-ttl-seconds" && !(60..=86400).contains(&n) {
                    return Err(
                        "TURN 有效期必须为 60–86400 秒 / TURN lifetime must be 60–86400 seconds"
                            .into(),
                    );
                }
            }
            let values = if matches!(spec.input, Input::Lines) {
                value
                    .lines()
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .collect::<Vec<_>>()
            } else {
                vec![value]
            };
            for value in values {
                args.extend([format!("--{}", spec.flag), value.into()]);
            }
        }
        match operation {
            "run" => {
                if matches!(self.kind, Kind::Agent | Kind::Root) {
                    args.push("run".into());
                }
            }
            "write-config" => {}
            "--print-identity" | "--print-public-key" => args.push(operation.into()),
            "autostart-status" | "autostart-install" | "autostart-uninstall" => args.extend([
                "autostart".into(),
                operation.trim_start_matches("autostart-").into(),
            ]),
            _ => return Err("未知服务操作 / Unknown service operation".into()),
        }
        Ok(args)
    }
}

#[derive(Debug)]
enum Event {
    Started(u32),
    Output(String),
    Exited(Option<i32>),
    Stopped,
    Error(String),
    Warning(String),
}
#[derive(Debug)]
enum Control {
    Stop,
}
struct Run {
    id: Uuid,
    binary: String,
    path: PathBuf,
    pid: Option<u32>,
    status: String,
    running: bool,
    output: String,
    receiver: Receiver<Event>,
    control: Sender<Control>,
}
#[derive(Default)]
pub(super) struct Services {
    form: Form,
    saved_forms: BTreeMap<Kind, Form>,
    runs: Vec<Run>,
}

impl Services {
    fn select(&mut self, kind: Kind) {
        if self.form.kind == kind {
            return;
        }
        let next = self.saved_forms.remove(&kind).unwrap_or_else(|| Form {
            kind,
            ..Default::default()
        });
        let previous = std::mem::replace(&mut self.form, next);
        self.saved_forms.insert(previous.kind, previous);
    }
}

fn tail(path: &std::path::Path) -> std::io::Result<String> {
    let mut file = fs::File::open(path)?;
    let length = file.metadata()?.len();
    file.seek(SeekFrom::Start(length.saturating_sub(64 * 1024)))?;
    let mut bytes = Vec::new();
    file.take(64 * 1024).read_to_end(&mut bytes)?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}
// The service inherits regular file handles, not GUI-owned pipes. Closing the GUI
// drops supervision but leaves the service and its output handles independently usable.
fn supervise(
    mut command: Command,
    path: PathBuf,
    events: SyncSender<Event>,
    control: Receiver<Control>,
) {
    let prepared = (|| -> Result<std::process::Child, String> {
        meshlake_core::create_restricted_secret_file(&path, b"").map_err(|_| {
            "无法创建受限服务日志 / Could not create restricted service log".to_owned()
        })?;
        let log = fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .map_err(|e| e.to_string())?;
        let error_log = log.try_clone().map_err(|e| e.to_string())?;
        command
            .stdin(Stdio::null())
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(error_log));
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            command.creation_flags(0x08000000);
        }
        command.spawn().map_err(|e| e.to_string())
    })();
    let mut child = match prepared {
        Ok(child) => child,
        Err(error) => {
            let _ = events.send(Event::Error(error));
            return;
        }
    };
    let _ = events.send(Event::Started(child.id()));
    let mut last = Instant::now() - Duration::from_secs(1);
    loop {
        match control.try_recv() {
            Ok(Control::Stop) => match child.kill().and_then(|_| child.wait()) {
                Ok(_) => {
                    if let Ok(output) = tail(&path) {
                        let _ = events.try_send(Event::Output(output));
                    }
                    let _ = events.send(Event::Stopped);
                    return;
                }
                Err(error) => {
                    let _ = events.try_send(Event::Warning(format!(
                        "终止失败，请检查进程状态 / Termination failed: {error}"
                    )));
                }
            },
            Err(TryRecvError::Disconnected) => return,
            Err(TryRecvError::Empty) => {}
        }
        match child.try_wait() {
            Ok(Some(status)) => {
                if let Ok(output) = tail(&path) {
                    let _ = events.send(Event::Output(output));
                }
                let _ = events.send(Event::Exited(status.code()));
                return;
            }
            Err(error) => {
                let _ = events.try_send(Event::Warning(error.to_string()));
            }
            Ok(None) => {}
        }
        if last.elapsed() >= Duration::from_millis(500) {
            if let Ok(output) = tail(&path) {
                let _ = events.try_send(Event::Output(output));
            }
            last = Instant::now();
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

impl App {
    pub(super) fn launch_service(&mut self, binary: String, args: Vec<String>) {
        if ![
            "meshlaked",
            "meshlake-controller",
            "meshlake-root",
            "meshlake-relay",
        ]
        .contains(&binary.as_str())
        {
            self.message = "未知服务 / Unknown service".into();
            return;
        }
        let Some(executable) = std::env::current_exe().ok().and_then(|p| {
            p.parent()
                .map(|d| d.join(format!("{binary}{}", std::env::consts::EXE_SUFFIX)))
        }) else {
            self.message = "无法定位服务程序 / Could not locate service executable".into();
            return;
        };
        if !executable.is_file() {
            self.message = format!(
                "配套程序不存在 / Missing sibling executable: {}",
                executable.display()
            );
            return;
        }
        let directory = settings_path().with_file_name("gui-runs");
        if fs::create_dir_all(&directory).is_err() {
            self.message = "无法创建服务日志目录 / Could not create service log directory".into();
            return;
        }
        let id = Uuid::new_v4();
        let path = directory.join(format!("{binary}-{id}.log"));
        let mut command = Command::new(executable);
        command.args(args);
        let (tx, rx) = mpsc::sync_channel(8);
        let (control_tx, control_rx) = mpsc::channel();
        let thread_path = path.clone();
        std::thread::spawn(move || supervise(command, thread_path, tx, control_rx));
        self.services.runs.push(Run {
            id,
            binary,
            path,
            pid: None,
            status: self.t("启动中", "Starting").into(),
            running: true,
            output: String::new(),
            receiver: rx,
            control: control_tx,
        });
        self.message = self
            .t(
                "启动请求已提交，请查看服务进程状态。",
                "Launch requested. Check the service process status.",
            )
            .into();
    }
    pub(super) fn stop_owned_service(&mut self, id: Uuid) {
        if let Some(run) = self
            .services
            .runs
            .iter_mut()
            .find(|r| r.id == id && r.running)
        {
            if run.control.send(Control::Stop).is_ok() {
                run.status = "正在终止 / Stopping".into();
            } else {
                self.message =
                    "监控线程已结束，请检查进程状态 / Monitor ended; inspect process state".into();
            }
        }
    }
    pub(super) fn poll_services(&mut self, context: &egui::Context) {
        let zh = self.settings.language == Language::Chinese;
        for run in &mut self.services.runs {
            while let Ok(event) = run.receiver.try_recv() {
                match event {
                    Event::Started(pid) => {
                        run.pid = Some(pid);
                        run.status = if zh {
                            "进程运行中（不代表服务健康）"
                        } else {
                            "Process running (health unverified)"
                        }
                        .into();
                    }
                    Event::Output(output) => run.output = output,
                    Event::Exited(code) => {
                        run.running = false;
                        run.status = format!(
                            "{} {}",
                            if zh {
                                "已退出，退出码"
                            } else {
                                "Exited with code"
                            },
                            code.map(|c| c.to_string())
                                .unwrap_or_else(|| "unknown".into())
                        );
                    }
                    Event::Stopped => {
                        run.running = false;
                        run.status = if zh {
                            "本次启动进程已终止"
                        } else {
                            "Owned process terminated"
                        }
                        .into();
                    }
                    Event::Error(error) => {
                        run.running = false;
                        run.status = error;
                    }
                    Event::Warning(error) => run.status = error,
                }
            }
            if run.running {
                context.request_repaint_after(Duration::from_millis(500));
            }
        }
    }
    pub(super) fn services_panel(&mut self, ui: &mut egui::Ui) {
        design::card(ui, |ui| {
            ui.heading(self.t("本机服务", "Local services"));
            ui.label(self.t("选择服务并填写运行参数；留空使用原生默认值。启动服务不会阻塞其他页面，退出界面不会停止服务。", "Select a service and configure its options; blank uses native defaults. Services run independently of navigation and GUI lifetime."));
            ui.horizontal_wrapped(|ui| {
                for kind in [Kind::Agent, Kind::Controller, Kind::Root, Kind::Relay] {
                    if ui
                        .selectable_label(self.services.form.kind == kind, kind.title())
                        .clicked()
                    {
                        self.services.select(kind);
                    }
                }
            });
            let kind = self.services.form.kind;
            ui.collapsing(self.t("启动参数", "Startup options"),|ui| {
                for spec in specs(kind) {
                    ui.push_id(spec.flag,|ui| {
                        let label=self.t(spec.zh,spec.en);
                        if matches!(spec.input,Input::Flag) {
                            let mut enabled=self.services.form.flags.contains(spec.flag);
                            if ui.checkbox(&mut enabled,label).changed() {if enabled {self.services.form.flags.insert(spec.flag.into());} else {self.services.form.flags.remove(spec.flag);}}
                        } else {
                            ui.label(label);
                            let value=self.services.form.values.entry(spec.flag.into()).or_default();
                            if matches!(spec.input,Input::Lines) {ui.add(egui::TextEdit::multiline(value).desired_rows(2).desired_width(f32::INFINITY));}
                            else {ui.add(design::input(value).desired_width(f32::INFINITY));}
                            if matches!(spec.input,Input::File|Input::SaveFile) {
                                let label=if self.settings.language==Language::Chinese {"浏览…"} else {"Browse…"};
                                file_picker::browse(ui,value,matches!(spec.input,Input::SaveFile),label,&mut self.message);
                            }
                        }
                    });
                }
                if kind==Kind::Controller {ui.small(self.t("首次管理员凭据通过新文件交付；图形界面不要求交互式终端。", "Initial administrator credentials are delivered to a new file; no interactive terminal is required."));}
            });
            ui.horizontal_wrapped(|ui| {
                for (zh, en, operation) in [
                    ("启动服务", "Start service", "run"),
                    ("查看帮助", "Show help", "--help"),
                ] {
                    if ui.button(self.t(zh, en)).clicked() {
                        self.service_operation(operation);
                    }
                }
                if matches!(kind, Kind::Root | Kind::Relay)
                    && ui
                        .button(self.t("查看公共身份", "Show public identity"))
                        .clicked()
                {
                    self.service_operation("--print-identity");
                }
                if kind == Kind::Root {
                    if ui.button(self.t("查看公钥", "Show public key")).clicked() {
                        self.service_operation("--print-public-key");
                    }
                    if ui
                        .button(self.t("导出配置", "Export configuration"))
                        .clicked()
                    {
                        self.service_operation("write-config");
                    }
                }
                if ui
                    .button(self.t("正常停止本机 Agent", "Gracefully stop local agent"))
                    .clicked()
                {
                    self.confirm_action(PendingAction::StopAgent);
                }
            });
            if matches!(kind, Kind::Agent | Kind::Root) {
                ui.horizontal_wrapped(|ui| {
                    for (zh, en, operation) in [
                        ("自启动状态", "Autostart status", "autostart-status"),
                        ("安装自启动", "Install autostart", "autostart-install"),
                        ("卸载自启动", "Uninstall autostart", "autostart-uninstall"),
                    ] {
                        if ui.button(self.t(zh, en)).clicked() {
                            self.service_operation(operation);
                        }
                    }
                });
            }
        });
        let mut stop = None;
        for run in &mut self.services.runs {
            ui.push_id(run.id, |ui| {
                design::card(ui, |ui| {
                    ui.strong(format!(
                        "{} · PID {}",
                        run.binary,
                        run.pid.map(|p| p.to_string()).unwrap_or_else(|| "—".into())
                    ));
                    ui.label(&run.status);
                    ui.small(run.path.display().to_string());
                    if run.running
                        && ui
                            .button(if self.settings.language == Language::Chinese {
                                "终止本次启动进程"
                            } else {
                                "Terminate owned process"
                            })
                            .clicked()
                    {
                        stop = Some(run.id);
                    }
                    ui.collapsing(
                        if self.settings.language == Language::Chinese {
                            "最近输出（最多 64 KiB）"
                        } else {
                            "Recent output (up to 64 KiB)"
                        },
                        |ui| {
                            ui.add(
                                egui::TextEdit::multiline(&mut run.output)
                                    .interactive(false)
                                    .desired_rows(8)
                                    .desired_width(f32::INFINITY)
                                    .font(egui::TextStyle::Monospace),
                            );
                        },
                    );
                });
            });
        }
        if let Some(id) = stop {
            self.confirm_action(PendingAction::StopService(id));
        }
    }
    fn service_operation(&mut self, operation: &str) {
        match self.services.form.arguments(operation) {
            Ok(args) => {
                let binary = self.services.form.kind.binary().to_owned();
                if matches!(operation, "--help" | "--version" | "autostart-status") {
                    self.launch_service(binary, args);
                } else {
                    self.confirm_action(PendingAction::StartService { binary, args });
                }
            }
            Err(error) => self.message = error,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn switching_services_retains_each_unsubmitted_form() {
        let mut services = Services::default();
        services
            .form
            .values
            .insert("state-file".into(), "agent-custom.json".into());
        services.select(Kind::Controller);
        services.form.values.insert(
            "planet-controller-url".into(),
            "https://controller.example".into(),
        );
        services.select(Kind::Agent);
        assert_eq!(services.form.value("state-file"), "agent-custom.json");
        services.select(Kind::Controller);
        assert_eq!(
            services.form.value("planet-controller-url"),
            "https://controller.example"
        );
    }

    #[test]
    #[ignore = "explicit native acceptance; requires MESHLAKE_GUI_NATIVE_DIR"]
    fn native_service_option_schema_matches_installed_help() {
        let directory = PathBuf::from(
            std::env::var_os("MESHLAKE_GUI_NATIVE_DIR")
                .expect("set reviewed local native build directory"),
        );
        assert!(directory.is_absolute());
        for kind in [Kind::Agent, Kind::Controller, Kind::Root, Kind::Relay] {
            let binary =
                directory.join(format!("{}{}", kind.binary(), std::env::consts::EXE_SUFFIX));
            let (ok, output) = maintenance::execute_process(
                &binary,
                &["--help".into()],
                Vec::new(),
                std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
                Duration::from_secs(5),
            )
            .unwrap();
            assert!(ok, "{} help failed: {output}", kind.binary());
            let actual = output
                .lines()
                .filter_map(|line| {
                    if !line.starts_with(' ') {
                        return None;
                    }
                    let flag = line
                        .split_whitespace()
                        .find(|part| part.starts_with("--"))?;
                    if flag.starts_with("--help") {
                        return None;
                    }
                    Some(flag.trim_start_matches("--").to_owned())
                })
                .collect::<BTreeSet<_>>();
            let mut represented = specs(kind)
                .iter()
                .map(|s| s.flag.to_owned())
                .collect::<BTreeSet<_>>();
            match kind {
                Kind::Controller => {
                    // The terminal-only credential claim is delivered through a restricted file in the GUI.
                    represented.insert("claim-initial-admin-token".into());
                }
                Kind::Root => {
                    represented.insert("print-public-key".into());
                    represented.insert("print-identity".into());
                }
                Kind::Relay => {
                    represented.insert("print-identity".into());
                }
                Kind::Agent => {}
            }
            assert_eq!(
                represented,
                actual,
                "{} native options drifted from the form",
                kind.binary()
            );
            println!(
                "{}: {} native options represented by forms/actions",
                kind.binary(),
                actual.len()
            );
        }
    }
    #[test]
    #[ignore = "owned child fixture; invoked explicitly by service lifecycle tests"]
    fn process_fixture() {
        use std::io::Write;
        let millis = std::env::var("MESHLAKE_GUI_FIXTURE_MS")
            .unwrap()
            .parse::<u64>()
            .unwrap();
        println!("fixture-started");
        std::io::stdout().flush().unwrap();
        std::thread::sleep(Duration::from_millis(millis));
        println!("fixture-completed");
    }
    struct Harness {
        directory: PathBuf,
        path: PathBuf,
        receiver: Receiver<Event>,
        control: Option<Sender<Control>>,
        thread: Option<std::thread::JoinHandle<()>>,
    }
    impl Harness {
        fn new(millis: u64) -> Self {
            let directory =
                std::env::temp_dir().join(format!("meshlake-gui-service-test-{}", Uuid::new_v4()));
            fs::create_dir(&directory).unwrap();
            let path = directory.join("process.log");
            let mut command = Command::new(std::env::current_exe().unwrap());
            command
                .args([
                    "--ignored",
                    "--exact",
                    "services::tests::process_fixture",
                    "--nocapture",
                ])
                .env("MESHLAKE_GUI_FIXTURE_MS", millis.to_string());
            let (tx, receiver) = mpsc::sync_channel(8);
            let (control, rx) = mpsc::channel();
            let log = path.clone();
            let thread = std::thread::spawn(move || supervise(command, log, tx, rx));
            Self {
                directory,
                path,
                receiver,
                control: Some(control),
                thread: Some(thread),
            }
        }
        fn until(&self, predicate: impl Fn(&Event) -> bool) -> Event {
            let deadline = Instant::now() + Duration::from_secs(6);
            loop {
                let event = self
                    .receiver
                    .recv_timeout(deadline.saturating_duration_since(Instant::now()))
                    .expect("service lifecycle event deadline");
                assert!(
                    !matches!(event, Event::Error(_) | Event::Warning(_)),
                    "{event:?}"
                );
                if predicate(&event) {
                    return event;
                }
            }
        }
    }
    impl Drop for Harness {
        fn drop(&mut self) {
            if let Some(control) = self.control.take() {
                let _ = control.send(Control::Stop);
            }
            // Drain the bounded event queue while the worker finishes.
            if let Some(thread) = self.thread.take() {
                while !thread.is_finished() {
                    let _ = self.receiver.recv_timeout(Duration::from_millis(50));
                }
                let _ = thread.join();
            }
            let _ = fs::remove_dir_all(&self.directory);
        }
    }
    #[test]
    fn live_output_and_stop_target_only_the_selected_owned_process() {
        let first = Harness::new(2500);
        let second = Harness::new(1400);
        let a = first.until(|e| matches!(e, Event::Started(_)));
        let b = second.until(|e| matches!(e, Event::Started(_)));
        if let (Event::Started(a), Event::Started(b)) = (a, b) {
            assert_ne!(a, b);
        }
        first.until(|e| matches!(e,Event::Output(s) if s.contains("fixture-started")));
        first.control.as_ref().unwrap().send(Control::Stop).unwrap();
        first.until(|e| matches!(e, Event::Stopped));
        second.until(|e| matches!(e, Event::Exited(Some(0))));
        assert!(!tail(&first.path).unwrap().contains("fixture-completed"));
        assert!(tail(&second.path).unwrap().contains("fixture-completed"));
    }
    #[test]
    fn dropping_supervision_leaves_service_output_and_lifetime_independent() {
        let mut fixture = Harness::new(350);
        fixture.until(|e| matches!(e, Event::Started(_)));
        drop(fixture.control.take());
        fixture.thread.take().unwrap().join().unwrap();
        let deadline = Instant::now() + Duration::from_secs(4);
        loop {
            if tail(&fixture.path).unwrap().contains("fixture-completed") {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "detached process did not complete"
            );
            std::thread::sleep(Duration::from_millis(25));
        }
    }
    #[test]
    fn service_output_tail_is_bounded_and_keeps_recent_bytes() {
        let path = std::env::temp_dir().join(format!("meshlake-tail-{}", Uuid::new_v4()));
        let mut data = vec![b'x'; 100_000];
        data.extend_from_slice(b"last line");
        fs::write(&path, data).unwrap();
        let output = tail(&path).unwrap();
        fs::remove_file(path).unwrap();
        assert_eq!(output.len(), 64 * 1024);
        assert!(output.ends_with("last line"));
    }
    #[test]
    fn form_builds_native_arguments_without_splitting_paths_and_preserves_repeat_order() {
        let mut form = Form {
            kind: Kind::Controller,
            ..Default::default()
        };
        form.values
            .insert("state-file".into(), r"C:\Mesh Lake\controller.json".into());
        form.values.insert(
            "planet-stun".into(),
            "one.example:3478\ntwo.example:3478".into(),
        );
        let args = form.arguments("run").unwrap();
        assert_eq!(
            args,
            vec![
                "--state-file",
                r"C:\Mesh Lake\controller.json",
                "--planet-stun",
                "one.example:3478",
                "--planet-stun",
                "two.example:3478"
            ]
        );
        form.values.insert("state-key-file".into(), "key".into());
        form.values
            .insert("state-key-systemd-credential".into(), "credential".into());
        assert!(form.arguments("run").is_err());
        assert_eq!(form.arguments("--help").unwrap(), vec!["--help"]);
    }
    #[test]
    fn validates_tls_and_turn_dependencies_and_does_not_export_config_during_run() {
        let mut form = Form {
            kind: Kind::Controller,
            ..Default::default()
        };
        form.values
            .insert("tls-certificate".into(), "cert.pem".into());
        assert!(form.arguments("run").is_err());
        form.values
            .insert("tls-private-key".into(), "key.pem".into());
        assert!(form.arguments("run").is_ok());
        form.values
            .insert("planet-turn-server".into(), "udp@127.0.0.1:3478".into());
        assert!(form.arguments("run").is_err());
        let mut root = Form {
            kind: Kind::Root,
            ..Default::default()
        };
        root.values
            .insert("write-config".into(), "root.json".into());
        assert_eq!(root.arguments("run").unwrap(), vec!["run"]);
        assert_eq!(
            root.arguments("write-config").unwrap(),
            vec!["--write-config", "root.json"]
        );
        root.values.insert("bind".into(), "invalid".into());
        assert!(root.arguments("run").is_err());
    }
}
