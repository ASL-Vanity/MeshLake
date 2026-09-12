#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

//! Native Windows UI. All persistent state and networking remain in `meshlaked`.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use eframe::egui;
use meshlake_core::{
    decode_protected_state, AgentStatus, EnrollmentResponse, MembershipClaims, RelayPolicy,
    SessionList, UpsertNetworkRequest, VirtualNetwork, CONTROLLER_STATE_PROTECTION_PURPOSE,
};
use reqwest::{blocking::Client, Certificate};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{fs, net::TcpStream, path::PathBuf, process::Command, time::Duration};
use tray_icon::{
    menu::{Menu, MenuEvent, MenuItem},
    Icon, TrayIcon, TrayIconBuilder,
};
use url::Url;
use uuid::Uuid;
#[cfg(target_os = "windows")]
use windows_sys::Win32::{
    Foundation::CloseHandle,
    Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY},
    System::Threading::{GetCurrentProcess, OpenProcessToken},
    UI::{Shell::ShellExecuteW, WindowsAndMessaging::SW_SHOWNORMAL},
};

const LOCAL_API: &str = "http://127.0.0.1:51821/v1";

fn exit_selection_body(
    ipv4: &str,
    ipv6: &str,
    kill_switch: bool,
) -> Result<serde_json::Value, String> {
    fn optional_id(value: &str) -> Result<Option<Uuid>, String> {
        if value.trim().is_empty() {
            return Ok(None);
        }
        Uuid::parse_str(value.trim())
            .map(Some)
            .map_err(|_| "网关设备 ID 必须是 UUID。".into())
    }
    Ok(
        json!({"ipv4_gateway": optional_id(ipv4)?, "ipv6_gateway": optional_id(ipv6)?, "kill_switch": kill_switch}),
    )
}

fn local_action_result(
    result: Result<reqwest::blocking::Response, reqwest::Error>,
    success: &str,
    language: Language,
) -> String {
    match result {
        Ok(response) if response.status().is_success() => success.into(),
        Ok(response) => format!(
            "{} HTTP {}",
            if language == Language::Chinese {
                "操作失败。"
            } else {
                "Operation failed."
            },
            response.status()
        ),
        Err(error) => format!(
            "{}: {error}",
            if language == Language::Chinese {
                "无法联系后台服务"
            } else {
                "Could not connect to the agent"
            }
        ),
    }
}

fn http_failure(response: reqwest::blocking::Response, operation: &str) -> String {
    // Error bodies can reflect submitted enrollment/admin credentials. Status is
    // sufficient to report the failure without copying untrusted secret-bearing text.
    format!("{operation} HTTP {}", response.status())
}

fn main() {
    if let Err(error) = run_gui() {
        write_startup_error(&format!("{error:#}"));
    }
}

fn write_startup_error(error: &str) {
    let path = settings_path().with_file_name("gui-startup-error.log");
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let _ = fs::write(path, error);
}

/// Elevation is an explicit maintenance action; opening the GUI never requires it.
#[cfg(target_os = "windows")]
fn relaunch_with_administrator_rights() -> Result<bool, String> {
    if process_is_elevated() {
        return Ok(true);
    }
    let executable = std::env::current_exe().map_err(|error| error.to_string())?;
    let parameters = std::env::args()
        .skip(1)
        .map(|argument| format!("\"{}\"", argument.replace('"', "\\\"")))
        .collect::<Vec<_>>()
        .join(" ");
    let operation: Vec<u16> = "runas\0".encode_utf16().collect();
    let executable: Vec<u16> = executable
        .as_os_str()
        .to_string_lossy()
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let parameters: Vec<u16> = parameters
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let result = unsafe {
        ShellExecuteW(
            std::ptr::null_mut(),
            operation.as_ptr(),
            executable.as_ptr(),
            parameters.as_ptr(),
            std::ptr::null(),
            SW_SHOWNORMAL,
        )
    };
    if (result as isize) <= 32 {
        Err("管理员权限请求被取消或被 Windows 拒绝。".into())
    } else {
        // The elevated child now owns the UI.  The original process must exit.
        Ok(false)
    }
}

#[cfg(target_os = "windows")]
fn process_is_elevated() -> bool {
    let mut token = std::ptr::null_mut();
    unsafe {
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }
        let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut size = 0;
        let success = GetTokenInformation(
            token,
            TokenElevation,
            (&mut elevation as *mut TOKEN_ELEVATION).cast(),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut size,
        ) != 0;
        let _ = CloseHandle(token);
        success && elevation.TokenIsElevated != 0
    }
}

fn run_gui() -> eframe::Result<()> {
    // The native window is created before App::new can send viewport commands.
    // Use one settings snapshot for its initial icon and the application theme.
    let settings = load_settings();
    eframe::run_native(
        "MeshLake",
        eframe::NativeOptions {
            viewport: egui::ViewportBuilder::default()
                .with_icon(icons::application_icon(64, settings.accent.color(false)))
                .with_inner_size([1200.0, 820.0])
                .with_min_inner_size([760.0, 520.0]),
            ..Default::default()
        },
        Box::new(move |context| Ok(Box::new(App::new(context, settings)))),
    )
}

use pages::Page;
#[cfg(test)]
mod api_tests;
mod confirmation;
mod controller_exit;
mod controller_policy;
mod design;
mod diagnostics;
mod file_io;
mod file_picker;
mod icons;
mod jobs;
mod lifecycle;
mod maintenance;
#[cfg(all(test, target_os = "windows"))]
mod native_tests;
mod pages;
mod services;
use confirmation::PendingAction;

struct App {
    services: services::Services,
    diagnostics: diagnostics::DiagnosticFields,
    request_timeout: u64,
    policy_editor: controller_policy::PolicyEditor,
    maintenance: maintenance::MaintenanceFields,
    process_cancel: Option<std::sync::Arc<std::sync::atomic::AtomicBool>>,
    files: file_io::FileFields,
    generated_invite: String,
    controller_document: String,
    pending_action: Option<PendingAction>,
    job: Option<jobs::JobReceiver>,
    page: Page,
    client: Client,
    api_base: String,
    status: Option<AgentStatus>,
    message: String,
    name: String,
    managed_create_id: String,
    prefix: String,
    ipv6_prefix: String,
    network_relay_policy: RelayPolicy,
    invite_lifetime: u64,
    candidate_device: String,
    candidate_ipv4: bool,
    candidate_ipv6: bool,
    controller: String,
    network_id: String,
    token: String,
    public_key: String,
    controller_public_key: String,
    relay_endpoint: String,
    upnp_enabled: bool,
    stun_servers: String,
    planet_manifest: String,
    planet_public_key: String,
    controller_tls_ca_pem: String,
    admin_token: String,
    admin_token_bound_value: String,
    admin_token_controller: Option<String>,
    managed_networks: Vec<VirtualNetwork>,
    selected_network: Option<Uuid>,
    members: Vec<MembershipClaims>,
    sessions: Option<SessionList>,
    issued_token: String,
    invite_link: String,
    settings: Settings,
    show_settings: bool,
    show_close_confirmation: bool,
    tray_exit_requested: std::sync::Arc<std::sync::atomic::AtomicBool>,
    dont_ask_again: bool,
    tray: Option<Tray>,
    cli_command: String,
    cli_output: String,
    exit_network_id: String,
    ipv4_gateway: String,
    ipv6_gateway: String,
    exit_kill_switch: bool,
    egress_interface: String,
    enable_ipv4_gateway: bool,
    enable_ipv6_gateway: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum Language {
    Chinese,
    English,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
struct Settings {
    theme: design::Theme,
    accent: design::Accent,
    reduced_motion: bool,
    zoom: f32,
    language: Language,
    minimize_on_close: bool,
    ask_on_close: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            theme: design::Theme::System,
            accent: design::Accent::default(),
            reduced_motion: false,
            zoom: 1.0,
            language: Language::Chinese,
            minimize_on_close: false,
            ask_on_close: true,
        }
    }
}

#[derive(Deserialize)]
struct IssuedToken {
    token: String,
    #[serde(default)]
    invite_link: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
struct LocalControllerState {
    admin_token: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedInviteLink {
    controller: String,
    network_id: String,
    token: String,
    public_key: String,
    planet_manifest_url: Option<String>,
    tls_ca_pem: Option<String>,
}

#[derive(Deserialize)]
struct ControllerPublicKey {
    public_key: String,
}

struct Tray {
    _icon: TrayIcon,
}

impl Default for App {
    fn default() -> Self {
        Self {
            services: Default::default(),
            diagnostics: Default::default(),
            request_timeout: 30,
            client: Client::builder()
                .timeout(Duration::from_secs(30))
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap(),
            pending_action: None,
            files: Default::default(),
            generated_invite: String::new(),
            controller_document: String::new(),
            maintenance: Default::default(),
            policy_editor: Default::default(),
            process_cancel: None,
            job: None,
            page: Page::Overview,
            api_base: LOCAL_API.into(),
            status: None,
            message: "点击“刷新状态”以连接本机 meshlaked 服务。".into(),
            name: String::new(),
            managed_create_id: String::new(),
            prefix: "100.64.10.0/24".into(),
            ipv6_prefix: String::new(),
            network_relay_policy: RelayPolicy::Preferred,
            invite_lifetime: 900,
            candidate_device: String::new(),
            candidate_ipv4: true,
            candidate_ipv6: false,
            controller: "http://127.0.0.1:51822".into(),
            network_id: String::new(),
            token: String::new(),
            public_key: String::new(),
            controller_public_key: String::new(),
            relay_endpoint: String::new(),
            upnp_enabled: true,
            stun_servers: String::new(),
            planet_manifest: String::new(),
            planet_public_key: String::new(),
            controller_tls_ca_pem: String::new(),
            admin_token: String::new(),
            admin_token_bound_value: String::new(),
            admin_token_controller: None,
            managed_networks: Vec::new(),
            selected_network: None,
            members: Vec::new(),
            sessions: None,
            issued_token: String::new(),
            invite_link: String::new(),
            settings: Settings::default(),
            show_settings: false,
            show_close_confirmation: false,
            tray_exit_requested: Default::default(),
            dont_ask_again: false,
            tray: None,
            cli_command: "status".into(),
            cli_output: String::new(),
            exit_network_id: String::new(),
            ipv4_gateway: String::new(),
            ipv6_gateway: String::new(),
            exit_kill_switch: false,
            egress_interface: String::new(),
            enable_ipv4_gateway: false,
            enable_ipv6_gateway: false,
        }
    }
}

impl App {
    fn run_cli_command_sync(&mut self, cancel: std::sync::Arc<std::sync::atomic::AtomicBool>) {
        let args = self
            .cli_command
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .collect::<Vec<_>>();
        if args.is_empty() {
            self.cli_output = "请输入 meshlake-cli 子命令。".into();
            return;
        }
        let daemon_commands = ["print-state-path"];
        let binary_name = if daemon_commands.contains(&args[0]) {
            if cfg!(windows) {
                "meshlaked.exe"
            } else {
                "meshlaked"
            }
        } else if cfg!(windows) {
            "meshlake-cli.exe"
        } else {
            "meshlake-cli"
        };
        let Some(executable) = std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.join(binary_name)))
        else {
            self.cli_output = "无法定位当前程序目录。".into();
            return;
        };
        if !executable.is_file() {
            self.cli_output = format!("未找到同目录 CLI：{}", executable.display());
            return;
        }
        let arguments = args.iter().map(|arg| (*arg).to_owned()).collect::<Vec<_>>();
        match maintenance::execute_process(
            &executable,
            &arguments,
            Vec::new(),
            cancel,
            Duration::from_secs(120),
        ) {
            Ok((success, output)) => {
                self.cli_output = output;
                self.message = if success {
                    "执行成功。 / Command succeeded."
                } else {
                    "执行失败，请查看结果。 / Command failed; inspect output."
                }
                .into();
            }
            Err(error) => {
                self.cli_output = error.clone();
                self.message = error;
            }
        }
    }
    fn new(context: &eframe::CreationContext<'_>, settings: Settings) -> Self {
        let mut app = Self::default();
        app.settings = settings;
        app.invite_link = std::env::args()
            .nth(1)
            .filter(|value| value.starts_with("meshlake://"))
            .unwrap_or_default();
        design::apply_theme(&context.egui_ctx, &app.settings);
        app.admin_token = load_local_admin_token().unwrap_or_default();
        app.admin_token_bound_value = app.admin_token.clone();
        if !app.admin_token.is_empty() {
            app.admin_token_controller = Some(app.controller.clone());
        }
        app.refresh();
        app.tray = create_tray(
            &context.egui_ctx,
            app.settings.language,
            app.settings.accent,
            app.tray_exit_requested.clone(),
        );
        app
    }

    fn refresh_sync(&mut self) {
        self.status = None;
        self.sessions = None;
        match self.client.get(format!("{}/status", self.api_base)).send() {
            Ok(response) if response.status().is_success() => match response.json() {
                Ok(status) => {
                    self.status = Some(status);
                    self.message = self
                        .t(
                            "已连接到本机 MeshLake 后台服务。",
                            "Connected to the local MeshLake agent.",
                        )
                        .into();
                }
                Err(_) => {
                    self.message = self
                        .t("后台响应格式无效。", "Invalid agent response.")
                        .into()
                }
            },
            Ok(response) => {
                self.message = http_failure(
                    response,
                    self.t("后台服务返回错误。", "Agent request failed."),
                )
            }
            Err(_) => {
                self.status = None;
                self.message = self.t("未连接到后台。请在维护页检查连接设置或启动服务。", "Agent unavailable. Check connection settings or start the service in Maintenance.").into();
            }
        }
    }

    fn refresh_sessions_sync(&mut self) {
        self.sessions = None;
        match self
            .client
            .get(format!("{}/sessions", self.api_base))
            .send()
        {
            Ok(response) if response.status().is_success() => match response.json() {
                Ok(sessions) => self.sessions = Some(sessions),
                Err(_) => {
                    self.message = self
                        .t("会话响应格式无效。", "Invalid sessions response.")
                        .into()
                }
            },
            Ok(response) => {
                self.message = http_failure(
                    response,
                    self.t("读取会话失败。", "Could not read sessions."),
                )
            }
            Err(_) => {
                self.message = self
                    .t(
                        "无法连接后台读取会话。",
                        "Could not connect to the agent to read sessions.",
                    )
                    .into()
            }
        }
    }

    fn adapter_sync(&mut self, start: bool) {
        let request = if start {
            self.client.post(format!("{}/adapter", self.api_base))
        } else {
            self.client.delete(format!("{}/adapter", self.api_base))
        };
        match request.send() {
            Ok(response) if response.status().is_success() => {
                self.message = if start {
                    self.t("网卡已启动。", "Adapter started.").into()
                } else {
                    self.t("网卡会话已停止。", "Adapter stopped.").into()
                };
                let action_message = self.message.clone();
                self.refresh_sync();
                if self.status.is_some() {
                    self.message = action_message;
                }
                self.refresh_sessions_sync();
            }
            Ok(response) => {
                self.message = http_failure(
                    response,
                    self.t("网卡操作失败。", "Adapter operation failed."),
                )
            }
            Err(error) => {
                self.message = format!(
                    "{}: {error}",
                    self.t("无法联系后台服务", "Could not connect to the agent")
                )
            }
        }
    }

    fn leave_network_sync(&mut self, id: Uuid) {
        match self
            .client
            .delete(format!("{}/networks/{id}", self.api_base))
            .send()
        {
            Ok(response) if response.status().is_success() => {
                self.message = self.t("已离开网络。", "Left the network.").into();
                let action_message = self.message.clone();
                self.refresh_sync();
                if self.status.is_some() {
                    self.message = action_message;
                }
            }
            Ok(response) => {
                self.message = http_failure(
                    response,
                    self.t("离开网络失败。", "Could not leave the network."),
                )
            }
            Err(error) => {
                self.message = format!(
                    "{}: {error}",
                    self.t("无法联系后台服务", "Could not connect to the agent")
                )
            }
        }
    }

    fn apply_exit_selection_sync(&mut self) {
        let Ok(network) = Uuid::parse_str(self.exit_network_id.trim()) else {
            self.message = self
                .t(
                    "出口网络 ID 必须是 UUID。",
                    "Exit network ID must be a UUID.",
                )
                .into();
            return;
        };
        let body = match exit_selection_body(
            &self.ipv4_gateway,
            &self.ipv6_gateway,
            self.exit_kill_switch,
        ) {
            Ok(body) => body,
            Err(error) => {
                self.message = error;
                return;
            }
        };
        match self
            .client
            .post(format!(
                "{}/networks/{network}/exit-selection",
                self.api_base
            ))
            .json(&body)
            .send()
        {
            Ok(r) if r.status().is_success() => {
                self.message = self
                    .t("出口节点选择已应用。", "Exit selection applied.")
                    .into()
            }
            Ok(r) => self.message = http_failure(r, "出口节点选择失败。"),
            Err(e) => {
                self.message = format!(
                    "{}: {e}",
                    self.t("无法联系后台服务", "Could not connect to the agent")
                )
            }
        }
    }

    fn apply_exit_gateway_sync(&mut self) {
        let Ok(network) = Uuid::parse_str(self.exit_network_id.trim()) else {
            self.message = self
                .t(
                    "出口网络 ID 必须是 UUID。",
                    "Exit network ID must be a UUID.",
                )
                .into();
            return;
        };
        let body = json!({ "egress_interface": self.egress_interface.trim(), "enable_ipv4": self.enable_ipv4_gateway, "enable_ipv6": self.enable_ipv6_gateway });
        match self
            .client
            .post(format!("{}/networks/{network}/exit-gateway", self.api_base))
            .json(&body)
            .send()
        {
            Ok(r) if r.status().is_success() => {
                self.message = self.t("出口网关已应用。", "Exit gateway applied.").into()
            }
            Ok(r) => self.message = http_failure(r, "出口网关配置失败。"),
            Err(e) => {
                self.message = format!(
                    "{}: {e}",
                    self.t("无法联系后台服务", "Could not connect to the agent")
                )
            }
        }
    }

    fn remove_exit_gateway_sync(&mut self) {
        let Ok(network) = Uuid::parse_str(self.exit_network_id.trim()) else {
            self.message = self
                .t(
                    "出口网络 ID 必须是 UUID。",
                    "Exit network ID must be a UUID.",
                )
                .into();
            return;
        };
        self.message = local_action_result(
            self.client
                .delete(format!("{}/networks/{network}/exit-gateway", self.api_base))
                .send(),
            self.t("出口网关已停用。", "Exit gateway disabled."),
            self.settings.language,
        );
    }

    fn clear_exit_selection_sync(&mut self) {
        let Ok(network) = Uuid::parse_str(self.exit_network_id.trim()) else {
            self.message = self
                .t(
                    "出口网络 ID 必须是 UUID。",
                    "Exit network ID must be a UUID.",
                )
                .into();
            return;
        };
        self.message = local_action_result(
            self.client
                .post(format!(
                    "{}/networks/{network}/exit-selection",
                    self.api_base
                ))
                .json(&json!({"ipv4_gateway": null, "ipv6_gateway": null, "kill_switch": false}))
                .send(),
            self.t("出口节点选择已清除。", "Exit selection cleared."),
            self.settings.language,
        );
    }

    fn stop_agent_sync(&mut self) {
        let result = self
            .client
            .post(format!("{}/shutdown", self.api_base))
            .send();
        if result.as_ref().is_ok_and(|r| r.status().is_success()) {
            self.status = None;
            self.sessions = None;
        }
        self.message = local_action_result(
            result,
            self.t(
                "后台已停止，GUI 保持打开。",
                "Agent stopped. The GUI stays open.",
            ),
            self.settings.language,
        );
    }

    fn join_network_sync(&mut self, planet_manifest_url: Option<String>) {
        let network_id = match Uuid::parse_str(self.network_id.trim()) {
            Ok(id) => id,
            Err(_) => {
                self.message = self
                    .t("网络 ID 必须是 UUID。", "Network ID must be a UUID.")
                    .into();
                return;
            }
        };
        let key = match STANDARD.decode(self.public_key.trim()) {
            Ok(key) if key.len() == 32 => key,
            _ => {
                self.message = self
                    .t(
                        "控制器公钥必须是 32 字节 Base64 值。",
                        "Controller public key must be a 32-byte Base64 value.",
                    )
                    .into();
                return;
            }
        };
        let tls_ca_pem = match normalize_optional_tls_ca(&self.controller_tls_ca_pem) {
            Ok(value) => value,
            Err(error) => {
                self.message = format!("控制器私有 CA 无效：{error}");
                return;
            }
        };
        let controller = match controller_base_url(&self.controller, tls_ca_pem.is_some()) {
            Ok(value) => value,
            Err(error) => {
                self.message = format!("控制器 URL 无效：{error}");
                return;
            }
        };
        let planet_manifest_url = match planet_manifest_url {
            Some(value) => match normalize_http_url(&value, "Planet manifest URL", true) {
                Ok(value) => Some(value),
                Err(error) => {
                    self.message = format!("Planet 清单 URL 无效：{error}");
                    return;
                }
            },
            None => None,
        };
        if let Err(error) = validate_tls_url_pair(
            &controller,
            planet_manifest_url.as_deref(),
            tls_ca_pem.is_some(),
        ) {
            self.message = error;
            return;
        }
        let enrollment_client = match configured_http_client(
            tls_ca_pem.as_deref(),
            Duration::from_secs(self.request_timeout),
            false,
        ) {
            Ok(client) => client,
            Err(error) => {
                self.message = format!("无法创建安全控制器连接：{error}");
                return;
            }
        };
        // Resolve the current agent identity before binding a one-time token.
        // A cached status may belong to an agent restarted with another state file.
        let current_status: AgentStatus = match self
            .client
            .get(format!("{}/status", self.api_base))
            .send()
        {
            Ok(response) if response.status().is_success() => {
                match response.json::<AgentStatus>() {
                    Ok(status) if status.identity_public_key.len() == 32 => status,
                    _ => {
                        self.message = self.t("后台身份响应无效，尚未提交入网令牌。", "Invalid agent identity response; enrollment token was not submitted.").into();
                        return;
                    }
                }
            }
            Ok(response) => {
                self.message = format!(
                    "{}: HTTP {}",
                    self.t(
                        "读取当前后台身份失败，尚未提交入网令牌",
                        "Could not read current agent identity; enrollment token was not submitted"
                    ),
                    response.status()
                );
                return;
            }
            Err(_) => {
                self.message = self.t("无法读取当前后台身份，尚未提交入网令牌。", "Could not read current agent identity; enrollment token was not submitted.").into();
                return;
            }
        };
        let device_id = current_status.device_id.0;
        let device_public_key = current_status.identity_public_key;
        let enrollment: EnrollmentResponse = match enrollment_client.post(format!("{controller}/v1/enroll")).json(&json!({"network_id": network_id, "device_id": device_id, "device_public_key": device_public_key, "token": self.token.trim()})).send() {
            Ok(response) if response.status().is_success() => match response.json() {
                Ok(value) => value,
                Err(_) => { self.message = self.t("控制器返回格式无效。", "Invalid controller response.").into(); return; }
            },
            Ok(response) => { self.message = http_failure(response, "控制器拒绝入网。"); return; }
            Err(error) => { self.message = format!("无法联系控制器：{error}"); return; }
        };
        match self
            .client
            .post(format!("{}/networks/enroll", self.api_base))
            .json(&json!({
                "enrollment": enrollment,
                "controller_public_key": key,
                "control_plane": {
                    "controller_url": controller,
                    "planet_manifest_url": planet_manifest_url,
                    "controller_tls_ca_pem": tls_ca_pem,
                }
            }))
            .send()
        {
            Ok(response) if response.status().is_success() => {
                self.message = self
                    .t(
                        "已安全加入控制器网络。",
                        "Joined the controller network securely.",
                    )
                    .into();
                self.token.clear();
                let action_message = self.message.clone();
                self.refresh_sync();
                if self.status.is_some() {
                    self.message = action_message;
                }
            }
            Ok(response) => self.message = http_failure(response, "后台拒绝入网记录。"),
            Err(error) => {
                self.message = format!(
                    "{}: {error}",
                    self.t("无法联系后台服务", "Could not connect to the agent")
                )
            }
        }
    }

    fn join_invite_link_sync(&mut self) {
        if self.invite_link.trim().is_empty() {
            self.message = self
                .t(
                    "请先粘贴或导入邀请链接。",
                    "Paste or import an invitation link first.",
                )
                .into();
            return;
        }
        let invitation = match parse_invite_link(self.invite_link.trim()) {
            Ok(invitation) => invitation,
            Err(error) => {
                self.message = format!("邀请链接无效：{error}");
                return;
            }
        };
        let current_controller = normalize_http_url(&self.controller, "controller URL", false).ok();
        let configured_tls_ca =
            if current_controller.as_deref() == Some(invitation.controller.as_str()) {
                match normalize_optional_tls_ca(&self.controller_tls_ca_pem) {
                    Ok(value) => value,
                    Err(error) => {
                        self.message = format!("已配置的控制器私有 CA 无效：{error}");
                        return;
                    }
                }
            } else {
                None
            };
        let effective_tls_ca = match select_effective_tls_ca(
            invitation.tls_ca_pem.as_deref(),
            configured_tls_ca.as_deref(),
        ) {
            Ok(value) => value,
            Err(error) => {
                self.message = error;
                return;
            }
        };
        self.switch_controller_context(invitation.controller);
        self.network_id = invitation.network_id;
        self.token = invitation.token;
        self.public_key = invitation.public_key.clone();
        self.controller_public_key = invitation.public_key;
        self.controller_tls_ca_pem = effective_tls_ca.unwrap_or_default();
        self.join_network_sync(invitation.planet_manifest_url);
    }

    fn configure_relay_sync(&mut self) {
        match self
            .client
            .post(format!("{}/relay", self.api_base))
            .json(&json!({
                "endpoint": self.relay_endpoint.trim(),
                "enable_upnp": self.upnp_enabled,
                "stun_servers": self.stun_servers.split(',').map(str::trim).filter(|value| !value.is_empty()).collect::<Vec<_>>(),
            }))
            .send()
        {
            Ok(response) if response.status().is_success() => {
                self.message = self.t("中继地址已保存并自动应用。", "Relay endpoint saved and applied.").into();
            }
            Ok(response) => {
                self.message = http_failure(response, "保存中继地址失败。")
            }
            Err(error) => self.message = format!("{}: {error}", self.t("无法联系后台服务", "Could not connect to the agent")),
        }
    }

    fn configure_planet_sync(&mut self) {
        let tls_ca_pem = match normalize_optional_tls_ca(&self.controller_tls_ca_pem) {
            Ok(value) => value,
            Err(error) => {
                self.message = format!("控制器私有 CA 无效：{error}");
                return;
            }
        };
        let manifest_url =
            match normalize_http_url(&self.planet_manifest, "Planet manifest URL", true) {
                Ok(value) => value,
                Err(error) => {
                    self.message = format!("Planet 清单 URL 无效：{error}");
                    return;
                }
            };
        if tls_ca_pem.is_some() && !manifest_url.starts_with("https://") {
            self.message = "使用私有 CA 时，Planet 清单 URL 必须是 https://。".into();
            return;
        }
        match self
            .client
            .post(format!("{}/planet", self.api_base))
            .json(&json!({
                "manifest_url": manifest_url,
                "controller_public_key_base64": self.planet_public_key.trim(),
                "tls_ca_certificate_pem": tls_ca_pem,
            }))
            .send()
        {
            Ok(response) if response.status().is_success() => {
                self.message = "行星服务器配置已验证、保存并自动应用。".into();
            }
            Ok(response) => self.message = http_failure(response, "保存行星服务器配置失败。"),
            Err(error) => self.message = format!("无法联系本机后台服务：{error}"),
        }
    }

    fn controller_request(
        &mut self,
        method: reqwest::Method,
        path: String,
        requires_admin: bool,
    ) -> Result<reqwest::blocking::RequestBuilder, String> {
        let tls_ca_pem = normalize_optional_tls_ca(&self.controller_tls_ca_pem)?;
        let controller = controller_base_url(&self.controller, tls_ca_pem.is_some())?;
        let client = controller_http_client(tls_ca_pem.as_deref())?;
        let request = client
            .request(method, format!("{controller}{path}"))
            .timeout(Duration::from_secs(self.request_timeout));
        if !requires_admin {
            return Ok(request);
        }

        let admin_token = self.admin_token.trim().to_owned();
        if admin_token.is_empty() {
            self.admin_token_bound_value = self.admin_token.clone();
            self.admin_token_controller = None;
            return Err("当前控制器需要管理员令牌。".into());
        }
        if self.admin_token != self.admin_token_bound_value {
            self.admin_token_bound_value = self.admin_token.clone();
            self.admin_token_controller = Some(controller.clone());
        }
        if self.admin_token_controller.as_deref() != Some(controller.as_str()) {
            return Err("管理员令牌已绑定到另一个控制器；请为当前控制器重新输入令牌。".into());
        }
        Ok(request.header("x-meshlake-admin-token", admin_token))
    }

    fn switch_controller_context(&mut self, controller: String) {
        let current = normalize_http_url(&self.controller, "controller URL", false).ok();
        if current.as_deref() != Some(controller.as_str()) {
            self.admin_token.clear();
            self.admin_token_bound_value.clear();
            self.admin_token_controller = None;
            self.controller_public_key.clear();
            self.controller_tls_ca_pem.clear();
            self.managed_networks.clear();
            self.selected_network = None;
            self.members.clear();
            self.issued_token.clear();
            self.generated_invite.clear();
            self.controller_document.clear();
            self.policy_editor = Default::default();
        }
        self.controller = controller;
    }

    fn controller_address_ui(&mut self, ui: &mut egui::Ui) {
        let mut address = self.controller.clone();
        if ui.add(design::input(&mut address)).changed() {
            self.switch_controller_context(address);
        }
    }

    fn refresh_controller_public_key_sync(&mut self, show_message: bool) {
        self.controller_public_key.clear();
        let request =
            match self.controller_request(reqwest::Method::GET, "/v1/public-key".into(), false) {
                Ok(request) => request,
                Err(error) => {
                    if show_message {
                        self.message = format!("控制器配置无效：{error}");
                    }
                    return;
                }
            };
        match request.send() {
            Ok(response) if response.status().is_success() => {
                match response.json::<ControllerPublicKey>() {
                    Ok(response) => {
                        self.controller_public_key = response.public_key;
                        if show_message {
                            self.message = self
                                .t("控制器公钥已读取；请通过可信渠道核对后再分享。", "Controller public key loaded; verify it through a trusted channel before sharing.")
                                .into();
                        }
                    }
                    Err(_) if show_message => {
                        self.message = self
                            .t(
                                "控制器公钥响应无效。",
                                "Invalid controller public key response.",
                            )
                            .into();
                    }
                    Err(_) => {}
                }
            }
            Ok(response) if show_message => {
                self.message = http_failure(response, "读取控制器公钥失败。");
            }
            Err(error) if show_message => {
                self.message = format!("无法联系控制器：{error}");
            }
            _ => {}
        }
    }

    fn refresh_managed_networks_sync(&mut self) {
        let request =
            match self.controller_request(reqwest::Method::GET, "/v1/networks".into(), false) {
                Ok(request) => request,
                Err(error) => {
                    self.message = format!("控制器配置无效：{error}");
                    return;
                }
            };
        match request.send() {
            Ok(response) if response.status().is_success() => match response.json() {
                Ok(networks) => {
                    self.managed_networks = networks;
                    self.message = self
                        .t("控制器网络列表已更新。", "Controller network list updated.")
                        .into();
                }
                Err(_) => {
                    self.message = self
                        .t("控制器响应格式无效。", "Invalid controller response.")
                        .into()
                }
            },
            Ok(response) => self.message = http_failure(response, "读取控制器网络失败。"),
            Err(error) => self.message = format!("无法联系控制器：{error}"),
        }
    }

    fn create_managed_network_sync(&mut self) {
        let id = if self.managed_create_id.trim().is_empty() {
            None
        } else {
            match Uuid::parse_str(self.managed_create_id.trim()) {
                Ok(id) => Some(meshlake_core::NetworkId(id)),
                Err(_) => {
                    self.message = self
                        .t("新网络 ID 必须是 UUID。", "New network ID must be a UUID.")
                        .into();
                    return;
                }
            }
        };
        let network_request = UpsertNetworkRequest {
            id,
            name: self.name.trim().to_owned(),
            ipv4_prefix: self.prefix.trim().to_owned(),
            ipv6_prefix: (!self.ipv6_prefix.trim().is_empty())
                .then(|| self.ipv6_prefix.trim().to_owned()),
            relay_policy: self.network_relay_policy.clone(),
        };
        let controller_request =
            match self.controller_request(reqwest::Method::POST, "/v1/networks".into(), true) {
                Ok(request) => request.json(&network_request),
                Err(error) => {
                    self.message = format!("控制器配置无效：{error}");
                    return;
                }
            };
        match controller_request.send() {
            Ok(response) if response.status().is_success() => {
                self.message = self
                    .t("控制器网络已创建。", "Controller network created.")
                    .into();
                self.name.clear();
                self.refresh_managed_networks_sync();
            }
            Ok(response) => self.message = http_failure(response, "创建控制器网络失败。"),
            Err(error) => self.message = format!("无法联系控制器：{error}"),
        }
    }

    fn create_local_network_sync(&mut self) {
        let id = if self.network_id.trim().is_empty() {
            None
        } else {
            match Uuid::parse_str(self.network_id.trim()) {
                Ok(id) => Some(meshlake_core::NetworkId(id)),
                Err(_) => {
                    self.message =
                        "网络 ID 必须为空或 UUID。 / Network ID must be empty or a UUID.".into();
                    return;
                }
            }
        };
        let request = UpsertNetworkRequest {
            id,
            name: self.name.trim().into(),
            ipv4_prefix: self.prefix.trim().into(),
            ipv6_prefix: (!self.ipv6_prefix.trim().is_empty())
                .then(|| self.ipv6_prefix.trim().into()),
            relay_policy: self.network_relay_policy.clone(),
        };
        let result = self
            .client
            .post(format!("{}/networks", self.api_base))
            .json(&request)
            .send();
        let success = result
            .as_ref()
            .is_ok_and(|response| response.status().is_success());
        let message = local_action_result(
            result,
            self.t("本地网络已创建。", "Local network created."),
            self.settings.language,
        );
        if success {
            self.refresh_sync();
        }
        self.message = message;
    }

    fn delete_managed_network_sync(&mut self, id: Uuid) {
        let request = match self.controller_request(
            reqwest::Method::DELETE,
            format!("/v1/networks/{id}"),
            true,
        ) {
            Ok(request) => request,
            Err(error) => {
                self.message = format!("控制器配置无效：{error}");
                return;
            }
        };
        match request.send() {
            Ok(response) if response.status().is_success() => {
                self.message = self
                    .t("网络已从控制器删除。", "Network deleted from controller.")
                    .into();
                self.members.clear();
                self.refresh_managed_networks_sync();
            }
            Ok(response) => self.message = http_failure(response, "删除网络失败。"),
            Err(error) => self.message = format!("无法联系控制器：{error}"),
        }
    }

    fn issue_enrollment_token_sync(&mut self, id: Uuid) {
        self.generated_invite.clear();
        self.issued_token.clear();
        self.refresh_controller_public_key_sync(false);
        if self.controller_public_key.is_empty() {
            self.message = self
                .t(
                    "无法读取控制器公钥，未生成邀请链接。",
                    "Could not load the controller public key; invitation link was not created.",
                )
                .into();
            return;
        }
        let request = match self.controller_request(
            reqwest::Method::POST,
            format!("/v1/networks/{id}/enrollment-tokens"),
            true,
        ) {
            Ok(request) => request.json(&json!({"expires_in_seconds": self.invite_lifetime})),
            Err(error) => {
                self.message = format!("控制器配置无效：{error}");
                return;
            }
        };
        match request.send() {
            Ok(response) if response.status().is_success() => {
                match response.json::<IssuedToken>() {
                    Ok(token) => {
                        self.issued_token = token.token;
                        self.generated_invite = match token.invite_link {
                            Some(link) if !link.trim().is_empty() => match parse_invite_link(&link)
                            {
                                Ok(_) => link,
                                Err(error) => {
                                    self.message = format!("控制器返回了无效的邀请链接：{error}");
                                    return;
                                }
                            },
                            _ => match make_invite_link(
                                &self.controller,
                                id,
                                &self.issued_token,
                                &self.controller_public_key,
                                normalize_optional_tls_ca(&self.controller_tls_ca_pem)
                                    .ok()
                                    .flatten()
                                    .as_deref(),
                            ) {
                                Ok(link) => link,
                                Err(error) => {
                                    self.message = format!("无法生成邀请链接：{error}");
                                    return;
                                }
                            },
                        };
                        self.message = format!(
                            "{} {} {}",
                            self.t(
                                "已生成一次性邀请，有效期",
                                "One-time invitation created; valid for"
                            ),
                            self.invite_lifetime,
                            self.t("秒。", "seconds.")
                        );
                    }
                    Err(_) => {
                        self.message = self
                            .t("令牌响应格式无效。", "Invalid enrollment token response.")
                            .into()
                    }
                }
            }
            Ok(response) => self.message = http_failure(response, "生成入网令牌失败。"),
            Err(error) => self.message = format!("无法联系控制器：{error}"),
        }
    }

    fn load_members_sync(&mut self, id: Uuid) {
        self.members.clear();
        let request = match self.controller_request(
            reqwest::Method::GET,
            format!("/v1/networks/{id}/members"),
            true,
        ) {
            Ok(request) => request,
            Err(error) => {
                self.message = format!("控制器配置无效：{error}");
                return;
            }
        };
        match request.send() {
            Ok(response) if response.status().is_success() => match response.json() {
                Ok(members) => {
                    self.selected_network = Some(id);
                    self.members = members;
                }
                Err(_) => {
                    self.message = self
                        .t("成员响应格式无效。", "Invalid membership response.")
                        .into()
                }
            },
            Ok(response) => self.message = http_failure(response, "读取成员失败。"),
            Err(error) => self.message = format!("无法联系控制器：{error}"),
        }
    }

    fn remove_member_sync(&mut self, network_id: Uuid, device_id: Uuid) {
        let request = match self.controller_request(
            reqwest::Method::DELETE,
            format!("/v1/networks/{network_id}/members/{device_id}"),
            true,
        ) {
            Ok(request) => request,
            Err(error) => {
                self.message = format!("控制器配置无效：{error}");
                return;
            }
        };
        match request.send() {
            Ok(response) if response.status().is_success() => {
                self.message = self
                    .t(
                        "成员已从控制器记录中移除。",
                        "Member removed from controller records.",
                    )
                    .into();
                self.load_members_sync(network_id);
            }
            Ok(response) => self.message = http_failure(response, "移除成员失败。"),
            Err(error) => self.message = format!("无法联系控制器：{error}"),
        }
    }

    fn t<'a>(&self, chinese: &'a str, english: &'a str) -> &'a str {
        match self.settings.language {
            Language::Chinese => chinese,
            Language::English => english,
        }
    }
}

fn parse_invite_link(value: &str) -> Result<ParsedInviteLink, String> {
    let link = Url::parse(value.trim()).map_err(|error| error.to_string())?;
    if link.scheme() != "meshlake" || link.host_str() != Some("join") {
        return Err("链接必须以 meshlake://join? 开头".into());
    }
    if !link.username().is_empty()
        || link.password().is_some()
        || !link.path().is_empty()
        || link.fragment().is_some()
    {
        return Err("链接包含不支持的 URL 组成部分".into());
    }
    let parameter = |name: &str| {
        link.query_pairs()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.into_owned())
            .filter(|value| !value.is_empty())
            .ok_or_else(|| format!("链接缺少 {name}"))
    };
    let controller = normalize_http_url(&parameter("controller")?, "controller URL", false)?;
    let network_id = Uuid::parse_str(&parameter("network_id")?)
        .map_err(|_| "network_id 不是有效 UUID".to_owned())?
        .to_string();
    let token = parameter("token")?;
    let public_key = parameter("public_key")?;
    let decoded_key = STANDARD
        .decode(&public_key)
        .map_err(|_| "public_key 不是有效 Base64".to_owned())?;
    if decoded_key.len() != 32 {
        return Err("public_key 必须正好包含 32 字节".into());
    }
    let planet_manifest_url = link
        .query_pairs()
        .find(|(key, _)| key == "planet")
        .map(|(_, value)| value.into_owned())
        .filter(|value| !value.is_empty())
        .map(|value| normalize_http_url(&value, "Planet manifest URL", true))
        .transpose()?;
    let tls_ca_pem = link
        .query_pairs()
        .find(|(key, _)| key == "tls_ca")
        .map(|(_, value)| value.into_owned())
        .filter(|value| !value.is_empty())
        .map(|encoded| {
            let decoded = STANDARD
                .decode(encoded)
                .map_err(|_| "tls_ca 不是有效 Base64".to_owned())?;
            if decoded.is_empty() || decoded.len() > 64 * 1024 {
                return Err("tls_ca 必须包含 1 字节到 64 KiB".into());
            }
            let pem =
                String::from_utf8(decoded).map_err(|_| "tls_ca 不是 UTF-8 PEM 证书".to_owned())?;
            normalize_tls_ca_pem(&pem)
        })
        .transpose()?;
    validate_tls_url_pair(
        &controller,
        planet_manifest_url.as_deref(),
        tls_ca_pem.is_some(),
    )?;
    Ok(ParsedInviteLink {
        controller,
        network_id,
        token,
        public_key,
        planet_manifest_url,
        tls_ca_pem,
    })
}

fn normalize_http_url(value: &str, description: &str, allow_path: bool) -> Result<String, String> {
    let value = value.trim();
    let Some((raw_scheme, authority_and_path)) = value.split_once("://") else {
        return Err(format!("{description} 必须使用 http:// 或 https://"));
    };
    let raw_authority = authority_and_path
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default();
    if !matches!(raw_scheme.to_ascii_lowercase().as_str(), "http" | "https")
        || authority_and_path.is_empty()
        || authority_and_path.starts_with('/')
        || value.contains('\\')
        || raw_authority.contains('@')
    {
        return Err(format!("{description} 必须包含有效的 HTTP authority"));
    }
    let mut url =
        Url::parse(value).map_err(|error| format!("{description} 不是有效 URL：{error}"))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(format!("{description} 必须使用 http:// 或 https://"));
    }
    if url.host_str().is_none() {
        return Err(format!("{description} 必须包含主机名或 IP"));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(format!("{description} 不得包含用户名或密码"));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(format!("{description} 不得包含 query 或 fragment"));
    }
    if !allow_path && url.path() != "/" {
        return Err(format!("{description} 不得包含路径"));
    }
    if allow_path && url.path() == "/" {
        return Err(format!("{description} 必须包含清单路径"));
    }
    if !allow_path {
        url.set_path("");
    }
    Ok(url.as_str().trim_end_matches('/').to_owned())
}

fn validate_tls_url_pair(
    controller_url: &str,
    planet_manifest_url: Option<&str>,
    has_private_ca: bool,
) -> Result<(), String> {
    if !has_private_ca {
        return Ok(());
    }
    if Url::parse(controller_url)
        .map_err(|error| error.to_string())?
        .scheme()
        != "https"
    {
        return Err("使用私有 CA 时，控制器 URL 必须是 https://".into());
    }
    if let Some(planet_manifest_url) = planet_manifest_url {
        if Url::parse(planet_manifest_url)
            .map_err(|error| error.to_string())?
            .scheme()
            != "https"
        {
            return Err("使用私有 CA 时，Planet 清单 URL 必须是 https://".into());
        }
    }
    Ok(())
}

fn controller_base_url(value: &str, has_private_ca: bool) -> Result<String, String> {
    let url = normalize_http_url(value, "controller URL", false)?;
    validate_tls_url_pair(&url, None, has_private_ca)?;
    Ok(url)
}

fn normalize_optional_tls_ca(value: &str) -> Result<Option<String>, String> {
    let value = value.trim();
    if value.is_empty() {
        Ok(None)
    } else {
        normalize_tls_ca_pem(value).map(Some)
    }
}

fn select_effective_tls_ca(
    invitation: Option<&str>,
    configured: Option<&str>,
) -> Result<Option<String>, String> {
    match (invitation, configured) {
        (None, None) => Ok(None),
        (Some(ca), None) | (None, Some(ca)) => Ok(Some(ca.to_owned())),
        (Some(invitation), Some(configured)) if invitation == configured => {
            Ok(Some(invitation.to_owned()))
        }
        (Some(_), Some(_)) => {
            Err("邀请链接中的私有 CA 与当前控制器配置冲突；已拒绝入网，请先核对 CA 指纹。".into())
        }
    }
}

fn tls_certificate_der_bundle(pem: &str) -> Result<Vec<Vec<u8>>, String> {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    if pem.is_empty() || pem.len() > 64 * 1024 {
        return Err("CA PEM 必须包含 1 字节到 64 KiB".into());
    }
    let mut certificates = Vec::new();
    let mut current = None::<String>;
    for line in pem.lines().map(str::trim) {
        match line {
            BEGIN => {
                if current.is_some() {
                    return Err("CA PEM 包含嵌套的证书块".into());
                }
                current = Some(String::new());
            }
            END => {
                let encoded = current
                    .take()
                    .ok_or_else(|| "CA PEM 的证书结束标记没有对应的开始标记".to_owned())?;
                if encoded.is_empty() {
                    return Err("CA PEM 包含空证书块".into());
                }
                certificates.push(
                    STANDARD
                        .decode(encoded)
                        .map_err(|_| "CA PEM 证书不是有效 Base64".to_owned())?,
                );
            }
            "" => {}
            value => {
                let Some(encoded) = current.as_mut() else {
                    return Err("CA PEM 的证书块外存在其他数据".into());
                };
                if !value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'='))
                {
                    return Err("CA PEM 证书包含非法字符".into());
                }
                encoded.push_str(value);
            }
        }
    }
    if current.is_some() {
        return Err("CA PEM 证书块缺少结束标记".into());
    }
    if certificates.is_empty() {
        return Err("CA PEM 不包含证书".into());
    }
    certificates.sort();
    certificates.dedup();
    Ok(certificates)
}

fn normalize_tls_ca_pem(pem: &str) -> Result<String, String> {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    let certificates = tls_certificate_der_bundle(pem)?;
    let mut builder = Client::builder().tls_built_in_root_certs(false);
    for certificate in &certificates {
        builder = builder.add_root_certificate(
            Certificate::from_der(certificate)
                .map_err(|error| format!("CA DER 证书无效：{error}"))?,
        );
    }
    builder
        .build()
        .map_err(|error| format!("CA X.509 证书无效：{error}"))?;

    let mut normalized = String::new();
    for certificate in certificates {
        normalized.push_str(BEGIN);
        normalized.push('\n');
        let encoded = STANDARD.encode(certificate);
        for line in encoded.as_bytes().chunks(64) {
            normalized.push_str(std::str::from_utf8(line).expect("base64 is ASCII"));
            normalized.push('\n');
        }
        normalized.push_str(END);
        normalized.push('\n');
    }
    Ok(normalized)
}

fn controller_http_client(tls_ca_pem: Option<&str>) -> Result<Client, String> {
    configured_http_client(tls_ca_pem, Duration::from_secs(30), false)
}

fn configured_http_client(
    tls_ca_pem: Option<&str>,
    timeout: Duration,
    local: bool,
) -> Result<Client, String> {
    let mut builder = Client::builder()
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none());
    if local {
        builder = builder.no_proxy();
    }
    if let Some(tls_ca_pem) = tls_ca_pem {
        let certificates = tls_certificate_der_bundle(tls_ca_pem)?;
        builder = builder.tls_built_in_root_certs(false);
        for certificate in certificates {
            builder = builder.add_root_certificate(
                Certificate::from_der(&certificate)
                    .map_err(|error| format!("CA DER 证书无效：{error}"))?,
            );
        }
    }
    builder
        .build()
        .map_err(|error| format!("无法创建 HTTPS 客户端：{error}"))
}

fn make_invite_link(
    controller: &str,
    network_id: Uuid,
    token: &str,
    controller_public_key: &str,
    tls_ca_pem: Option<&str>,
) -> Result<String, String> {
    let controller = controller_base_url(controller, tls_ca_pem.is_some())?;
    let mut link = Url::parse("meshlake://join").expect("static invitation URL is valid");
    link.query_pairs_mut()
        .append_pair("controller", &controller)
        .append_pair("network_id", &network_id.to_string())
        .append_pair("token", token)
        .append_pair("public_key", controller_public_key);
    if let Some(tls_ca_pem) = tls_ca_pem {
        link.query_pairs_mut()
            .append_pair("tls_ca", &STANDARD.encode(tls_ca_pem.as_bytes()));
    }
    Ok(link.into())
}

impl eframe::App for App {
    fn update(&mut self, context: &egui::Context, _: &mut eframe::Frame) {
        self.poll_services(context);
        self.poll_job(context);

        let explicit_exit = self
            .tray_exit_requested
            .swap(false, std::sync::atomic::Ordering::Relaxed);
        if explicit_exit || context.input(|input| input.viewport().close_requested()) {
            context.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            self.request_close(context, explicit_exit);
        }
        self.render_shell(context);
        self.confirmation_ui(context);
        if self.show_settings && self.pending_action.is_none() && !self.show_close_confirmation {
            let mut open = self.show_settings;
            let before = self.settings.clone();
            let minimize_label = self.t(
                "点击关闭按钮时默认最小化到托盘",
                "Minimize to tray when closing the window",
            );
            let ask_label = self.t("关闭时询问", "Ask when closing");
            design::preferences_window(context, self.t("设置", "Settings"), &mut open).show(
                context,
                |ui| {
                    ui.label(
                        egui::RichText::new(self.t("MeshLake 设置", "MeshLake Settings"))
                            .size(20.0)
                            .strong()
                            .color(ui.visuals().hyperlink_color),
                    );
                    ui.separator();
                    ui.label(egui::RichText::new(self.t("语言", "Language")).strong());
                    ui.selectable_value(&mut self.settings.language, Language::Chinese, "简体中文");
                    ui.selectable_value(&mut self.settings.language, Language::English, "English");
                    ui.separator();
                    self.appearance_settings_ui(ui);
                    ui.separator();
                    ui.checkbox(&mut self.settings.minimize_on_close, minimize_label);
                    ui.checkbox(&mut self.settings.ask_on_close, ask_label);
                    ui.separator();
                    ui.small(self.t(
                        "本软件使用 MiSans 字体 · © 小米科技有限责任公司",
                        "Uses MiSans fonts · © Xiaomi Inc.",
                    ));
                    ui.collapsing(self.t("字体许可", "Font license"), |ui| {
                        ui.label(include_str!("../assets/fonts/NOTICE.txt"));
                    });
                },
            );
            self.show_settings = open;
            if before != self.settings {
                if before.language != self.settings.language
                    || before.accent != self.settings.accent
                {
                    self.tray = create_tray(
                        context,
                        self.settings.language,
                        self.settings.accent,
                        self.tray_exit_requested.clone(),
                    );
                }
                design::apply_theme(context, &self.settings);
                if before.accent != self.settings.accent {
                    context.send_viewport_cmd(egui::ViewportCommand::Icon(Some(
                        std::sync::Arc::new(icons::application_icon(
                            64,
                            self.settings.accent.color(false),
                        )),
                    )));
                }
                save_settings(&self.settings);
            }
        }

        self.close_confirmation_ui(context);
    }
}

fn settings_path() -> PathBuf {
    std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join("MeshLake")
        .join("gui-settings.json")
}

fn load_settings() -> Settings {
    fs::read(settings_path())
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
}

fn save_settings(settings: &Settings) {
    let path = settings_path();
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let _ = fs::write(
        path,
        serde_json::to_vec_pretty(settings).unwrap_or_default(),
    );
}

fn install_ui_fonts(context: &egui::Context) {
    let mut fonts = egui::FontDefinitions::default();
    fonts.font_data.insert(
        "MiSans".into(),
        egui::FontData::from_static(include_bytes!("../assets/fonts/MiSans-Regular.ttf")).into(),
    );
    fonts.font_data.insert(
        "MiSans Medium".into(),
        egui::FontData::from_static(include_bytes!("../assets/fonts/MiSans-Medium.ttf")).into(),
    );
    fonts
        .families
        .entry(egui::FontFamily::Proportional)
        .or_default()
        .insert(0, "MiSans".into());
    fonts
        .families
        .entry(egui::FontFamily::Monospace)
        .or_default()
        .push("MiSans".into());
    fonts.families.insert(
        egui::FontFamily::Name("MiSans Medium".into()),
        vec!["MiSans Medium".into(), "MiSans".into()],
    );
    context.set_fonts(fonts);
}

fn load_local_admin_token() -> Option<String> {
    let path = std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)?
        .join("MeshLake")
        .join("controller.json");
    let bytes = fs::read(path).ok()?;
    decode_local_admin_token(&bytes)
}

fn decode_local_admin_token(bytes: &[u8]) -> Option<String> {
    decode_protected_state::<LocalControllerState>(bytes, CONTROLLER_STATE_PROTECTION_PURPOSE)
        .ok()
        .map(|decoded| decoded.value.admin_token)
}

fn exit_gui() {
    // The GUI owns no daemon lifetime. Stop the agent explicitly from Maintenance.
    std::process::exit(0);
}
fn create_tray(
    context: &egui::Context,
    language: Language,
    accent: design::Accent,
    exit_requested: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> Option<Tray> {
    let menu = Menu::new();
    let show = MenuItem::new(
        if language == Language::Chinese {
            "显示 MeshLake"
        } else {
            "Show MeshLake"
        },
        true,
        None,
    );
    let exit = MenuItem::new(
        if language == Language::Chinese {
            "退出图形界面"
        } else {
            "Exit GUI"
        },
        true,
        None,
    );
    menu.append(&show).ok()?;
    menu.append(&exit).ok()?;
    let image = icons::application_icon(32, accent.color(false));
    let icon = Icon::from_rgba(image.rgba, image.width, image.height).ok()?;
    let tray = TrayIconBuilder::new()
        .with_tooltip("MeshLake")
        .with_menu(Box::new(menu))
        .with_icon(icon)
        .build()
        .ok()?;
    let show_id = show.id().clone();
    let exit_id = exit.id().clone();
    let context = context.clone();
    MenuEvent::set_event_handler(Some(move |event: MenuEvent| {
        if event.id == show_id {
            context.send_viewport_cmd(egui::ViewportCommand::Visible(true));
            context.send_viewport_cmd(egui::ViewportCommand::Minimized(false));
            context.send_viewport_cmd(egui::ViewportCommand::Focus);
            context.request_repaint();
        } else if event.id == exit_id {
            exit_requested.store(true, std::sync::atomic::Ordering::Relaxed);
            context.request_repaint();
        }
    }));
    Some(Tray { _icon: tray })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invalid_gateway_id_cannot_silently_clear_a_selected_exit() {
        assert!(exit_selection_body("not-a-uuid", "", true).is_err());
        assert!(exit_selection_body("", "invalid", false).is_err());
    }

    #[test]
    fn exit_selection_keeps_independent_families_and_kill_switch() {
        let id = Uuid::new_v4();
        let body = exit_selection_body(&format!(" {id} "), "", true).unwrap();
        assert_eq!(body["ipv4_gateway"], id.to_string());
        assert!(body["ipv6_gateway"].is_null());
        assert_eq!(body["kill_switch"], true);
    }

    #[test]
    fn every_page_renders_offline_at_minimum_window_size() {
        let context = egui::Context::default();
        let mut app = App::default();
        for language in [Language::Chinese, Language::English] {
            app.settings.language = language;
            for page in Page::ALL {
                app.page = page;
                let input = egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(560.0, 480.0),
                    )),
                    ..Default::default()
                };
                let output = context.run(input, |context| {
                    egui::CentralPanel::default().show(context, |ui| {
                        app.render_page(context, ui);
                    });
                });
                assert!(!output.shapes.is_empty(), "{page:?} has no UI");
            }
        }
    }

    #[test]
    fn complete_shell_keeps_content_accessible_with_zoom_and_short_windows() {
        // Logical points: the smallest supported window at 150% UI zoom,
        // the normal minimum, a short wide window, and a desktop window.
        for size in [
            egui::vec2(507.0, 347.0),
            egui::vec2(760.0, 520.0),
            egui::vec2(1280.0, 347.0),
            egui::vec2(1280.0, 800.0),
        ] {
            for language in [Language::Chinese, Language::English] {
                for theme in [design::Theme::Light, design::Theme::Dark] {
                    let context = egui::Context::default();
                    let mut app = App::default();
                    app.settings.language = language;
                    app.settings.theme = theme;
                    design::apply_theme(&context, &app.settings);
                    for page in Page::ALL {
                        app.page = page;
                        let viewport = egui::Rect::from_min_size(egui::Pos2::ZERO, size);
                        let mut content = egui::Rect::NOTHING;
                        let output = context.run(
                            egui::RawInput {
                                screen_rect: Some(viewport),
                                ..Default::default()
                            },
                            |ctx| {
                                content = app.render_shell(ctx);
                            },
                        );
                        assert!(!output.shapes.is_empty());
                        assert!(
                            content.width() >= size.x * 0.65,
                            "{page:?}: {content:?} at {size:?}"
                        );
                        assert!(
                            content.height() >= 120.0,
                            "{page:?}: {content:?} at {size:?}"
                        );
                        assert!(
                            viewport.expand(1.0).contains_rect(content),
                            "{page:?}: {content:?} at {size:?}"
                        );
                    }
                }
            }
        }
    }

    fn generated_test_ca_pem() -> String {
        let rcgen::CertifiedKey { cert, .. } =
            rcgen::generate_simple_self_signed(vec!["planet.example.com".into()]).unwrap();
        cert.pem()
    }

    fn invitation(controller: &str, planet: Option<&str>, tls_ca: Option<&str>) -> String {
        let mut link = Url::parse("meshlake://join").unwrap();
        link.query_pairs_mut()
            .append_pair("controller", controller)
            .append_pair("network_id", "2a2d7ed1-5a22-4f60-b6c5-573ac589c514")
            .append_pair("token", "single-use")
            .append_pair("public_key", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=");
        if let Some(planet) = planet {
            link.query_pairs_mut().append_pair("planet", planet);
        }
        if let Some(tls_ca) = tls_ca {
            link.query_pairs_mut()
                .append_pair("tls_ca", &STANDARD.encode(tls_ca.as_bytes()));
        }
        link.into()
    }

    #[test]
    fn base64_controller_key_decodes() {
        assert_eq!(STANDARD.decode("AQIDBA==").unwrap(), vec![1, 2, 3, 4]);
    }

    #[test]
    fn invitation_private_ca_is_normalized_and_kept_with_planet() {
        let pem = generated_test_ca_pem();
        let normalized = normalize_tls_ca_pem(&pem).unwrap();
        let parsed = parse_invite_link(&invitation(
            "https://planet.example.com/",
            Some("https://planet.example.com/v1/planet"),
            Some(&pem),
        ))
        .unwrap();
        assert_eq!(parsed.controller, "https://planet.example.com");
        assert_eq!(
            parsed.planet_manifest_url.as_deref(),
            Some("https://planet.example.com/v1/planet")
        );
        assert_eq!(parsed.tls_ca_pem.as_deref(), Some(normalized.as_str()));
        assert!(controller_http_client(parsed.tls_ca_pem.as_deref()).is_ok());
    }

    #[test]
    fn invitation_rejects_private_ca_over_plain_http() {
        let pem = generated_test_ca_pem();
        assert!(
            parse_invite_link(&invitation("http://planet.example.com", None, Some(&pem),)).is_err()
        );
        assert!(parse_invite_link(&invitation(
            "https://planet.example.com",
            Some("http://planet.example.com/v1/planet"),
            Some(&pem),
        ))
        .is_err());
    }

    #[test]
    fn invitation_ca_conflict_is_rejected_instead_of_overwriting_configuration() {
        let invitation = normalize_tls_ca_pem(&generated_test_ca_pem()).unwrap();
        let configured = normalize_tls_ca_pem(&generated_test_ca_pem()).unwrap();
        assert_ne!(invitation, configured);
        assert!(select_effective_tls_ca(Some(&invitation), Some(&configured)).is_err());

        assert_eq!(
            select_effective_tls_ca(None, Some(&configured)).unwrap(),
            Some(configured.clone())
        );
        assert_eq!(
            select_effective_tls_ca(Some(&invitation), Some(&invitation)).unwrap(),
            Some(invitation)
        );
    }

    #[test]
    fn controller_url_rejects_credentials_query_fragment_and_paths() {
        assert!(controller_base_url("https://user@example.com", false).is_err());
        assert!(controller_base_url("https://@example.com", false).is_err());
        assert!(controller_base_url("https://example.com\\", false).is_err());
        assert!(controller_base_url("https://example.com?token=x", false).is_err());
        assert!(controller_base_url("https://example.com#fragment", false).is_err());
        assert!(controller_base_url("https://example.com/controller", false).is_err());
    }

    #[test]
    fn controller_url_is_returned_in_normalized_form() {
        assert_eq!(
            controller_base_url("HTTPS://EXAMPLE.COM:443/", false).unwrap(),
            "https://example.com"
        );
    }

    #[test]
    fn public_controller_requests_never_include_the_admin_token() {
        let mut app = App::default();
        app.admin_token = "local-administrator-token".into();
        app.admin_token_bound_value = app.admin_token.clone();
        app.admin_token_controller = Some(app.controller.clone());

        let request = app
            .controller_request(reqwest::Method::GET, "/v1/public-key".into(), false)
            .unwrap()
            .build()
            .unwrap();
        assert!(!request.headers().contains_key("x-meshlake-admin-token"));
    }

    #[test]
    fn local_admin_token_is_not_sent_to_a_remote_controller() {
        let mut app = App::default();
        app.admin_token = "local-administrator-token".into();
        app.admin_token_bound_value = app.admin_token.clone();
        app.admin_token_controller = Some(app.controller.clone());
        app.controller = "https://remote.example.com".into();

        let error = app
            .controller_request(reqwest::Method::POST, "/v1/networks".into(), true)
            .unwrap_err();
        assert!(error.contains("另一个控制器"));
    }

    #[test]
    fn reentered_admin_token_binds_only_to_the_current_controller() {
        let mut app = App::default();
        app.admin_token = "local-administrator-token".into();
        app.admin_token_bound_value = app.admin_token.clone();
        app.admin_token_controller = Some(app.controller.clone());
        app.controller = "https://remote.example.com".into();

        app.admin_token = "remote-administrator-token".into();
        let request = app
            .controller_request(reqwest::Method::POST, "/v1/networks".into(), true)
            .unwrap()
            .build()
            .unwrap();
        assert_eq!(
            request
                .headers()
                .get("x-meshlake-admin-token")
                .unwrap()
                .to_str()
                .unwrap(),
            "remote-administrator-token"
        );
        assert_eq!(
            app.admin_token_controller.as_deref(),
            Some("https://remote.example.com")
        );
    }

    #[test]
    fn switching_invitation_controller_clears_the_old_management_context() {
        let mut app = App::default();
        app.admin_token = "local-administrator-token".into();
        app.admin_token_bound_value = app.admin_token.clone();
        app.admin_token_controller = Some(app.controller.clone());
        app.controller_public_key = "old-public-key".into();
        app.controller_tls_ca_pem = "old-private-ca".into();
        app.managed_networks.push(VirtualNetwork {
            id: meshlake_core::NetworkId(Uuid::new_v4()),
            name: "old-network".into(),
            ipv4_prefix: "100.64.10.0/24".into(),
            ipv6_prefix: None,
            relay_policy: RelayPolicy::Preferred,
        });
        app.selected_network = Some(Uuid::new_v4());
        app.members.push(MembershipClaims {
            network_id: meshlake_core::NetworkId(Uuid::new_v4()),
            device_id: meshlake_core::DeviceId(Uuid::new_v4()),
            device_public_key: vec![7; 32],
            assigned_addresses: vec!["100.64.10.2".parse().unwrap()],
            allowed_routes: vec!["100.64.10.0/24".into()],
            issued_at_unix_seconds: 1,
            expires_at_unix_seconds: Some(2),
        });
        app.issued_token = "old-issued-token".into();
        app.generated_invite = "old-invitation".into();
        app.controller_document = "old-controller-document".into();

        app.switch_controller_context("https://remote.example.com".into());

        assert_eq!(app.controller, "https://remote.example.com");
        assert!(app.admin_token.is_empty());
        assert!(app.admin_token_bound_value.is_empty());
        assert!(app.admin_token_controller.is_none());
        assert!(app.controller_public_key.is_empty());
        assert!(app.controller_tls_ca_pem.is_empty());
        assert!(app.managed_networks.is_empty());
        assert!(app.selected_network.is_none());
        assert!(app.members.is_empty());
        assert!(app.issued_token.is_empty());
        assert!(app.generated_invite.is_empty());
        assert!(app.controller_document.is_empty());
    }

    #[test]
    fn plaintext_controller_state_remains_readable() {
        let state = serde_json::to_vec(&LocalControllerState {
            admin_token: "legacy-admin-token".into(),
        })
        .unwrap();
        assert_eq!(
            decode_local_admin_token(&state).as_deref(),
            Some("legacy-admin-token")
        );
    }

    #[cfg(windows)]
    #[test]
    fn dpapi_controller_state_is_readable() {
        let state = LocalControllerState {
            admin_token: "protected-admin-token".into(),
        };
        let protected =
            meshlake_core::encode_protected_state(&state, CONTROLLER_STATE_PROTECTION_PURPOSE)
                .unwrap();
        assert_eq!(
            decode_local_admin_token(&protected).as_deref(),
            Some("protected-admin-token")
        );
    }
}
