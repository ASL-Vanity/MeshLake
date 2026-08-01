#![cfg_attr(target_os = "windows", windows_subsystem = "windows")]

//! Native Windows UI. All persistent state and networking remain in `meshlaked`.

use base64::{engine::general_purpose::STANDARD, Engine as _};
use eframe::egui;
use meshlake_core::{
    decode_protected_state, AgentStatus, EnrollmentResponse, MembershipClaims, RelayPolicy,
    UpsertNetworkRequest, VirtualNetwork, CONTROLLER_STATE_PROTECTION_PURPOSE,
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
    UI::{
        Shell::ShellExecuteW,
        WindowsAndMessaging::{
            FindWindowW, SetForegroundWindow, ShowWindow, SW_RESTORE, SW_SHOWNORMAL,
        },
    },
};

const LOCAL_API: &str = "http://127.0.0.1:51821/v1";

fn main() {
    #[cfg(target_os = "windows")]
    match relaunch_with_administrator_rights() {
        Ok(true) => {}
        Ok(false) => return,
        Err(error) => {
            write_startup_error(&error);
            return;
        }
    }
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

/// Wintun adapter creation requires an elevated token.  Relaunch before any
/// background process is started so `meshlaked` inherits the same token.
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
    eframe::run_native(
        "MeshLake",
        eframe::NativeOptions {
            viewport: egui::ViewportBuilder::default().with_inner_size([940.0, 640.0]),
            ..Default::default()
        },
        Box::new(|context| Ok(Box::new(App::new(context)))),
    )
}

struct App {
    client: Client,
    status: Option<AgentStatus>,
    message: String,
    name: String,
    prefix: String,
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
    issued_token: String,
    invite_link: String,
    settings: Settings,
    show_settings: bool,
    show_close_confirmation: bool,
    dont_ask_again: bool,
    tray: Option<Tray>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum Language {
    Chinese,
    English,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Settings {
    language: Language,
    minimize_on_close: bool,
    ask_on_close: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
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
            client: Client::builder()
                .timeout(Duration::from_secs(5))
                .build()
                .unwrap(),
            status: None,
            message: "点击“刷新状态”以连接本机 meshlaked 服务。".into(),
            name: String::new(),
            prefix: "100.64.10.0/24".into(),
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
            issued_token: String::new(),
            invite_link: std::env::args()
                .nth(1)
                .filter(|value| value.starts_with("meshlake://"))
                .unwrap_or_default(),
            settings: load_settings(),
            show_settings: false,
            show_close_confirmation: false,
            dont_ask_again: false,
            tray: None,
        }
    }
}

impl App {
    fn new(context: &eframe::CreationContext<'_>) -> Self {
        install_chinese_font(&context.egui_ctx);
        ensure_agent_running();
        ensure_local_controller_running();
        let mut app = Self::default();
        app.admin_token = load_local_admin_token().unwrap_or_default();
        app.admin_token_bound_value = app.admin_token.clone();
        if !app.admin_token.is_empty() {
            app.admin_token_controller = Some(app.controller.clone());
        }
        app.refresh_controller_public_key(false);
        if !app.controller_public_key.is_empty() {
            app.public_key = app.controller_public_key.clone();
        }
        app.tray = create_tray(&context.egui_ctx);
        app
    }

    fn refresh(&mut self) {
        match self.client.get(format!("{LOCAL_API}/status")).send() {
            Ok(response) if response.status().is_success() => match response.json() {
                Ok(status) => {
                    self.status = Some(status);
                    self.message = "已连接到本机 MeshLake 后台服务。".into();
                }
                Err(error) => self.message = format!("后台响应格式无效：{error}"),
            },
            Ok(response) => self.message = format!("后台服务返回：{}", response.status()),
            Err(_) => {
                self.status = None;
                self.message = "未检测到 meshlaked。请先启动 meshlaked.exe run。".into();
            }
        }
    }

    fn adapter(&mut self, start: bool) {
        let request = if start {
            self.client.post(format!("{LOCAL_API}/adapter"))
        } else {
            self.client.delete(format!("{LOCAL_API}/adapter"))
        };
        match request.send() {
            Ok(response) if response.status().is_success() => {
                self.message = if start {
                    "网卡已启动并已同步已分配的 IPv4 地址。".into()
                } else {
                    "网卡会话已停止。".into()
                };
                self.refresh();
            }
            Ok(response) => {
                self.message = response.text().unwrap_or_else(|_| "网卡操作失败。".into())
            }
            Err(error) => self.message = format!("无法联系后台服务：{error}"),
        }
    }

    fn join_network(&mut self, planet_manifest_url: Option<String>) {
        ensure_local_controller_running();
        let network_id = match Uuid::parse_str(self.network_id.trim()) {
            Ok(id) => id,
            Err(_) => {
                self.message = "网络 ID 必须是 UUID。".into();
                return;
            }
        };
        let (device_id, device_public_key) = match &self.status {
            Some(status) => (status.device_id.0, status.identity_public_key.clone()),
            None => {
                self.message = "请先刷新状态。".into();
                return;
            }
        };
        let key = match STANDARD.decode(self.public_key.trim()) {
            Ok(key) if key.len() == 32 => key,
            _ => {
                self.message = "控制器公钥必须是 32 字节 Base64 值。".into();
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
        let enrollment_client = match controller_http_client(tls_ca_pem.as_deref()) {
            Ok(client) => client,
            Err(error) => {
                self.message = format!("无法创建安全控制器连接：{error}");
                return;
            }
        };
        let enrollment: EnrollmentResponse = match enrollment_client.post(format!("{controller}/v1/enroll")).json(&json!({"network_id": network_id, "device_id": device_id, "device_public_key": device_public_key, "token": self.token.trim()})).send() {
            Ok(response) if response.status().is_success() => match response.json() {
                Ok(value) => value,
                Err(error) => { self.message = format!("控制器返回格式无效：{error}"); return; }
            },
            Ok(response) => { self.message = response.text().unwrap_or_else(|_| "控制器拒绝入网。".into()); return; }
            Err(error) => { self.message = format!("无法联系控制器：{error}"); return; }
        };
        match self
            .client
            .post(format!("{LOCAL_API}/networks/enroll"))
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
                self.message = "已安全加入控制器网络。".into();
                self.token.clear();
                self.refresh();
            }
            Ok(response) => {
                self.message = response
                    .text()
                    .unwrap_or_else(|_| "后台拒绝入网记录。".into())
            }
            Err(error) => self.message = format!("无法联系后台服务：{error}"),
        }
    }

    fn join_invite_link(&mut self) {
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
        self.join_network(invitation.planet_manifest_url);
    }

    fn configure_relay(&mut self) {
        match self
            .client
            .post(format!("{LOCAL_API}/relay"))
            .json(&json!({
                "endpoint": self.relay_endpoint.trim(),
                "enable_upnp": self.upnp_enabled,
                "stun_servers": self.stun_servers.split(',').map(str::trim).filter(|value| !value.is_empty()).collect::<Vec<_>>(),
            }))
            .send()
        {
            Ok(response) if response.status().is_success() => {
                self.message = "中继地址已保存并自动应用。".into();
            }
            Ok(response) => {
                self.message = response
                    .text()
                    .unwrap_or_else(|_| "保存中继地址失败。".into())
            }
            Err(error) => self.message = format!("无法联系后台服务：{error}"),
        }
    }

    fn configure_planet(&mut self) {
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
            .post(format!("{LOCAL_API}/planet"))
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
            Ok(response) => {
                self.message = response
                    .text()
                    .unwrap_or_else(|_| "保存行星服务器配置失败。".into())
            }
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
        let request = client.request(method, format!("{controller}{path}"));
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
        }
        self.controller = controller;
    }

    fn refresh_controller_public_key(&mut self, show_message: bool) {
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
                    Err(error) if show_message => {
                        self.message = format!("控制器公钥响应无效：{error}");
                    }
                    Err(_) => {}
                }
            }
            Ok(response) if show_message => {
                self.message = response
                    .text()
                    .unwrap_or_else(|_| "读取控制器公钥失败。".into());
            }
            Err(error) if show_message => {
                self.message = format!("无法联系控制器：{error}");
            }
            _ => {}
        }
    }

    fn refresh_managed_networks(&mut self) {
        ensure_local_controller_running();
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
                Err(error) => self.message = format!("控制器响应格式无效：{error}"),
            },
            Ok(response) => {
                self.message = response
                    .text()
                    .unwrap_or_else(|_| "读取控制器网络失败。".into())
            }
            Err(error) => self.message = format!("无法联系控制器：{error}"),
        }
    }

    fn create_managed_network(&mut self) {
        ensure_local_controller_running();
        let network_request = UpsertNetworkRequest {
            id: None,
            name: self.name.trim().to_owned(),
            ipv4_prefix: self.prefix.trim().to_owned(),
            ipv6_prefix: None,
            relay_policy: RelayPolicy::Preferred,
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
                self.refresh_managed_networks();
            }
            Ok(response) => {
                self.message = response
                    .text()
                    .unwrap_or_else(|_| "创建控制器网络失败。".into())
            }
            Err(error) => self.message = format!("无法联系控制器：{error}"),
        }
    }

    fn delete_managed_network(&mut self, id: Uuid) {
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
                self.refresh_managed_networks();
            }
            Ok(response) => {
                self.message = response.text().unwrap_or_else(|_| "删除网络失败。".into())
            }
            Err(error) => self.message = format!("无法联系控制器：{error}"),
        }
    }

    fn issue_enrollment_token(&mut self, id: Uuid) {
        ensure_local_controller_running();
        self.refresh_controller_public_key(false);
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
            Ok(request) => request.json(&json!({"expires_in_seconds": 900})),
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
                        self.invite_link = match token.invite_link {
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
                        self.message = self
                            .t(
                                "已生成 15 分钟有效的一次性入网令牌。",
                                "A 15-minute invitation link was created.",
                            )
                            .into();
                    }
                    Err(error) => self.message = format!("令牌响应格式无效：{error}"),
                }
            }
            Ok(response) => {
                self.message = response
                    .text()
                    .unwrap_or_else(|_| "生成入网令牌失败。".into())
            }
            Err(error) => self.message = format!("无法联系控制器：{error}"),
        }
    }

    fn load_members(&mut self, id: Uuid) {
        ensure_local_controller_running();
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
                Err(error) => self.message = format!("成员响应格式无效：{error}"),
            },
            Ok(response) => {
                self.message = response.text().unwrap_or_else(|_| "读取成员失败。".into())
            }
            Err(error) => self.message = format!("无法联系控制器：{error}"),
        }
    }

    fn remove_member(&mut self, network_id: Uuid, device_id: Uuid) {
        ensure_local_controller_running();
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
                self.load_members(network_id);
            }
            Ok(response) => {
                self.message = response.text().unwrap_or_else(|_| "移除成员失败。".into())
            }
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
    let mut builder = Client::builder()
        .timeout(Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none());
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
        if context.input(|input| input.viewport().close_requested()) {
            context.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            if self.settings.minimize_on_close {
                context.send_viewport_cmd(egui::ViewportCommand::Visible(false));
            } else if self.settings.ask_on_close {
                self.show_close_confirmation = true;
            } else {
                shutdown_all_meshlake_and_exit();
            }
        }
        egui::TopBottomPanel::top("top").show(context, |ui| {
            ui.horizontal(|ui| {
                ui.heading("MeshLake");
                ui.label(self.t(
                    "连接万物的湖泊 · Windows 管理端",
                    "Lake of Connecting Everything · Windows Manager",
                ));
                if ui.button(self.t("刷新状态", "Refresh")).clicked() {
                    self.refresh();
                }
                if ui.button(self.t("设置", "Settings")).clicked() {
                    self.show_settings = true;
                }
            });
        });
        egui::CentralPanel::default().show(context, |ui| {
            ui.label(&self.message);
            ui.separator();
            ui.heading("本机后台与虚拟网卡");
            if let Some(status) = self.status.clone() {
                ui.label(format!("设备 ID：{}", status.device_id.0));
                ui.label(format!("网卡状态：{}", status.adapter_state));
                ui.horizontal(|ui| {
                    if ui.button("启动网卡").clicked() {
                        self.adapter(true);
                    }
                    if ui.button("停止网卡").clicked() {
                        self.adapter(false);
                    }
                });
                ui.horizontal(|ui| {
                    ui.label("UDP 协调 / 中继地址");
                    ui.text_edit_singleline(&mut self.relay_endpoint);
                    if ui.button("保存中继").clicked() {
                        self.configure_relay();
                    }
                });
                ui.checkbox(&mut self.upnp_enabled, "启用 UPnP 自动映射 UDP 端口");
                ui.horizontal(|ui| {
                    ui.label("STUN 服务器（可选，逗号分隔）");
                    ui.text_edit_singleline(&mut self.stun_servers);
                });
                ui.small("例如 stun.example.com:3478。用于发现公网 UDP 候选；无法直连时仍自动使用中继。");
                ui.collapsing("行星服务器（推荐）", |ui| {
                    ui.label("受签名的 Planet 清单会自动配置控制器、中继和 STUN 节点。");
                    ui.horizontal(|ui| {
                        ui.label("清单 URL");
                        ui.text_edit_singleline(&mut self.planet_manifest);
                    });
                    ui.horizontal(|ui| {
                        ui.label("控制器公钥（Base64）");
                        ui.text_edit_singleline(&mut self.planet_public_key);
                        if ui.button("保存行星配置").clicked() {
                            self.configure_planet();
                        }
                    });
                    ui.small("公钥必须由服务器管理员通过可信渠道提供；不要只相信网页返回的公钥。");
                });
                ui.separator();
                ui.heading(format!("已加入网络（{}）", status.networks.len()));
                for network in &status.networks {
                    ui.label(format!(
                        "{} · {} · 地址：{}",
                        network.network.name,
                        network.network.ipv4_prefix,
                        network
                            .assigned_addresses
                            .iter()
                            .map(ToString::to_string)
                            .collect::<Vec<_>>()
                            .join(", ")
                    ));
                }
            } else {
                ui.label("GUI 关闭不会停止正在运行的后台服务。");
            }
            ui.collapsing(
                self.t(
                    "私有控制器 / Planet CA（高级）",
                    "Private controller / Planet CA (advanced)",
                ),
                |ui| {
                    ui.label(self.t(
                        "仅在控制器使用私有 CA 签发 HTTPS 证书时粘贴 PEM。邀请链接中的 CA 会自动填入这里，并按网络保存到后台。",
                        "Paste PEM only when the controller HTTPS certificate is issued by a private CA. An invitation CA is filled here automatically and stored per network by the agent.",
                    ));
                    ui.add(
                        egui::TextEdit::multiline(&mut self.controller_tls_ca_pem)
                            .desired_rows(4)
                            .desired_width(780.0)
                            .hint_text("-----BEGIN CERTIFICATE-----"),
                    );
                },
            );
            ui.separator();
            ui.collapsing(
                self.t("控制器网络管理", "Controller network management"),
                |ui| {
                    ui.label(self.t(
                        "管理员令牌仅保存在本次 GUI 运行内。",
                        "The administrator token is kept only for this GUI session.",
                    ));
                    ui.colored_label(
                        egui::Color32::YELLOW,
                        self.t(
                            "注意：移除成员会轮换网络密钥并更新签名授权清单。正常在线客户端通常在约 20 秒内停用该成员；拒绝刷新客户端的最坏窗口由 90 秒授权租约限定。",
                            "Removing a member rotates the network key and updates the signed authorization manifest. Normal online clients usually enforce it within about 20 seconds; the worst case for a non-refreshing client is bounded by the 90-second authorization lease.",
                        ),
                    );
                    egui::Grid::new("controller-admin")
                        .num_columns(2)
                        .show(ui, |ui| {
                            ui.label(self.t("控制器 URL", "Controller URL"));
                            ui.text_edit_singleline(&mut self.controller);
                            ui.end_row();
                            ui.label(self.t("管理员令牌", "Administrator token"));
                            ui.add(
                                egui::TextEdit::singleline(&mut self.admin_token).password(true),
                            );
                            ui.end_row();
                        });
                    ui.horizontal(|ui| {
                        ui.label(self.t("控制器公钥 (Base64)", "Controller public key (Base64)"));
                        ui.add(
                            egui::TextEdit::singleline(&mut self.controller_public_key)
                                .desired_width(430.0)
                                .interactive(false),
                        );
                        if ui.button(self.t("读取公钥", "Load key")).clicked() {
                            self.refresh_controller_public_key(true);
                        }
                        if ui.button(self.t("复制", "Copy")).clicked()
                            && !self.controller_public_key.is_empty()
                        {
                            context.copy_text(self.controller_public_key.clone());
                            self.message = self.t("控制器公钥已复制到剪贴板。", "Controller public key copied to clipboard.").into();
                        }
                    });
                    ui.small(self.t(
                        "设备会先尝试 UDP 打洞直连；遇到对称 NAT 或受限网络时，自动经此中继转发。",
                        "MeshLake tries UDP hole punching first and automatically falls back to this relay for symmetric NATs or restrictive networks.",
                    ));
                    ui.small(self.t(
                        "这是可公开分发的验证公钥；不要分享管理员令牌或 controller.json 文件。",
                        "This verification key may be shared. Never share the administrator token or controller.json file.",
                    ));
                    if ui.button(self.t("将此公钥填入“加入网络”", "Use this key for joining")).clicked()
                        && !self.controller_public_key.is_empty()
                    {
                        self.public_key = self.controller_public_key.clone();
                    }
                    if ui
                        .button(self.t("刷新控制器网络", "Refresh controller networks"))
                        .clicked()
                    {
                        self.refresh_managed_networks();
                    }
                    ui.horizontal(|ui| {
                        ui.label(self.t("新网络名称", "New network name"));
                        ui.text_edit_singleline(&mut self.name);
                        ui.label(self.t("IPv4 前缀", "IPv4 prefix"));
                        ui.text_edit_singleline(&mut self.prefix);
                        if ui
                            .button(self.t("在控制器创建", "Create on controller"))
                            .clicked()
                        {
                            self.create_managed_network();
                        }
                    });
                    for network in self.managed_networks.clone() {
                        ui.group(|ui| {
                            ui.label(format!(
                                "{} · {} · {}",
                                network.name, network.id.0, network.ipv4_prefix
                            ));
                            ui.horizontal(|ui| {
                                if ui
                                    .button(self.t("生成邀请链接", "Create invitation link"))
                                    .clicked()
                                {
                                    self.issue_enrollment_token(network.id.0);
                                }
                                if ui.button(self.t("查看成员", "View members")).clicked() {
                                    self.load_members(network.id.0);
                                }
                                if ui.button(self.t("删除网络", "Delete network")).clicked() {
                                    self.delete_managed_network(network.id.0);
                                }
                            });
                        });
                    }
                    if !self.invite_link.is_empty() {
                        ui.label(self.t(
                            "最新邀请链接（15 分钟有效，仅供一台设备使用）：",
                            "Latest invitation link (valid for 15 minutes, for one device only):",
                        ));
                        ui.horizontal(|ui| {
                            ui.add(
                                egui::TextEdit::singleline(&mut self.invite_link)
                                    .desired_width(620.0)
                                    .interactive(false),
                            );
                            if ui.button(self.t("复制链接", "Copy link")).clicked() {
                                context.copy_text(self.invite_link.clone());
                                self.message = self.t("邀请链接已复制到剪贴板。", "Invitation link copied to clipboard.").into();
                            }
                        });
                    }
                    if let Some(network_id) = self.selected_network {
                        ui.label(format!("{} {network_id}", self.t("成员列表：", "Members:")));
                        for member in self.members.clone() {
                            ui.horizontal(|ui| {
                                ui.label(format!(
                                    "{} · {}",
                                    member.device_id.0,
                                    member
                                        .assigned_addresses
                                        .iter()
                                        .map(ToString::to_string)
                                        .collect::<Vec<_>>()
                                        .join(", ")
                                ));
                                if ui.button(self.t("移除成员", "Remove member")).clicked() {
                                    self.remove_member(network_id, member.device_id.0);
                                }
                            });
                        }
                    }
                },
            );
            ui.separator();
            ui.heading("加入控制器网络");
            ui.label(self.t(
                "推荐：粘贴管理员发来的邀请链接，软件会自动读取控制器、网络、公钥和一次性令牌。",
                "Recommended: paste an invitation link from the administrator. MeshLake reads the controller, network, public key, and token automatically.",
            ));
            ui.horizontal(|ui| {
                ui.add(egui::TextEdit::singleline(&mut self.invite_link).desired_width(680.0));
                if ui.button(self.t("通过链接加入", "Join from link")).clicked() {
                    self.join_invite_link();
                }
            });
            ui.small(self.t(
                "邀请链接相当于一次性入网凭据，请只通过可信渠道发送；它只能由首个使用的设备重试。",
                "An invitation link is a one-time enrollment credential. Send it only through a trusted channel; it can be retried only by the first device that uses it.",
            ));
            ui.separator();
            ui.collapsing(self.t("手动加入（高级）", "Manual join (advanced)"), |ui| {
            ui.label("控制器公钥必须由管理员通过可信渠道提供。不要信任未核验网页给出的公钥。");
            egui::Grid::new("join").num_columns(2).show(ui, |ui| {
                ui.label("控制器 URL");
                ui.text_edit_singleline(&mut self.controller);
                ui.end_row();
                ui.label("网络 ID");
                ui.text_edit_singleline(&mut self.network_id);
                ui.end_row();
                ui.label("一次性令牌");
                ui.add(egui::TextEdit::singleline(&mut self.token).password(true));
                ui.end_row();
                ui.label("控制器公钥 (Base64)");
                ui.add(egui::TextEdit::singleline(&mut self.public_key).password(true));
                ui.end_row();
            });
            if ui.button("安全加入网络").clicked() {
                self.join_network(None);
            }
            });
        });

        if self.show_settings {
            let mut open = self.show_settings;
            let before = self.settings.clone();
            let minimize_label = self.t(
                "点击关闭按钮时默认最小化到托盘",
                "Minimize to tray when closing the window",
            );
            let ask_label = self.t("关闭时询问", "Ask when closing");
            egui::Window::new(self.t("设置", "Settings"))
                .open(&mut open)
                .resizable(false)
                .show(context, |ui| {
                    ui.heading(self.t("语言", "Language"));
                    ui.selectable_value(&mut self.settings.language, Language::Chinese, "简体中文");
                    ui.selectable_value(&mut self.settings.language, Language::English, "English");
                    ui.separator();
                    ui.checkbox(&mut self.settings.minimize_on_close, minimize_label);
                    ui.checkbox(&mut self.settings.ask_on_close, ask_label);
                });
            self.show_settings = open;
            if before.language != self.settings.language
                || before.minimize_on_close != self.settings.minimize_on_close
                || before.ask_on_close != self.settings.ask_on_close
            {
                save_settings(&self.settings);
            }
        }

        if self.show_close_confirmation {
            let (title, text, minimize, exit, never) = match self.settings.language {
                Language::Chinese => ("关闭 MeshLake", "请选择最小化到系统托盘，或完全退出 MeshLake 并结束后台网络服务。", "最小化到托盘", "完全退出 MeshLake", "不再询问"),
                Language::English => ("Close MeshLake", "Minimize to the system tray, or fully exit MeshLake and stop its background network services.", "Minimize to tray", "Fully exit MeshLake", "Don't ask again"),
            };
            let mut action = None;
            egui::Window::new(title)
                .collapsible(false)
                .resizable(false)
                .show(context, |ui| {
                    ui.label(text);
                    ui.checkbox(&mut self.dont_ask_again, never);
                    ui.horizontal(|ui| {
                        if ui.button(minimize).clicked() {
                            action = Some(true);
                        }
                        if ui.button(exit).clicked() {
                            action = Some(false);
                        }
                    });
                });
            if let Some(minimize) = action {
                self.show_close_confirmation = false;
                if self.dont_ask_again {
                    self.settings.minimize_on_close = minimize;
                    self.settings.ask_on_close = false;
                    save_settings(&self.settings);
                }
                if minimize {
                    context.send_viewport_cmd(egui::ViewportCommand::Visible(false));
                } else {
                    shutdown_all_meshlake_and_exit();
                }
            }
        }
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

fn install_chinese_font(context: &egui::Context) {
    let paths = [
        PathBuf::from(r"C:\Windows\Fonts\NotoSansSC-VF.ttf"),
        PathBuf::from(r"C:\Windows\Fonts\simhei.ttf"),
        PathBuf::from(r"C:\Windows\Fonts\msyh.ttc"),
    ];
    let Some(bytes) = paths.iter().find_map(|path| fs::read(path).ok()) else {
        return;
    };
    let mut fonts = egui::FontDefinitions::default();
    fonts.font_data.insert(
        "meshlake-chinese".into(),
        egui::FontData::from_owned(bytes).into(),
    );
    for family in [egui::FontFamily::Proportional, egui::FontFamily::Monospace] {
        fonts
            .families
            .entry(family)
            .or_default()
            .insert(0, "meshlake-chinese".into());
    }
    context.set_fonts(fonts);
}

fn ensure_agent_running() {
    if TcpStream::connect_timeout(
        &"127.0.0.1:51821".parse().unwrap(),
        Duration::from_millis(100),
    )
    .is_ok()
    {
        return;
    }
    let Some(executable) = std::env::current_exe().ok() else {
        return;
    };
    let Some(folder) = executable.parent() else {
        return;
    };
    let agent = folder.join("meshlaked.exe");
    if !agent.is_file() {
        return;
    }
    #[cfg(target_os = "windows")]
    use std::os::windows::process::CommandExt;
    let mut command = Command::new(agent);
    command.arg("run");
    #[cfg(target_os = "windows")]
    command.creation_flags(0x08000000); // CREATE_NO_WINDOW
    let _ = command.spawn();
}

fn ensure_local_controller_running() {
    if TcpStream::connect_timeout(
        &"127.0.0.1:51822".parse().unwrap(),
        Duration::from_millis(100),
    )
    .is_ok()
    {
        return;
    }
    let Some(executable) = std::env::current_exe().ok() else {
        return;
    };
    let Some(folder) = executable.parent() else {
        return;
    };
    let controller = folder.join("meshlake-controller.exe");
    if !controller.is_file() {
        return;
    }
    #[cfg(target_os = "windows")]
    use std::os::windows::process::CommandExt;
    let mut command = Command::new(controller);
    #[cfg(target_os = "windows")]
    command.creation_flags(0x08000000); // CREATE_NO_WINDOW
    if command.spawn().is_ok() {
        for _ in 0..15 {
            std::thread::sleep(Duration::from_millis(100));
            if TcpStream::connect_timeout(
                &"127.0.0.1:51822".parse().unwrap(),
                Duration::from_millis(100),
            )
            .is_ok()
            {
                break;
            }
        }
    }
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

fn shutdown_all_meshlake_and_exit() {
    std::thread::spawn(move || {
        let _ = Client::builder()
            .timeout(Duration::from_secs(2))
            .build()
            .and_then(|client| client.post(format!("{LOCAL_API}/shutdown")).send());
        for process in [
            "meshlaked.exe",
            "meshlake-controller.exe",
            "meshlake-root.exe",
            "meshlake-relay.exe",
        ] {
            let mut command = Command::new("taskkill");
            #[cfg(target_os = "windows")]
            {
                use std::os::windows::process::CommandExt;
                command.creation_flags(0x08000000); // CREATE_NO_WINDOW
            }
            let _ = command.args(["/IM", process, "/T", "/F"]).output();
        }
        // Do not rely on a window-close event here: when the main viewport is
        // hidden, eframe may keep its event loop (and tray icon) alive. Ending
        // this process explicitly lets Windows remove the icon as well.
        std::process::exit(0);
    });
}

fn create_tray(context: &egui::Context) -> Option<Tray> {
    let menu = Menu::new();
    let show = MenuItem::new("显示 MeshLake", true, None);
    let exit = MenuItem::new("完全退出 MeshLake", true, None);
    menu.append(&show).ok()?;
    menu.append(&exit).ok()?;
    let icon = Icon::from_rgba(vec![30, 144, 255, 255].repeat(32 * 32), 32, 32).ok()?;
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
            show_native_window();
            context.send_viewport_cmd(egui::ViewportCommand::Visible(true));
            context.request_repaint();
        } else if event.id == exit_id {
            shutdown_all_meshlake_and_exit();
        }
    }));
    Some(Tray { _icon: tray })
}

#[cfg(target_os = "windows")]
fn meshlake_window() -> *mut std::ffi::c_void {
    let title: Vec<u16> = "MeshLake\0".encode_utf16().collect();
    unsafe { FindWindowW(std::ptr::null(), title.as_ptr()) }
}

#[cfg(not(target_os = "windows"))]
fn meshlake_window() -> *mut std::ffi::c_void {
    std::ptr::null_mut()
}

fn show_native_window() {
    let window = meshlake_window();
    if !window.is_null() {
        unsafe {
            ShowWindow(window, SW_RESTORE);
            SetForegroundWindow(window);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
