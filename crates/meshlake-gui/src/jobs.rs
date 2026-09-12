use super::*;
use std::sync::mpsc::{self, Receiver, TryRecvError};

pub(super) struct WorkerSnapshot {
    request_timeout: u64,
    policy_editor: controller_policy::PolicyEditor,
    generated_invite: String,
    controller_document: String,
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
impl WorkerSnapshot {
    fn capture(app: &App) -> Self {
        Self {
            request_timeout: app.request_timeout,
            policy_editor: app.policy_editor.clone(),
            generated_invite: app.generated_invite.clone(),
            controller_document: app.controller_document.clone(),
            client: app.client.clone(),
            api_base: app.api_base.clone(),
            status: app.status.clone(),
            message: app.message.clone(),
            name: app.name.clone(),
            managed_create_id: app.managed_create_id.clone(),
            prefix: app.prefix.clone(),
            ipv6_prefix: app.ipv6_prefix.clone(),
            network_relay_policy: app.network_relay_policy.clone(),
            invite_lifetime: app.invite_lifetime.clone(),
            candidate_device: app.candidate_device.clone(),
            candidate_ipv4: app.candidate_ipv4.clone(),
            candidate_ipv6: app.candidate_ipv6.clone(),
            controller: app.controller.clone(),
            network_id: app.network_id.clone(),
            token: app.token.clone(),
            public_key: app.public_key.clone(),
            controller_public_key: app.controller_public_key.clone(),
            relay_endpoint: app.relay_endpoint.clone(),
            upnp_enabled: app.upnp_enabled.clone(),
            stun_servers: app.stun_servers.clone(),
            planet_manifest: app.planet_manifest.clone(),
            planet_public_key: app.planet_public_key.clone(),
            controller_tls_ca_pem: app.controller_tls_ca_pem.clone(),
            admin_token: app.admin_token.clone(),
            admin_token_bound_value: app.admin_token_bound_value.clone(),
            admin_token_controller: app.admin_token_controller.clone(),
            managed_networks: app.managed_networks.clone(),
            selected_network: app.selected_network.clone(),
            members: app.members.clone(),
            sessions: app.sessions.clone(),
            issued_token: app.issued_token.clone(),
            invite_link: app.invite_link.clone(),
            settings: app.settings.clone(),
            cli_command: app.cli_command.clone(),
            cli_output: app.cli_output.clone(),
            exit_network_id: app.exit_network_id.clone(),
            ipv4_gateway: app.ipv4_gateway.clone(),
            ipv6_gateway: app.ipv6_gateway.clone(),
            exit_kill_switch: app.exit_kill_switch.clone(),
            egress_interface: app.egress_interface.clone(),
            enable_ipv4_gateway: app.enable_ipv4_gateway.clone(),
            enable_ipv6_gateway: app.enable_ipv6_gateway.clone(),
        }
    }
    fn apply(self, app: &mut App) {
        app.request_timeout = self.request_timeout;
        app.policy_editor = self.policy_editor;
        app.generated_invite = self.generated_invite;
        app.controller_document = self.controller_document;
        app.client = self.client;
        app.api_base = self.api_base;
        app.status = self.status;
        app.message = self.message;
        app.name = self.name;
        app.managed_create_id = self.managed_create_id;
        app.prefix = self.prefix;
        app.ipv6_prefix = self.ipv6_prefix;
        app.network_relay_policy = self.network_relay_policy;
        app.invite_lifetime = self.invite_lifetime;
        app.candidate_device = self.candidate_device;
        app.candidate_ipv4 = self.candidate_ipv4;
        app.candidate_ipv6 = self.candidate_ipv6;
        app.controller = self.controller;
        app.network_id = self.network_id;
        app.token = self.token;
        app.public_key = self.public_key;
        app.controller_public_key = self.controller_public_key;
        app.relay_endpoint = self.relay_endpoint;
        app.upnp_enabled = self.upnp_enabled;
        app.stun_servers = self.stun_servers;
        app.planet_manifest = self.planet_manifest;
        app.planet_public_key = self.planet_public_key;
        app.controller_tls_ca_pem = self.controller_tls_ca_pem;
        app.admin_token = self.admin_token;
        app.admin_token_bound_value = self.admin_token_bound_value;
        app.admin_token_controller = self.admin_token_controller;
        app.managed_networks = self.managed_networks;
        app.selected_network = self.selected_network;
        app.members = self.members;
        app.sessions = self.sessions;
        app.issued_token = self.issued_token;
        app.invite_link = self.invite_link;
        app.cli_command = self.cli_command;
        app.cli_output = self.cli_output;
        app.exit_network_id = self.exit_network_id;
        app.ipv4_gateway = self.ipv4_gateway;
        app.ipv6_gateway = self.ipv6_gateway;
        app.exit_kill_switch = self.exit_kill_switch;
        app.egress_interface = self.egress_interface;
        app.enable_ipv4_gateway = self.enable_ipv4_gateway;
        app.enable_ipv6_gateway = self.enable_ipv6_gateway;
    }
}

impl App {
    pub(super) fn read_controller_document(&mut self, path: String) {
        self.start_job(move |app| {
            app.controller_document.clear();
            let result = (|| -> Result<String, String> {
                let response = app
                    .controller_request(reqwest::Method::GET, path.clone(), false)?
                    .send()
                    .map_err(|e| e.to_string())?;
                if !response.status().is_success() {
                    return Err(format!("HTTP {}", response.status()));
                }
                if path == "/health" {
                    return response.text().map_err(|e| e.to_string());
                }
                let value: serde_json::Value = response.json().map_err(|e| e.to_string())?;
                file_io::sanitized_json(&value).map_err(|e| e.to_string())
            })();
            match result {
                Ok(value) => {
                    app.controller_document = value;
                    app.message = "控制器查询完成。 / Controller query completed.".into();
                }
                Err(error) => {
                    app.message = format!("控制器查询失败 / Controller query failed: {error}")
                }
            }
        });
    }
    pub(super) fn create_local_network(&mut self) {
        self.start_job(|app| app.create_local_network_sync());
    }
    pub(super) fn run_cli_command(&mut self) {
        if !self.can_start_action() {
            return;
        }
        let cancel = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        self.process_cancel = Some(cancel.clone());
        self.start_job(move |app| app.run_cli_command_sync(cancel));
    }
    pub(super) fn refresh(&mut self) {
        self.start_job(move |app| {
            app.refresh_sync();
            if app.status.is_some() {
                app.refresh_sessions_sync();
            }
        });
    }
    pub(super) fn refresh_sessions(&mut self) {
        self.start_job(move |app| app.refresh_sessions_sync());
    }
    pub(super) fn adapter(&mut self, start: bool) {
        self.start_job(move |app| app.adapter_sync(start));
    }
    pub(super) fn leave_network(&mut self, id: Uuid) {
        self.start_job(move |app| app.leave_network_sync(id));
    }
    pub(super) fn apply_exit_selection(&mut self) {
        self.start_job(move |app| app.apply_exit_selection_sync());
    }
    pub(super) fn apply_exit_gateway(&mut self) {
        self.start_job(move |app| app.apply_exit_gateway_sync());
    }
    pub(super) fn remove_exit_gateway(&mut self) {
        self.start_job(move |app| app.remove_exit_gateway_sync());
    }
    pub(super) fn clear_exit_selection(&mut self) {
        self.start_job(move |app| app.clear_exit_selection_sync());
    }
    pub(super) fn stop_agent(&mut self) {
        self.start_job(move |app| app.stop_agent_sync());
    }
    pub(super) fn join_network(&mut self, planet_manifest_url: Option<String>) {
        self.start_job(move |app| app.join_network_sync(planet_manifest_url));
    }
    pub(super) fn join_invite_link(&mut self) {
        self.start_job(move |app| app.join_invite_link_sync());
    }
    pub(super) fn configure_relay(&mut self) {
        self.start_job(move |app| app.configure_relay_sync());
    }
    pub(super) fn configure_planet(&mut self) {
        self.start_job(move |app| app.configure_planet_sync());
    }
    pub(super) fn refresh_controller_public_key(&mut self, show_message: bool) {
        self.start_job(move |app| app.refresh_controller_public_key_sync(show_message));
    }
    pub(super) fn refresh_managed_networks(&mut self) {
        self.start_job(move |app| app.refresh_managed_networks_sync());
    }
    pub(super) fn create_managed_network(&mut self) {
        self.start_job(move |app| app.create_managed_network_sync());
    }
    pub(super) fn delete_managed_network(&mut self, id: Uuid) {
        self.start_job(move |app| app.delete_managed_network_sync(id));
    }
    pub(super) fn issue_enrollment_token(&mut self, id: Uuid) {
        self.start_job(move |app| app.issue_enrollment_token_sync(id));
    }
    pub(super) fn load_members(&mut self, id: Uuid) {
        self.start_job(move |app| app.load_members_sync(id));
    }
    pub(super) fn remove_member(&mut self, network_id: Uuid, device_id: Uuid) {
        self.start_job(move |app| app.remove_member_sync(network_id, device_id));
    }
    pub(super) fn update_controller_exit(&mut self, grant: bool) {
        self.start_job(move |app| app.update_controller_exit_sync(grant));
    }
    pub(super) fn start_job(&mut self, work: impl FnOnce(&mut App) + Send + 'static) {
        if !self.can_start_action() {
            return;
        }
        let snapshot = WorkerSnapshot::capture(self);
        let (tx, rx) = mpsc::channel();
        match std::thread::Builder::new()
            .name("meshlake-gui-request".into())
            .spawn(move || {
                let mut worker = App::default();
                worker.settings = snapshot.settings.clone();
                snapshot.apply(&mut worker);
                work(&mut worker);
                let _ = tx.send(WorkerSnapshot::capture(&worker));
            }) {
            Ok(_) => {
                self.job = Some(rx);
                self.message = self.t("正在执行，请稍候…", "Working, please wait…").into();
            }
            Err(error) => self.message = format!("无法启动后台任务：{error}"),
        }
    }

    pub(super) fn poll_job(&mut self, context: &egui::Context) {
        let Some(rx) = &self.job else {
            return;
        };
        match rx.try_recv() {
            Ok(result) => {
                self.job = None;
                self.process_cancel = None;
                result.apply(self);
            }
            Err(TryRecvError::Empty) => context.request_repaint_after(Duration::from_millis(80)),
            Err(TryRecvError::Disconnected) => {
                self.job = None;
                self.process_cancel = None;
                self.message = self
                    .t(
                        "后台任务意外结束，请检查状态后重试。",
                        "Background task ended unexpectedly. Check status before retrying.",
                    )
                    .into();
            }
        }
    }
}
pub(super) type JobReceiver = Receiver<WorkerSnapshot>;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pending_work_does_not_block_rendering_or_overwrite_navigation_and_language() {
        let mut app = App::default();
        let (release_tx, release_rx) = mpsc::channel();
        app.start_job(move |worker| {
            release_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            worker.message = "completed".into();
        });
        assert!(app.job.is_some());
        app.page = Page::Join;
        app.settings.language = Language::English;
        let context = egui::Context::default();
        let output = context.run(Default::default(), |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                app.render_page(ctx, ui);
            });
        });
        assert!(!output.shapes.is_empty());
        app.start_job(|_| panic!("a second job must not start"));
        release_tx.send(()).unwrap();
        let completed = app
            .job
            .take()
            .unwrap()
            .recv_timeout(Duration::from_secs(5))
            .unwrap();
        completed.apply(&mut app);
        assert_eq!(app.page, Page::Join);
        assert_eq!(app.settings.language, Language::English);
        assert_eq!(app.message, "completed");
    }
}
