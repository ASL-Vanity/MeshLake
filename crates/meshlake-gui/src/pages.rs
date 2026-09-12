use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Page {
    Overview,
    Connectivity,
    Join,
    Controller,
    Gateway,
    Maintenance,
}
impl Page {
    pub(super) const ALL: [Self; 6] = [
        Self::Overview,
        Self::Connectivity,
        Self::Join,
        Self::Controller,
        Self::Gateway,
        Self::Maintenance,
    ];
    pub(super) fn title(self, language: Language) -> &'static str {
        let (zh, en) = match self {
            Self::Overview => ("概览", "Overview"),
            Self::Connectivity => ("连接与网卡", "Connectivity"),
            Self::Join => ("加入网络", "Join network"),
            Self::Controller => ("控制器管理", "Controller"),
            Self::Gateway => ("出口与网关", "Exit gateways"),
            Self::Maintenance => ("维护工具", "Maintenance"),
        };
        if language == Language::Chinese {
            zh
        } else {
            en
        }
    }
}

fn surface(ui: &mut egui::Ui, title: &str, content: impl FnOnce(&mut egui::Ui)) {
    egui::Frame::new()
        .fill(ui.visuals().window_fill)
        .stroke(ui.visuals().widgets.noninteractive.bg_stroke)
        .corner_radius(10)
        .inner_margin(egui::Margin::same(18))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.label(egui::RichText::new(title).size(17.0).strong());
            ui.add_space(4.0);
            content(ui);
        });
    ui.add_space(6.0);
}
fn field(ui: &mut egui::Ui, label: &str, value: &mut String) {
    ui.label(label);
    ui.add(design::input(value).desired_width(f32::INFINITY));
}
fn secret(ui: &mut egui::Ui, label: &str, value: &mut String) {
    ui.label(label);
    ui.add(
        design::input(value)
            .password(true)
            .desired_width(f32::INFINITY),
    );
}

fn json_details(
    ui: &mut egui::Ui,
    label: &str,
    copy_label: &str,
    id: impl std::hash::Hash,
    value: &impl Serialize,
) {
    ui.push_id(id, |ui| {
        ui.collapsing(label, |ui| {
            let mut text = file_io::sanitized_json(value).unwrap_or_default();
            design::document_view(ui, "details-json", &mut text);
            if ui.button(copy_label).clicked() {
                ui.ctx().copy_text(text);
            }
        });
    });
}

impl App {
    pub(super) fn render_page(&mut self, context: &egui::Context, ui: &mut egui::Ui) {
        match self.page {
            Page::Overview => self.overview_page(ui),
            Page::Connectivity => self.connectivity_page(ui),
            Page::Join => self.join_page(ui),
            Page::Controller => self.controller_page(context, ui),
            Page::Gateway => self.gateway_page(ui),
            Page::Maintenance => self.maintenance_page(ui),
        }
    }
    fn overview_page(&mut self, ui: &mut egui::Ui) {
        if let Some(status) = self.status.clone() {
            surface(ui, self.t("本机设备", "This device"), |ui| {
                ui.label(self.t("设备 ID", "Device ID"));
                ui.horizontal_wrapped(|ui| {
                    ui.monospace(status.device_id.0.to_string());
                    if ui.button(self.t("复制", "Copy")).clicked() {
                        ui.ctx().copy_text(status.device_id.0.to_string());
                    }
                });
                ui.horizontal_wrapped(|ui| {
                    ui.label(format!(
                        "{} · {}",
                        self.t("网卡", "Adapter"),
                        status.adapter_state
                    ));
                    ui.separator();
                    ui.label(format!(
                        "{} · {}",
                        self.t("已加入网络", "Joined networks"),
                        status.networks.len()
                    ));
                });
            });
            surface(ui, self.t("我的网络", "My networks"), |ui| {
                if status.networks.is_empty() {
                    ui.label(self.t(
                        "尚未加入网络，使用邀请连接你的第一台设备。",
                        "No networks yet. Use an invitation to connect your first device.",
                    ));
                }
                for network in &status.networks {
                    ui.horizontal_wrapped(|ui| {
                        ui.strong(&network.network.name);
                        ui.label(&network.network.ipv4_prefix);
                        if let Some(prefix) = &network.network.ipv6_prefix {
                            ui.label(prefix);
                        }
                    });
                    ui.monospace(network.network.id.0.to_string());
                    json_details(
                        ui,
                        self.t("网络详情", "Network details"),
                        self.t("复制 JSON", "Copy JSON"),
                        network.network.id.0,
                        network,
                    );
                    ui.label(format!(
                        "{} {}",
                        self.t("分配地址：", "Assigned addresses:"),
                        network
                            .assigned_addresses
                            .iter()
                            .map(ToString::to_string)
                            .collect::<Vec<_>>()
                            .join(", ")
                    ));
                    if ui.button(self.t("离开网络", "Leave network")).clicked() {
                        self.confirm_action(PendingAction::Leave(network.network.id.0));
                    }
                    ui.separator();
                }
                if ui.button(self.t("加入网络", "Join network")).clicked() {
                    self.page = Page::Join;
                }
            });
        } else {
            surface(
                ui,
                self.t("让设备连接起来", "Bring your devices together"),
                |ui| {
                    ui.label(self.t("连接本机后台后，在这里查看网络和设备状态。已有邀请时，也可以先准备入网信息。", "Connect to the local agent to view your networks and device status. You can also prepare enrollment with an existing invitation."));
                    ui.add_space(8.0);
                    ui.horizontal_wrapped(|ui| {
                        if ui.button(self.t("加入网络", "Join network")).clicked() {
                            self.page = Page::Join;
                        }
                        if ui
                            .button(self.t("打开维护工具", "Open maintenance"))
                            .clicked()
                        {
                            self.page = Page::Maintenance;
                        }
                    });
                },
            );
        }
        surface(ui, self.t("连接会话", "Connection sessions"), |ui| {
            if ui.button(self.t("刷新会话", "Refresh sessions")).clicked() {
                self.refresh_sessions();
            }
            if let Some(sessions) = &self.sessions {
                if sessions.sessions.is_empty() {
                    ui.label(self.t("当前没有会话。", "No sessions at present."));
                }
                for session in &sessions.sessions {
                    ui.horizontal_wrapped(|ui| {
                        ui.monospace(session.network_id.0.to_string());
                        ui.label(format!("{:?} · {:?}", session.state, session.path));
                    });
                }
            } else {
                ui.label(self.t("尚未读取会话数据。", "Session data has not been loaded."));
            }
        });
        self.status_details_ui(ui);
    }
    fn relay_policy_ui(&mut self, ui: &mut egui::Ui) {
        ui.label(self.t("中继策略", "Relay policy"));
        ui.horizontal_wrapped(|ui| {
            for (value, zh, en) in [
                (RelayPolicy::Preferred, "优先直连", "Prefer direct"),
                (RelayPolicy::Required, "始终中继", "Require relay"),
                (RelayPolicy::Disabled, "禁用中继", "Disable relay"),
            ] {
                let label = self.t(zh, en);
                ui.selectable_value(&mut self.network_relay_policy, value, label);
            }
        });
    }
    fn network_definition_ui(&mut self, ui: &mut egui::Ui) {
        field(ui, self.t("网络名称", "Network name"), &mut self.name);
        field(ui, self.t("IPv4 前缀", "IPv4 prefix"), &mut self.prefix);
        field(
            ui,
            self.t("IPv6 前缀（可选）", "IPv6 prefix (optional)"),
            &mut self.ipv6_prefix,
        );
        self.relay_policy_ui(ui);
    }
    fn connectivity_page(&mut self, ui: &mut egui::Ui) {
        surface(ui, self.t("虚拟网卡", "Virtual adapter"), |ui| {
            let active = self.status.as_ref().map(|s| s.adapter_state == "active");
            ui.label(match active {
                Some(true) => self.t("网卡正在运行", "Adapter is active"),
                Some(false) => self.t("网卡尚未启动", "Adapter is inactive"),
                None => self.t(
                    "先连接后台以读取网卡状态",
                    "Connect to the agent to read adapter status",
                ),
            });
            ui.horizontal_wrapped(|ui| {
                if ui
                    .add_enabled(
                        active == Some(false),
                        egui::Button::new(self.t("启动网卡", "Start adapter")),
                    )
                    .clicked()
                {
                    self.adapter(true);
                }
                if ui
                    .add_enabled(
                        active == Some(true),
                        egui::Button::new(self.t("停止网卡", "Stop adapter")),
                    )
                    .clicked()
                {
                    self.confirm_action(PendingAction::StopAdapter);
                }
            });
        });
        surface(
            ui,
            self.t("中继与连接发现", "Relay and discovery"),
            |ui| {
                field(
                    ui,
                    self.t("UDP 中继地址", "UDP relay endpoint"),
                    &mut self.relay_endpoint,
                );
                field(
                    ui,
                    self.t(
                        "STUN 服务器（可选，逗号分隔）",
                        "STUN servers (optional, comma-separated)",
                    ),
                    &mut self.stun_servers,
                );
                let label = self.t(
                    "启用 PCP / NAT-PMP / UPnP 自动端口映射",
                    "Enable PCP / NAT-PMP / UPnP automatic port mapping",
                );
                ui.checkbox(&mut self.upnp_enabled, label);
                if ui
                    .button(self.t("保存中继配置", "Save relay settings"))
                    .clicked()
                {
                    self.configure_relay();
                }
            },
        );
        surface(ui, self.t("Planet 配置", "Planet configuration"), |ui| {
            ui.label(self.t(
                "使用签名清单配置控制器、中继和 STUN 节点。",
                "Configure controller, relay and STUN nodes from a signed manifest.",
            ));
            field(
                ui,
                self.t("清单 URL", "Manifest URL"),
                &mut self.planet_manifest,
            );
            field(
                ui,
                self.t(
                    "控制器验证公钥（Base64）",
                    "Controller verification key (Base64)",
                ),
                &mut self.planet_public_key,
            );
            self.ca_file_ui(ui);
            if ui
                .button(self.t("验证并保存 Planet", "Verify and save Planet"))
                .clicked()
            {
                self.configure_planet();
            }
        });
        ui.collapsing(self.t("创建本地开发网络", "Create a local development network"), |ui| {
            ui.label(self.t("本地开发记录不包含控制器成员证书；实际组网请通过邀请加入。", "Local development records do not include membership certificates. Use enrollment for an operational network."));
            field(ui, self.t("网络 ID（可选）", "Network ID (optional)"), &mut self.network_id);
            self.network_definition_ui(ui);
            if ui.button(self.t("创建本地网络", "Create local network")).clicked() { self.create_local_network(); }
        });
    }
    fn join_page(&mut self, ui: &mut egui::Ui) {
        surface(
            ui,
            self.t("使用邀请加入", "Join with an invitation"),
            |ui| {
                ui.label(self.t(
                    "粘贴管理员提供的一次性邀请链接。",
                    "Paste the one-time invitation supplied by your administrator.",
                ));
                secret(
                    ui,
                    self.t("邀请链接", "Invitation link"),
                    &mut self.invite_link,
                );
                if ui
                    .button(self.t("通过邀请加入", "Join with invitation"))
                    .clicked()
                {
                    self.join_invite_link();
                }
                ui.collapsing(
                    self.t("从文件导入邀请", "Import invitation from file"),
                    |ui| self.credential_file_ui(ui, file_io::Credential::Invite),
                );
            },
        );
        surface(ui, self.t("手动入网", "Manual enrollment"), |ui| {
            ui.label(self.t("控制器地址", "Controller URL"));
            self.controller_address_ui(ui);
            field(ui, self.t("网络 ID", "Network ID"), &mut self.network_id);
            secret(
                ui,
                self.t("一次性入网令牌", "One-time enrollment token"),
                &mut self.token,
            );
            field(
                ui,
                self.t(
                    "控制器验证公钥（Base64）",
                    "Controller verification key (Base64)",
                ),
                &mut self.public_key,
            );
            ui.collapsing(
                self.t("从文件导入令牌", "Import token from file"),
                |ui| self.credential_file_ui(ui, file_io::Credential::Enrollment),
            );
            self.private_ca_ui(ui);
            if ui
                .button(self.t("验证并加入网络", "Verify and join network"))
                .clicked()
            {
                self.join_network(None);
            }
        });
    }
    fn private_ca_ui(&mut self, ui: &mut egui::Ui) {
        ui.collapsing(
            self.t("私有 CA（高级）", "Private CA (advanced)"),
            |ui| {
                self.ca_file_ui(ui);
                ui.label(self.t(
                    "PEM 证书，仅用于私有 HTTPS 控制器",
                    "PEM certificates for a private HTTPS controller",
                ));
                ui.add(
                    egui::TextEdit::multiline(&mut self.controller_tls_ca_pem)
                        .desired_width(f32::INFINITY)
                        .desired_rows(4),
                );
            },
        );
    }
    fn controller_page(&mut self, context: &egui::Context, ui: &mut egui::Ui) {
        surface(
            ui,
            self.t("控制器连接", "Controller connection"),
            |ui| {
                ui.label(self.t("控制器地址", "Controller URL"));
                self.controller_address_ui(ui);
                secret(
                    ui,
                    self.t("管理员令牌", "Administrator token"),
                    &mut self.admin_token,
                );
                ui.collapsing(
                    self.t("从文件导入管理员令牌", "Import administrator token"),
                    |ui| self.credential_file_ui(ui, file_io::Credential::Admin),
                );
                self.private_ca_ui(ui);
                ui.horizontal_wrapped(|ui| {
                    if ui.button(self.t("健康检查", "Health check")).clicked() {
                        self.read_controller_document("/health".into());
                    }
                    if ui.button(self.t("读取 Planet", "Read Planet")).clicked() {
                        self.read_controller_document("/v1/planet".into());
                    }
                    if ui.button(self.t("读取公钥", "Read public key")).clicked() {
                        self.refresh_controller_public_key(true);
                    }
                    if ui
                        .button(self.t("刷新网络列表", "Refresh networks"))
                        .clicked()
                    {
                        self.refresh_managed_networks();
                    }
                });
                if !self.controller_public_key.is_empty() {
                    ui.label(self.t("控制器验证公钥", "Controller verification key"));
                    ui.add(
                        design::input(&mut self.controller_public_key)
                            .interactive(false)
                            .desired_width(f32::INFINITY),
                    );
                    ui.horizontal_wrapped(|ui| {
                        if ui.button(self.t("复制公钥", "Copy key")).clicked() {
                            context.copy_text(self.controller_public_key.clone());
                        }
                        if ui
                            .button(self.t("填入手动入网表单", "Use in enrollment form"))
                            .clicked()
                        {
                            self.public_key = self.controller_public_key.clone();
                        }
                    });
                }
                if !self.controller_document.is_empty() {
                    ui.collapsing(self.t("查询结果", "Query result"), |ui| {
                        ui.add(
                            egui::TextEdit::multiline(&mut self.controller_document)
                                .desired_rows(8)
                                .desired_width(f32::INFINITY)
                                .font(egui::TextStyle::Monospace)
                                .interactive(false),
                        );
                        if ui.button(self.t("复制结果", "Copy result")).clicked() {
                            context.copy_text(self.controller_document.clone());
                        }
                    });
                }
            },
        );
        surface(ui, self.t("网络管理", "Network management"), |ui| {
            ui.collapsing(self.t("创建新网络", "Create a new network"), |ui| {
                field(
                    ui,
                    self.t("新网络 ID（可选）", "New network ID (optional)"),
                    &mut self.managed_create_id,
                );
                self.network_definition_ui(ui);
                if ui
                    .button(self.t("创建控制器网络", "Create controller network"))
                    .clicked()
                {
                    self.create_managed_network();
                }
            });
            if self.managed_networks.is_empty() {
                ui.label(self.t(
                    "列表为空或尚未读取，点击“刷新网络列表”。",
                    "No networks loaded. Select Refresh networks.",
                ));
            }
            for network in self.managed_networks.clone() {
                ui.separator();
                ui.horizontal_wrapped(|ui| {
                    if ui
                        .selectable_label(
                            self.selected_network == Some(network.id.0),
                            &network.name,
                        )
                        .clicked()
                    {
                        self.selected_network = Some(network.id.0);
                        self.members.clear();
                        self.issued_token.clear();
                        self.generated_invite.clear();
                        self.load_members(network.id.0);
                    }
                    ui.label(&network.ipv4_prefix);
                    if let Some(prefix) = &network.ipv6_prefix {
                        ui.label(prefix);
                    }
                });
                ui.monospace(network.id.0.to_string());
                json_details(
                    ui,
                    self.t("网络详情", "Network details"),
                    self.t("复制 JSON", "Copy JSON"),
                    network.id.0,
                    &network,
                );
                ui.horizontal_wrapped(|ui| {
                    if ui.button(self.t("选择网络", "Select network")).clicked() {
                        self.selected_network = Some(network.id.0);
                        self.members.clear();
                        self.issued_token.clear();
                        self.generated_invite.clear();
                        self.load_members(network.id.0);
                    }
                    if ui.button(self.t("删除网络", "Delete network")).clicked() {
                        self.confirm_action(PendingAction::DeleteNetwork(network.id.0));
                    }
                });
            }
        });
        if let Some(network) = self.selected_network {
            surface(ui, self.t("邀请设备", "Invite a device"), |ui| {
                ui.monospace(network.to_string());
                ui.horizontal_wrapped(|ui| {
                    ui.label(self.t("有效期（秒）", "Lifetime (seconds)"));
                    ui.add(egui::DragValue::new(&mut self.invite_lifetime).range(60..=86400));
                    if ui
                        .button(self.t("生成邀请链接", "Create invitation"))
                        .clicked()
                    {
                        self.issue_enrollment_token(network);
                    }
                });
                if !self.generated_invite.is_empty() {
                    ui.add(
                        design::input(&mut self.generated_invite)
                            .password(true)
                            .interactive(false)
                            .desired_width(f32::INFINITY),
                    );
                    if ui.button(self.t("复制邀请", "Copy invitation")).clicked() {
                        context.copy_text(self.generated_invite.clone());
                    }
                    self.invite_export_ui(ui);
                }
            });
            self.standalone_token_ui(ui);
            surface(ui, self.t("网络成员", "Network members"), |ui| {
                ui.horizontal_wrapped(|ui| {
                    if ui.button(self.t("刷新成员", "Refresh members")).clicked() {
                        self.load_members(network);
                    }
                    if ui
                        .button(self.t("读取授权清单", "Read authorization"))
                        .clicked()
                    {
                        self.read_controller_document(format!(
                            "/v1/networks/{network}/authorization"
                        ));
                    }
                    if ui
                        .button(self.t("读取策略清单", "Read policy manifest"))
                        .clicked()
                    {
                        self.read_controller_document(format!("/v1/networks/{network}/policy"));
                    }
                });
                if self.members.is_empty() {
                    ui.label(self.t("没有已读取的成员。", "No members loaded."));
                }
                for member in self.members.clone() {
                    ui.separator();
                    ui.monospace(member.device_id.0.to_string());
                    json_details(
                        ui,
                        self.t("成员授权详情", "Membership details"),
                        self.t("复制 JSON", "Copy JSON"),
                        member.device_id.0,
                        &member,
                    );
                    ui.label(
                        member
                            .assigned_addresses
                            .iter()
                            .map(ToString::to_string)
                            .collect::<Vec<_>>()
                            .join(", "),
                    );
                    ui.horizontal_wrapped(|ui| {
                        if ui
                            .button(self.t("用作出口候选", "Use as exit candidate"))
                            .clicked()
                        {
                            self.candidate_device = member.device_id.0.to_string();
                        }
                        if ui.button(self.t("移除成员", "Remove member")).clicked() {
                            self.confirm_action(PendingAction::RemoveMember(
                                network,
                                member.device_id.0,
                            ));
                        }
                    });
                }
            });
            surface(
                ui,
                self.t("出口候选授权", "Exit candidate authorization"),
                |ui| {
                    field(
                        ui,
                        self.t("设备 ID", "Device ID"),
                        &mut self.candidate_device,
                    );
                    ui.horizontal_wrapped(|ui| {
                        ui.checkbox(&mut self.candidate_ipv4, "IPv4");
                        ui.checkbox(&mut self.candidate_ipv6, "IPv6");
                    });
                    ui.horizontal_wrapped(|ui| {
                        if ui
                            .button(self.t("授权 / 更新", "Authorize / update"))
                            .clicked()
                        {
                            self.update_controller_exit(true);
                        }
                        if ui
                            .button(self.t("撤销出口授权", "Revoke exit authorization"))
                            .clicked()
                        {
                            match Uuid::parse_str(self.candidate_device.trim()) {
                                Ok(id) => {
                                    self.confirm_action(PendingAction::RevokeExit(network, id))
                                }
                                Err(_) => {
                                    self.message = self
                                        .t("设备 ID 必须是 UUID。", "Device ID must be a UUID.")
                                        .into()
                                }
                            }
                        }
                    });
                },
            );
            self.controller_policy_panel(ui);
        }
    }
    fn gateway_page(&mut self, ui: &mut egui::Ui) {
        surface(ui, self.t("选择网络", "Select a network"), |ui| {
            if let Some(status) = self.status.clone() {
                ui.horizontal_wrapped(|ui| {
                    for network in status.networks {
                        if ui
                            .selectable_label(
                                self.exit_network_id == network.network.id.0.to_string(),
                                &network.network.name,
                            )
                            .clicked()
                        {
                            self.exit_network_id = network.network.id.0.to_string();
                        }
                    }
                });
            }
            field(
                ui,
                self.t("网络 ID", "Network ID"),
                &mut self.exit_network_id,
            );
        });
        surface(ui, self.t("流量出口", "Traffic exit"), |ui| {
            field(
                ui,
                self.t(
                    "IPv4 网关设备 ID（留空不选择）",
                    "IPv4 gateway device ID (blank for none)",
                ),
                &mut self.ipv4_gateway,
            );
            field(
                ui,
                self.t(
                    "IPv6 网关设备 ID（留空不选择）",
                    "IPv6 gateway device ID (blank for none)",
                ),
                &mut self.ipv6_gateway,
            );
            let label = self.t("启用故障关闭", "Enable kill switch");
            ui.checkbox(&mut self.exit_kill_switch, label);
            ui.horizontal_wrapped(|ui| {
                if ui
                    .button(self.t("应用出口选择", "Apply exit selection"))
                    .clicked()
                {
                    self.apply_exit_selection();
                }
                if ui
                    .button(self.t("清除出口选择", "Clear exit selection"))
                    .clicked()
                {
                    match Uuid::parse_str(self.exit_network_id.trim()) {
                        Ok(id) => self.confirm_action(PendingAction::ClearExit(id)),
                        Err(_) => {
                            self.message = self
                                .t("网络 ID 必须是 UUID。", "Network ID must be a UUID.")
                                .into()
                        }
                    }
                }
            });
        });
        surface(
            ui,
            self.t("将本机作为网关", "Use this device as a gateway"),
            |ui| {
                field(
                    ui,
                    self.t("出口网卡", "Egress interface"),
                    &mut self.egress_interface,
                );
                ui.horizontal_wrapped(|ui| {
                    ui.checkbox(&mut self.enable_ipv4_gateway, "IPv4");
                    ui.checkbox(&mut self.enable_ipv6_gateway, "IPv6");
                });
                ui.horizontal_wrapped(|ui| {
                    if ui
                        .button(self.t("应用网关配置", "Apply gateway settings"))
                        .clicked()
                    {
                        self.apply_exit_gateway();
                    }
                    if ui.button(self.t("停用网关", "Disable gateway")).clicked() {
                        match Uuid::parse_str(self.exit_network_id.trim()) {
                            Ok(id) => self.confirm_action(PendingAction::DisableGateway(id)),
                            Err(_) => {
                                self.message = self
                                    .t("网络 ID 必须是 UUID。", "Network ID must be a UUID.")
                                    .into()
                            }
                        }
                    }
                });
            },
        );
    }
    fn maintenance_page(&mut self, ui: &mut egui::Ui) {
        self.diagnostics_panel(ui);
        self.services_panel(ui);
        self.backup_ui(ui);
        self.agent_maintenance_ui(ui);
        ui.collapsing(
            self.t("高级命令控制台", "Advanced command console"),
            |ui| {
                ui.label(self.t(
                    "首行填写子命令，其余每行一个参数。路径无需引号。",
                    "Enter the command followed by one argument per line. Paths need no quotes.",
                ));
                ui.add(
                    egui::TextEdit::multiline(&mut self.cli_command)
                        .desired_rows(5)
                        .desired_width(f32::INFINITY)
                        .font(egui::TextStyle::Monospace),
                );
                if ui.button(self.t("执行", "Run")).clicked() {
                    self.run_cli_command();
                }
                if !self.cli_output.is_empty() {
                    ui.add(
                        egui::TextEdit::multiline(&mut self.cli_output)
                            .desired_rows(8)
                            .desired_width(f32::INFINITY)
                            .font(egui::TextStyle::Monospace)
                            .interactive(false),
                    );
                }
            },
        );
    }
}
