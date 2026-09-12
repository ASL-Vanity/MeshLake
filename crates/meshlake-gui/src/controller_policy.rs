use super::*;

#[derive(Clone, Default)]
pub(super) struct PolicyEditor {
    file: String,
    target: Option<(String, Uuid)>,
    loaded: bool,
    stale: bool,
    routes: Vec<(String, String)>,
    exits: Vec<(String, bool, bool)>,
    dns_servers: String,
    search_domains: String,
    confirm_policy: bool,
    member: String,
    member_routes: String,
    confirm_routes: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EditablePolicy {
    routes: Vec<EditableRoute>,
    exit_nodes: Vec<EditableExit>,
    dns: EditableDns,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EditableRoute {
    prefix: String,
    gateway_device_id: Uuid,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EditableExit {
    gateway_device_id: Uuid,
    supports_ipv4: bool,
    supports_ipv6: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EditableDns {
    #[serde(default)]
    servers: Vec<std::net::IpAddr>,
    #[serde(default)]
    search_domains: Vec<String>,
}

impl PolicyEditor {
    pub(super) fn invalidate_after_exit_update(&mut self) {
        self.stale = true;
        self.confirm_policy = false;
    }

    fn import(&mut self, bytes: &[u8]) -> Result<(), String> {
        if self.stale {
            return Err("出口授权已改变。现有草稿已保留，请先重新读取策略再导入。 / Exit grants changed. Your draft is retained; reload policy before importing.".into());
        }
        let policy: EditablePolicy = serde_json::from_slice(bytes)
            .map_err(|_| "策略文件无效：必须包含 routes、exit_nodes、dns，不接受未知字段。 / Invalid policy file: routes, exit_nodes and dns are required; unknown fields are rejected.".to_owned())?;
        let candidate = Self {
            loaded: true,
            target: self.target.clone(),
            file: self.file.clone(),
            routes: policy
                .routes
                .into_iter()
                .map(|r| (r.prefix, r.gateway_device_id.to_string()))
                .collect(),
            exits: policy
                .exit_nodes
                .into_iter()
                .map(|e| {
                    (
                        e.gateway_device_id.to_string(),
                        e.supports_ipv4,
                        e.supports_ipv6,
                    )
                })
                .collect(),
            dns_servers: policy
                .dns
                .servers
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("\n"),
            search_domains: policy.dns.search_domains.join("\n"),
            ..Default::default()
        };
        candidate.request()?;
        *self = candidate;
        Ok(())
    }
    fn from_manifest(
        target: (String, Uuid),
        manifest: meshlake_core::NetworkPolicyManifest,
    ) -> Self {
        Self {
            target: Some(target),
            loaded: true,
            routes: manifest
                .routes
                .into_iter()
                .map(|route| {
                    (
                        route.prefix,
                        route.gateway_certificate.claims.device_id.0.to_string(),
                    )
                })
                .collect(),
            exits: manifest
                .exit_nodes
                .into_iter()
                .map(|node| {
                    (
                        node.gateway_certificate.claims.device_id.0.to_string(),
                        node.supports_ipv4,
                        node.supports_ipv6,
                    )
                })
                .collect(),
            dns_servers: manifest
                .dns
                .servers
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("\n"),
            search_domains: manifest.dns.search_domains.join("\n"),
            ..Default::default()
        }
    }

    fn request(&self) -> Result<serde_json::Value, String> {
        if self.stale {
            return Err("出口授权已改变，请重新读取策略后再保存。 / Exit grants changed; reload policy before saving.".into());
        }
        if !self.loaded {
            return Err("请先读取策略。 / Load policy first.".into());
        }
        let routes = self
            .routes
            .iter()
            .map(|(prefix, device)| {
                let id = Uuid::parse_str(device.trim())
                    .map_err(|_| "路由网关设备 ID 无效 / Invalid route gateway ID")?;
                if prefix.trim().is_empty() {
                    return Err("路由前缀不能为空 / Route prefix is required");
                }
                Ok(json!({"prefix":prefix.trim(),"gateway_device_id":id}))
            })
            .collect::<Result<Vec<_>, &str>>()
            .map_err(str::to_owned)?;
        let exits = self
            .exits
            .iter()
            .map(|(device, v4, v6)| {
                let id = Uuid::parse_str(device.trim())
                    .map_err(|_| "出口设备 ID 无效 / Invalid exit ID")?;
                if !v4 && !v6 {
                    return Err("出口至少选择一种协议 / Select an exit address family");
                }
                Ok(json!({"gateway_device_id":id,"supports_ipv4":v4,"supports_ipv6":v6}))
            })
            .collect::<Result<Vec<_>, &str>>()
            .map_err(str::to_owned)?;
        let servers = self
            .dns_servers
            .split_whitespace()
            .map(|s| s.parse::<std::net::IpAddr>())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| "DNS 必须为 IP 地址 / DNS must contain IP addresses")?;
        Ok(
            json!({"routes":routes,"exit_nodes":exits,"dns":{"servers":servers,
            "search_domains":self.search_domains.split_whitespace().collect::<Vec<_>>()}}),
        )
    }
}

impl App {
    pub(super) fn controller_policy_panel(&mut self, ui: &mut egui::Ui) {
        let Some(network) = self.selected_network else {
            return;
        };
        let target = (self.controller.clone(), network);
        if self.policy_editor.target.as_ref() != Some(&target) {
            self.policy_editor = PolicyEditor {
                target: Some(target.clone()),
                ..Default::default()
            };
        }
        ui.collapsing(
            self.t("路由与 DNS 策略", "Routing and DNS policy"),
            |ui| {
                ui.label(format!("Network: {network}"));
                if self.policy_editor.stale {
                    ui.label(self.t("出口授权已改变；下方草稿已保留，暂不可保存或导入。请先记录需要保留的编辑，再重新读取完整策略。", "Exit grants changed. The draft below is retained; saving and importing are blocked. Copy any edits you need before reloading the complete policy."));
                }
                if ui
                    .button(self.t("读取完整策略", "Load complete policy"))
                    .clicked()
                {
                    self.start_job(move |app| app.load_policy_sync(network));
                }
                ui.collapsing(self.t("导入 / 导出可编辑策略文件", "Import / export editable policy"), |ui| {
                    ui.label(self.t("策略 JSON 文件路径", "Policy JSON file path"));
                    ui.add(design::input(&mut self.policy_editor.file));
                    ui.horizontal_wrapped(|ui| {
                        let label = self.t("选择文件…", "Choose file…");
                        file_picker::browse(ui, &mut self.policy_editor.file, false, label, &mut self.message);
                        let label = self.t("选择保存位置…", "Choose destination…");
                        file_picker::browse(ui, &mut self.policy_editor.file, true, label, &mut self.message);
                    });
                    ui.horizontal_wrapped(|ui| {
                        if ui.button(self.t("导入到表单", "Import into form")).clicked() {
                            self.start_job(|app| app.import_policy_file_sync());
                        }
                        if ui.add_enabled(self.policy_editor.loaded && !self.policy_editor.stale, egui::Button::new(self.t("导出到新文件", "Export to a new file"))).clicked() {
                            self.start_job(|app| app.export_policy_file_sync());
                        }
                    });
                });
                if !self.policy_editor.loaded {
                    return;
                }
                ui.label(self.t("路由前缀 / 网关设备 ID", "Route prefix / gateway device ID"));
                let mut remove = None;
                for (index, (prefix, device)) in self.policy_editor.routes.iter_mut().enumerate() {
                    ui.push_id(("policy-route", index), |ui| {
                        ui.horizontal(|ui| {
                            let fields_width = (ui.available_width() - 64.0).max(80.0);
                            ui.add(design::input(prefix).desired_width(fields_width * 0.38));
                            ui.add(design::input(device).desired_width(fields_width * 0.62));
                            if ui.button("−").clicked() {
                                remove = Some(index);
                            }
                        })
                    });
                }
                if let Some(index) = remove {
                    self.policy_editor.routes.remove(index);
                }
                if ui.button(self.t("添加路由", "Add route")).clicked() {
                    self.policy_editor.routes.push(Default::default());
                }
                ui.label(self.t(
                    "出口设备 ID / 地址协议",
                    "Exit device ID / address families",
                ));
                let mut remove = None;
                for (index, (device, v4, v6)) in self.policy_editor.exits.iter_mut().enumerate() {
                    ui.push_id(("policy-exit", index), |ui| {
                        ui.horizontal(|ui| {
                            let device_width = (ui.available_width() - 160.0).max(60.0);
                            ui.add(design::input(device).desired_width(device_width));
                            ui.checkbox(v4, "IPv4");
                            ui.checkbox(v6, "IPv6");
                            if ui.button("−").clicked() {
                                remove = Some(index);
                            }
                        })
                    });
                }
                if let Some(index) = remove {
                    self.policy_editor.exits.remove(index);
                }
                if ui.button(self.t("添加出口", "Add exit")).clicked() {
                    self.policy_editor.exits.push((String::new(), true, false));
                }
                ui.label(self.t("DNS 服务器（每行一个 IP）", "DNS servers (one IP per line)"));
                ui.add(
                    egui::TextEdit::multiline(&mut self.policy_editor.dns_servers).desired_rows(2),
                );
                ui.label(self.t("搜索域（每行一个）", "Search domains (one per line)"));
                ui.add(
                    egui::TextEdit::multiline(&mut self.policy_editor.search_domains)
                        .desired_rows(2),
                );
                let confirm_label = self.t("确认用以上内容替换完整策略", "Confirm complete policy replacement");
                ui.checkbox(
                    &mut self.policy_editor.confirm_policy,
                    confirm_label,
                );
                if ui
                    .add_enabled(
                        self.policy_editor.confirm_policy && !self.policy_editor.stale,
                        egui::Button::new(self.t("保存策略", "Save policy")),
                    )
                    .clicked()
                {
                    match self.policy_editor.request() {
                        Ok(body) => {
                            self.policy_editor.confirm_policy = false;
                            self.start_job(move |app| app.save_policy_sync(network, body));
                        }
                        Err(error) => self.message = error,
                    }
                }
            },
        );
        ui.collapsing(
            self.t("成员路由授权", "Member route authorization"),
            |ui| {
                ui.label(self.t("成员设备 ID", "Member device ID"));
                ui.add(design::input(&mut self.policy_editor.member));
                ui.label(self.t(
                    "允许的路由前缀（每行一个，留空将撤销全部）",
                    "Allowed prefixes (one per line; empty revokes all)",
                ));
                ui.add(
                    egui::TextEdit::multiline(&mut self.policy_editor.member_routes)
                        .desired_rows(3),
                );
                let confirm_label = self.t(
                    "确认替换此成员全部路由授权",
                    "Confirm replacing all member route grants",
                );
                ui.checkbox(&mut self.policy_editor.confirm_routes, confirm_label);
                if ui
                    .add_enabled(
                        self.policy_editor.confirm_routes,
                        egui::Button::new(self.t("保存路由授权", "Save route grants")),
                    )
                    .clicked()
                {
                    match Uuid::parse_str(self.policy_editor.member.trim()) {
                        Ok(device) => {
                            let routes = self
                                .policy_editor
                                .member_routes
                                .split_whitespace()
                                .map(str::to_owned)
                                .collect::<Vec<_>>();
                            self.policy_editor.confirm_routes = false;
                            self.start_job(move |app| {
                                app.save_member_routes_sync(network, device, routes)
                            });
                        }
                        Err(_) => {
                            self.message = "成员设备 ID 无效 / Invalid member device ID".into()
                        }
                    }
                }
            },
        );
    }

    fn import_policy_file_sync(&mut self) {
        use std::io::Read;
        let result = (|| -> Result<(), String> {
            if self.policy_editor.stale {
                return Err("出口授权已改变，请先重新读取策略。 / Exit grants changed; reload policy first.".into());
            }
            let file = fs::File::open(self.policy_editor.file.trim())
                .map_err(|_| "无法打开策略文件。 / Could not open policy file.")?;
            let mut bytes = Vec::new();
            file.take(1024 * 1024 + 1)
                .read_to_end(&mut bytes)
                .map_err(|_| "无法读取策略文件。 / Could not read policy file.")?;
            if bytes.len() > 1024 * 1024 {
                return Err("策略文件超过 1 MiB。 / Policy file exceeds 1 MiB.".into());
            }
            self.policy_editor.import(&bytes)
        })();
        self.message = match result {
            Ok(()) => self
                .t(
                    "已导入表单，尚未提交。请检查后确认保存策略。",
                    "Imported into the form, not submitted. Review and confirm Save policy.",
                )
                .into(),
            Err(error) => error,
        };
    }

    fn export_policy_file_sync(&mut self) {
        use std::io::Write;
        let result = (|| -> Result<(), String> {
            let bytes = serde_json::to_vec_pretty(&self.policy_editor.request()?)
                .map_err(|_| "策略序列化失败。 / Could not serialize policy.")?;
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(self.policy_editor.file.trim())
                .map_err(|_| {
                    "请选择有写入权限且尚不存在的文件。 / Choose a writable path to a new file."
                })?;
            file.write_all(&bytes)
                .and_then(|_| file.sync_all())
                .map_err(|_| "策略文件写入失败。 / Could not write policy file.".into())
        })();
        self.message = match result {
            Ok(()) => self
                .t("已导出可编辑策略文件。", "Editable policy exported.")
                .into(),
            Err(error) => error,
        };
    }

    fn load_policy_sync(&mut self, network: Uuid) {
        let result = (|| -> Result<meshlake_core::NetworkPolicyManifest, String> {
            let response = self
                .controller_request(
                    reqwest::Method::GET,
                    format!("/v1/networks/{network}/policy"),
                    false,
                )?
                .send()
                .map_err(|e| e.to_string())?;
            if !response.status().is_success() {
                return Err(format!(
                    "读取策略失败 / Policy query failed: {}",
                    response.status()
                ));
            }
            response.json().map_err(|e| e.to_string())
        })();
        match result {
            Ok(manifest) => {
                self.policy_editor =
                    PolicyEditor::from_manifest((self.controller.clone(), network), manifest);
                self.message = "策略已读取 / Policy loaded".into();
            }
            Err(error) => self.message = error,
        }
    }

    fn save_policy_sync(&mut self, network: Uuid, body: serde_json::Value) {
        if self.policy_editor.stale {
            self.message = "出口授权已改变，请重新读取策略后再保存。 / Exit grants changed; reload policy before saving.".into();
            return;
        }
        let result = (|| -> Result<(), String> {
            let response = self
                .controller_request(
                    reqwest::Method::POST,
                    format!("/v1/networks/{network}/policy"),
                    true,
                )?
                .json(&body)
                .send()
                .map_err(|e| e.to_string())?;
            if !response.status().is_success() {
                return Err(format!(
                    "保存策略失败 / Policy update failed: {}",
                    response.status()
                ));
            }
            let manifest = response.json().map_err(|e| e.to_string())?;
            self.policy_editor =
                PolicyEditor::from_manifest((self.controller.clone(), network), manifest);
            Ok(())
        })();
        self.message = match result {
            Ok(()) => "策略已保存 / Policy saved".into(),
            Err(error) => error,
        };
    }

    fn save_member_routes_sync(&mut self, network: Uuid, device: Uuid, routes: Vec<String>) {
        let result = (|| -> Result<(), String> {
            let response = self
                .controller_request(
                    reqwest::Method::POST,
                    format!("/v1/networks/{network}/members/{device}/allowed-routes"),
                    true,
                )?
                .json(&json!({"allowed_routes":routes}))
                .send()
                .map_err(|e| e.to_string())?;
            if !response.status().is_success() {
                return Err(format!(
                    "路由授权失败 / Route grant failed: {}",
                    response.status()
                ));
            }
            let member: MembershipClaims = response.json().map_err(|e| e.to_string())?;
            if let Some(previous) = self
                .members
                .iter_mut()
                .find(|m| m.device_id == member.device_id)
            {
                *previous = member;
            }
            Ok(())
        })();
        self.message = match result {
            Ok(()) => "路由授权已保存 / Route grants saved".into(),
            Err(error) => error,
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exit_changes_block_stale_policy_saves_and_imports_without_losing_drafts() {
        for grant in [true, false] {
            let fixture = manifest();
            let stub = crate::api_tests::Stub::new(vec![
                (200, fixture.clone()),
                (200, fixture.clone()),
                (200, fixture.clone()),
            ]);
            let mut app = stub.app();
            let network = Uuid::from_u128(1);
            app.selected_network = Some(network);
            app.candidate_device = Uuid::from_u128(2).to_string();
            app.candidate_ipv4 = true;
            app.policy_editor = PolicyEditor::from_manifest(
                (app.controller.clone(), network),
                serde_json::from_value(fixture).unwrap(),
            );
            app.policy_editor.dns_servers = "10.9.0.1".into();
            app.policy_editor.confirm_policy = true;
            let draft = app.policy_editor.request().unwrap();
            app.update_controller_exit_sync(grant);
            assert!(app.policy_editor.stale);
            assert!(app.policy_editor.loaded);
            assert!(!app.policy_editor.confirm_policy);
            assert_eq!(app.policy_editor.dns_servers, "10.9.0.1");
            assert!(app.policy_editor.request().is_err());
            assert!(app
                .policy_editor
                .import(&serde_json::to_vec(&draft).unwrap())
                .is_err());
            app.save_policy_sync(network, draft);
            assert!(app.message.contains("reload policy"));
            app.load_policy_sync(network);
            assert!(!app.policy_editor.stale);
            assert!(app.policy_editor.request().is_ok());
            let requests = stub.finish();
            assert_eq!(requests.len(), 3);
            assert_eq!(requests[0].method, "GET");
            assert_eq!(requests[1].method, "POST");
            assert_eq!(
                requests[1].body["exit_nodes"].as_array().unwrap().len(),
                usize::from(grant)
            );
            assert_eq!(requests[2].method, "GET");
        }
    }

    #[test]
    fn failed_exit_updates_preserve_editable_policy_and_confirmation() {
        for grant in [true, false] {
            let fixture = manifest();
            let stub = crate::api_tests::Stub::new(vec![(200, fixture.clone()), (403, json!({}))]);
            let mut app = stub.app();
            app.selected_network = Some(Uuid::from_u128(1));
            app.candidate_device = Uuid::from_u128(2).to_string();
            app.candidate_ipv4 = true;
            app.policy_editor = PolicyEditor::from_manifest(
                (app.controller.clone(), Uuid::from_u128(1)),
                serde_json::from_value(fixture).unwrap(),
            );
            app.policy_editor.confirm_policy = true;
            let before = app.policy_editor.request().unwrap();
            app.update_controller_exit_sync(grant);
            assert!(app.message.contains("403"));
            assert!(!app.policy_editor.stale);
            assert!(app.policy_editor.confirm_policy);
            assert_eq!(app.policy_editor.request().unwrap(), before);
            assert_eq!(stub.finish().len(), 2);
        }
    }

    #[test]
    fn policy_file_workers_roundtrip_and_preserve_draft_on_import_failure() {
        let directory = std::env::temp_dir().join(format!("meshlake-policy-{}", Uuid::new_v4()));
        fs::create_dir(&directory).unwrap();
        let path = directory.join("策略 file.json");
        let mut app = App::default();
        app.policy_editor = PolicyEditor::from_manifest(
            ("http://localhost".into(), Uuid::from_u128(1)),
            serde_json::from_value(manifest()).unwrap(),
        );
        app.policy_editor.file = path.to_string_lossy().into_owned();
        let before = app.policy_editor.request().unwrap();
        app.export_policy_file_sync();
        let bytes = fs::read(&path).unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&bytes).unwrap(),
            before
        );
        app.policy_editor.dns_servers = "10.8.0.1".into();
        app.export_policy_file_sync();
        assert_eq!(fs::read(&path).unwrap(), bytes);
        app.import_policy_file_sync();
        assert_eq!(app.policy_editor.request().unwrap(), before);
        fs::write(&path, b"{invalid}").unwrap();
        app.import_policy_file_sync();
        assert_eq!(app.policy_editor.request().unwrap(), before);
        fs::remove_file(path).unwrap();
        fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn editable_policy_roundtrip_preserves_all_sections_and_rejects_typos_atomically() {
        let mut editor = PolicyEditor::from_manifest(
            ("http://localhost".into(), Uuid::from_u128(1)),
            serde_json::from_value(manifest()).unwrap(),
        );
        let before = editor.request().unwrap();
        editor
            .import(&serde_json::to_vec(&before).unwrap())
            .unwrap();
        assert_eq!(editor.request().unwrap(), before);
        for invalid in [
            json!({"routes":[],"exit_nodes":[]}),
            json!({"routes":[],"exit_nodes":[],"dns":{},"route":[]}),
            json!({"routes":[],"exit_nodes":[],"dns":{"server":["10.0.0.1"]}}),
        ] {
            assert!(editor
                .import(&serde_json::to_vec(&invalid).unwrap())
                .is_err());
            assert_eq!(editor.request().unwrap(), before);
        }
        assert!(!editor.confirm_policy);
    }

    fn manifest() -> serde_json::Value {
        let certificate = json!({"claims":{"network_id":Uuid::from_u128(1),"device_id":Uuid::from_u128(2),
            "device_public_key":[9],"assigned_addresses":["10.2.0.2"],"allowed_routes":["10.2.0.0/16"],
            "issued_at_unix_seconds":10,"expires_at_unix_seconds":1000},"controller_public_key":[7],"signature":[8]});
        json!({"version":2,"network_id":Uuid::from_u128(1),"policy_epoch":3,
            "routes":[{"prefix":"10.2.0.0/16","gateway_certificate":certificate}],
            "exit_nodes":[{"gateway_certificate":certificate,"supports_ipv4":true,"supports_ipv6":true}],
            "dns":{"servers":["10.2.0.1"],"search_domains":["mesh.test"]},
            "issued_at_unix_seconds":10,"expires_at_unix_seconds":1000,"controller_public_key":[7],"signature":[8]})
    }

    #[test]
    fn policy_load_and_save_use_correct_auth_and_preserve_other_sections() {
        let fixture = manifest();
        let stub =
            crate::api_tests::Stub::new(vec![(200, fixture.clone()), (200, fixture.clone())]);
        let mut app = stub.app();
        let network = Uuid::from_u128(1);
        app.load_policy_sync(network);
        assert!(app.policy_editor.loaded, "{}", app.message);
        let body = app.policy_editor.request().unwrap();
        assert_eq!(body["dns"], fixture["dns"]);
        assert_eq!(body["exit_nodes"][0]["supports_ipv6"], true);
        app.save_policy_sync(network, body.clone());
        assert!(app.message.contains("Policy saved"), "{}", app.message);
        let requests = stub.finish();
        assert_eq!(requests[0].method, "GET");
        assert!(!requests[0].headers.contains("x-meshlake-admin-token"));
        assert_eq!(requests[1].method, "POST");
        assert_eq!(requests[1].path, format!("/v1/networks/{network}/policy"));
        assert!(requests[1]
            .headers
            .contains("x-meshlake-admin-token: fixture-admin"));
        assert_eq!(requests[1].body, body);
    }

    #[test]
    fn failed_policy_and_member_routes_never_report_success_or_reflect_credentials() {
        let stub = crate::api_tests::Stub::new(vec![
            (403, json!("fixture-admin")),
            (403, json!("fixture-admin")),
        ]);
        let mut app = stub.app();
        let network = Uuid::from_u128(1);
        let device = Uuid::from_u128(2);
        app.save_policy_sync(network, json!({"routes":[],"exit_nodes":[],"dns":{}}));
        assert!(app.message.contains("403"));
        assert!(!app.message.contains("fixture-admin"));
        app.save_member_routes_sync(network, device, vec!["10.0.0.0/8".into()]);
        assert!(app.message.contains("403"));
        assert!(!app.message.contains("fixture-admin"));
        let requests = stub.finish();
        assert_eq!(
            requests[1].path,
            format!("/v1/networks/{network}/members/{device}/allowed-routes")
        );
        assert_eq!(requests[1].body, json!({"allowed_routes":["10.0.0.0/8"]}));
    }
    #[test]
    fn requires_loaded_policy_and_valid_device_and_dns_inputs() {
        let mut editor = PolicyEditor::default();
        assert!(editor.request().is_err());
        editor.loaded = true;
        editor.routes.push(("10.0.0.0/8".into(), "invalid".into()));
        assert!(editor.request().is_err());
        editor.routes[0].1 = Uuid::from_u128(1).to_string();
        editor.dns_servers = "bad-dns".into();
        assert!(editor.request().is_err());
        editor.dns_servers = "10.0.0.1\nfd00::1".into();
        let value = editor.request().unwrap();
        assert_eq!(value["dns"]["servers"], json!(["10.0.0.1", "fd00::1"]));
        assert_eq!(
            value["routes"][0]["gateway_device_id"],
            Uuid::from_u128(1).to_string()
        );
    }
}
