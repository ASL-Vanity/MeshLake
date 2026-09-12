use super::*;
use std::io::{Read, Write};

pub(super) fn sanitized_json(value: &impl Serialize) -> Result<String, serde_json::Error> {
    fn redact(value: &mut serde_json::Value) {
        match value {
            serde_json::Value::Object(object) => {
                for key in [
                    "network_key",
                    "identity_secret_key",
                    "token",
                    "admin_token",
                    "password",
                    "invite_link",
                ] {
                    object.remove(key);
                }
                for child in object.values_mut() {
                    redact(child);
                }
            }
            serde_json::Value::Array(items) => {
                for item in items {
                    redact(item);
                }
            }
            _ => {}
        }
    }
    let mut value = serde_json::to_value(value)?;
    redact(&mut value);
    serde_json::to_string_pretty(&value)
}

fn export_json(path: &str, json: &str) -> Result<(), String> {
    // Reject absent/invalid serialization before creating the destination.
    serde_json::from_str::<serde_json::Value>(json).map_err(|_| {
        "没有有效的 JSON 可导出。 / No valid JSON is available to export.".to_owned()
    })?;
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path.trim())
        .and_then(|mut file| {
            file.write_all(json.as_bytes())?;
            file.sync_all()
        })
        .map_err(|_| "导出失败：检查路径和权限；已有文件不会被覆盖。 / Export failed: check path and permissions; existing files are not overwritten.".to_owned())
}

#[derive(Default)]
pub(super) struct FileFields {
    invite: String,
    enrollment: String,
    admin: String,
    ca: String,
    invite_export: String,
    token_export: String,
    session_export: String,
    status_export: String,
}

pub(super) enum Credential {
    Invite,
    Enrollment,
    Admin,
}

fn read_credential(path: &str) -> Result<String, String> {
    let value =
        meshlake_core::read_restricted_secret_string_file(std::path::Path::new(path.trim()))
            .map_err(|_| "凭据文件读取失败，请检查路径和文件访问权限。 / Could not read credential file; check path and permissions.".to_owned())?;
    let value = value.trim_end_matches(['\r', '\n']);
    if value.is_empty() {
        return Err("凭据文件为空。 / Credential file is empty.".into());
    }
    Ok(value.to_owned())
}

fn read_ca(path: &str) -> Result<String, String> {
    let mut file = fs::File::open(path.trim())
        .map_err(|_| "无法打开 CA 文件。 / Could not open CA file.")?
        .take(1024 * 1024 + 1);
    let mut pem = String::new();
    file.read_to_string(&mut pem)
        .map_err(|_| "CA 文件不是有效 UTF-8 文本。 / CA file is not valid UTF-8 text.")?;
    if pem.len() > 1024 * 1024 {
        return Err("CA 文件超过 1 MiB。 / CA file exceeds 1 MiB.".into());
    }
    normalize_tls_ca_pem(&pem)
}

impl App {
    pub(super) fn standalone_token_ui(&mut self, ui: &mut egui::Ui) {
        let Some(network) = self.selected_network else {
            return;
        };
        design::card(ui, |ui| {
            ui.heading(self.t("独立入网令牌", "Standalone enrollment token"));
            ui.small(self.t("适用于手动入网，不要求控制器配置 Planet。令牌保存到新的受限权限文件。", "For manual enrollment without a Planet configuration. Save the token to a new restricted file."));
            ui.label(format!("{} {network}", self.t("网络：", "Network:")));
            ui.horizontal_wrapped(|ui| {
                ui.label(self.t("有效期（秒）", "Lifetime (seconds)"));
                ui.add(egui::DragValue::new(&mut self.invite_lifetime).range(60..=86400));
            });
            ui.label(self.t("令牌文件路径", "Token file path"));
            ui.add(design::input(&mut self.files.token_export));
            let label = self.t("选择保存位置…", "Choose destination…");
            file_picker::browse(
                ui,
                &mut self.files.token_export,
                true,
                label,
                &mut self.message,
            );
            if ui
                .button(self.t("签发并保存令牌", "Issue and save token"))
                .clicked()
            {
                let path = std::path::PathBuf::from(self.files.token_export.trim());
                if self.files.token_export.trim().is_empty() {
                    self.message = self
                        .t(
                            "请选择尚不存在的令牌文件路径。",
                            "Choose a token file path that does not already exist.",
                        )
                        .into();
                } else {
                    self.start_job(move |app| {
                        if path.exists() {
                            app.message = app.t("请选择尚不存在的令牌文件路径。", "Choose a token file path that does not already exist.").into();
                            return;
                        }
                        app.issue_standalone_token_sync(network);
                        if !app.issued_token.is_empty() {
                            app.message = match meshlake_core::create_restricted_secret_file(&path, app.issued_token.as_bytes()) {
                                Ok(()) => app.t("令牌已签发并保存到受限文件。", "Token issued and saved to a restricted file.").into(),
                                Err(_) => app.t("令牌已签发，但文件保存失败；请更换路径后使用“保存现有令牌”。", "Token issued, but saving failed. Choose another path and use Save existing token.").into(),
                            };
                        }
                    });
                }
            }
            if !self.issued_token.is_empty() {
                ui.label(self.t("最近签发的令牌", "Most recently issued token"));
                ui.add(
                    design::input(&mut self.issued_token)
                        .password(true)
                        .interactive(false),
                );
                if ui
                    .button(self.t("保存现有令牌", "Save existing token"))
                    .clicked()
                {
                    let path = self.files.token_export.clone();
                    self.start_job(move |app| {
                        app.message = match meshlake_core::create_restricted_secret_file(std::path::Path::new(path.trim()), app.issued_token.as_bytes()) {
                            Ok(()) => app.t("令牌已保存到受限文件。", "Token saved to a restricted file.").into(),
                            Err(_) => app.t("保存失败，请检查路径、权限及文件是否已存在。", "Save failed; check the path, permissions and whether the file already exists.").into(),
                        };
                    });
                }
            }
        });
    }

    pub(super) fn issue_standalone_token_sync(&mut self, network: Uuid) {
        self.issued_token.clear();
        self.generated_invite.clear();
        let result = (|| -> Result<String, String> {
            if !(60..=86400).contains(&self.invite_lifetime) {
                return Err(
                    "有效期必须为 60–86400 秒。 / Lifetime must be 60–86400 seconds.".into(),
                );
            }
            let response = self
                .controller_request(
                    reqwest::Method::POST,
                    format!("/v1/networks/{network}/enrollment-tokens"),
                    true,
                )?
                .json(&json!({"expires_in_seconds":self.invite_lifetime}))
                .send()
                .map_err(|_| "无法联系控制器。 / Could not contact controller.")?;
            if !response.status().is_success() {
                return Err(format!(
                    "{} {}",
                    self.t("令牌签发失败：", "Token issuance failed:"),
                    response.status()
                ));
            }
            let token = response
                .json::<IssuedToken>()
                .map_err(|_| "令牌响应无效。 / Invalid token response.")?;
            if token.token.trim().is_empty() {
                return Err("控制器返回了空令牌。 / Controller returned an empty token.".into());
            }
            Ok(token.token)
        })();
        match result {
            Ok(token) => {
                self.issued_token = token;
                self.message = self
                    .t(
                        "独立入网令牌已签发。",
                        "Standalone enrollment token issued.",
                    )
                    .into();
            }
            Err(error) => self.message = error,
        }
    }

    pub(super) fn credential_file_ui(&mut self, ui: &mut egui::Ui, kind: Credential) {
        let label = match kind {
            Credential::Invite => self.t("邀请链接文件", "Invitation file"),
            Credential::Enrollment => self.t("入网令牌文件", "Enrollment token file"),
            Credential::Admin => self.t("管理员令牌文件", "Admin token file"),
        };
        let browse_label = self.t("浏览…", "Browse…");
        let import_label = self.t("导入", "Import");
        let mut load = false;
        let path = match kind {
            Credential::Invite => &mut self.files.invite,
            Credential::Enrollment => &mut self.files.enrollment,
            Credential::Admin => &mut self.files.admin,
        };
        ui.horizontal_wrapped(|ui| {
            ui.label(label);
            ui.add(design::input(path).hint_text("C:\\…"));
            file_picker::browse(ui, path, false, browse_label, &mut self.message);
            load = ui.button(import_label).clicked();
        });
        if load {
            let path = path.clone();
            self.start_credential_import(path, kind);
        }
    }

    fn start_credential_import(&mut self, path: String, kind: Credential) {
        self.start_job(move |app| match read_credential(&path) {
            Ok(value) => {
                match kind {
                    Credential::Invite => {
                        if parse_invite_link(&value).is_err() {
                            app.message = app
                                .t(
                                    "文件中的邀请链接无效。",
                                    "The file contains an invalid invitation link.",
                                )
                                .into();
                            return;
                        }
                        app.invite_link = value;
                    }
                    Credential::Enrollment => app.token = value,
                    Credential::Admin => {
                        app.admin_token = value;
                        app.admin_token_bound_value.clear();
                    }
                }
                app.message = app
                    .t(
                        "凭据已导入，尚未提交。",
                        "Credential imported; it has not been submitted.",
                    )
                    .into();
            }
            Err(error) => app.message = error,
        });
    }

    pub(super) fn ca_file_ui(&mut self, ui: &mut egui::Ui) {
        ui.horizontal_wrapped(|ui| {
            ui.label(self.t("私有 CA 文件（可选）", "Private CA file (optional)"));
            ui.add(design::input(&mut self.files.ca));
            let label = self.t("浏览…", "Browse…");
            file_picker::browse(ui, &mut self.files.ca, false, label, &mut self.message);
            if ui.button(self.t("导入 CA", "Import CA")).clicked() {
                let path = self.files.ca.clone();
                self.start_job(move |app| match read_ca(&path) {
                    Ok(pem) => {
                        app.controller_tls_ca_pem = pem;
                        app.message = app.t("CA 已导入。", "CA imported.").into();
                    }
                    Err(error) => app.message = error,
                });
            }
        });
    }

    pub(super) fn invite_export_ui(&mut self, ui: &mut egui::Ui) {
        if self.generated_invite.is_empty() {
            return;
        }
        ui.horizontal_wrapped(|ui| {
            ui.label(self.t("保存邀请到新文件", "Save invitation to a new file"));
            ui.add(design::input(&mut self.files.invite_export));
            let label = self.t("选择保存位置…", "Choose destination…");
            file_picker::browse(
                ui,
                &mut self.files.invite_export,
                true,
                label,
                &mut self.message,
            );
            if ui.button(self.t("安全导出", "Export securely")).clicked() {
                let path = self.files.invite_export.clone();
                self.start_job(move |app| {
                    app.message = match meshlake_core::create_restricted_secret_file(
                        std::path::Path::new(path.trim()),
                        app.generated_invite.as_bytes(),
                    ) {
                        Ok(()) => app.t("邀请已保存到受限权限文件。", "Invitation saved to a restricted file.").into(),
                        Err(_) => app.t("导出失败：请检查路径、权限和文件是否已存在。", "Export failed; check path, permissions and whether the file already exists.").into(),
                    };
                });
            }
        });
    }

    pub(super) fn status_details_ui(&mut self, ui: &mut egui::Ui) {
        if self.status.is_some() {
            let copy_label = self.t("复制", "Copy");
            let path_label = self.t("导出到新文件", "Export to a new file");
            let browse_label = self.t("浏览…", "Browse…");
            let export_label = self.t("导出状态", "Export status");
            let success_message =
                self.t("已导出脱敏状态 JSON。", "Sanitized status JSON exported.");
            ui.collapsing(self.t("完整后台状态", "Full agent status"), |ui| {
                let Some(status) = &self.status else {
                    return;
                };
                let json = sanitized_json(status).unwrap_or_default();
                let mut display = json.clone();
                design::document_view(ui, "full-status-json", &mut display);
                if ui.button(copy_label).clicked() {
                    ui.ctx().copy_text(json.clone());
                }
                ui.label(path_label);
                ui.add(design::input(&mut self.files.status_export));
                file_picker::browse(
                    ui,
                    &mut self.files.status_export,
                    true,
                    browse_label,
                    &mut self.message,
                );
                if ui.button(export_label).clicked() {
                    self.start_json_export(
                        self.files.status_export.clone(),
                        json.clone(),
                        success_message,
                    );
                }
            });
        }
        if self.sessions.is_some() {
            let copy_label = self.t("复制", "Copy");
            let path_label = self.t("导出到新文件", "Export to a new file");
            let browse_label = self.t("浏览…", "Browse…");
            let export_label = self.t("导出会话", "Export sessions");
            let success_message = self.t("会话 JSON 已导出。", "Sessions JSON exported.");
            ui.collapsing(self.t("完整会话 JSON", "Full sessions JSON"), |ui| {
                let Some(sessions) = &self.sessions else {
                    return;
                };
                let json = sanitized_json(sessions).unwrap_or_default();
                let mut display = json.clone();
                design::document_view(ui, "full-sessions-json", &mut display);
                if ui.button(copy_label).clicked() {
                    ui.ctx().copy_text(json.clone());
                }
                ui.label(path_label);
                ui.add(design::input(&mut self.files.session_export));
                file_picker::browse(
                    ui,
                    &mut self.files.session_export,
                    true,
                    browse_label,
                    &mut self.message,
                );
                if ui.button(export_label).clicked() {
                    self.start_json_export(
                        self.files.session_export.clone(),
                        json.clone(),
                        success_message,
                    );
                }
            });
        }
    }

    fn start_json_export(&mut self, path: String, json: String, success_message: &'static str) {
        self.start_job(move |app| {
            app.message = match export_json(&path, &json) {
                Ok(()) => success_message.into(),
                Err(error) => error,
            };
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finish_file_job(app: &mut App) {
        let context = egui::Context::default();
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while app.job.is_some() {
            assert!(
                std::time::Instant::now() < deadline,
                "File job did not finish"
            );
            app.poll_job(&context);
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn credential_file_jobs_apply_valid_values_and_preserve_input_on_failure() {
        let directory =
            std::env::temp_dir().join(format!("meshlake-import-job-{}", Uuid::new_v4()));
        fs::create_dir(&directory).unwrap();
        let path = directory.join("凭据 导入.txt");
        meshlake_core::create_restricted_secret_file(&path, b"imported-token\r\n").unwrap();
        let mut app = App::default();
        app.settings.language = Language::English;
        app.admin_token = "previous-token".into();
        app.admin_token_bound_value = "previous-token".into();
        app.start_credential_import(path.to_str().unwrap().into(), Credential::Admin);
        assert!(app.job.is_some());
        assert_eq!(app.admin_token, "previous-token");
        finish_file_job(&mut app);
        assert_eq!(app.admin_token, "imported-token");
        assert!(app.admin_token_bound_value.is_empty());
        assert_eq!(
            app.message,
            "Credential imported; it has not been submitted."
        );

        app.start_credential_import(path.to_str().unwrap().into(), Credential::Enrollment);
        finish_file_job(&mut app);
        assert_eq!(app.token, "imported-token");

        app.invite_link = "previous-invitation".into();
        app.start_credential_import(path.to_str().unwrap().into(), Credential::Invite);
        finish_file_job(&mut app);
        assert_eq!(app.invite_link, "previous-invitation");
        assert_eq!(app.message, "The file contains an invalid invitation link.");
        assert!(!app.message.contains("imported-token"));
        fs::remove_file(path).unwrap();
        fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn json_export_job_reports_completed_write_and_preserves_existing_file() {
        let directory =
            std::env::temp_dir().join(format!("meshlake-export-job-{}", Uuid::new_v4()));
        fs::create_dir(&directory).unwrap();
        let path = directory.join("状态 导出.json");
        let mut app = App::default();
        app.start_json_export(
            path.to_str().unwrap().into(),
            "{\"ready\":true}".into(),
            "Exported",
        );
        assert!(app.job.is_some());
        assert_ne!(app.message, "Exported");
        finish_file_job(&mut app);
        assert_eq!(app.message, "Exported");
        let original = fs::read(&path).unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&original).unwrap()["ready"],
            true
        );

        app.start_json_export(path.to_str().unwrap().into(), "{}".into(), "Exported");
        finish_file_job(&mut app);
        assert_ne!(app.message, "Exported");
        assert!(!app.message.contains(path.to_str().unwrap()));
        assert_eq!(fs::read(&path).unwrap(), original);
        fs::remove_file(path).unwrap();
        fs::remove_dir(directory).unwrap();
    }

    #[test]
    fn json_export_supports_unicode_and_preserves_existing_files() {
        let directory = std::env::temp_dir().join(format!("meshlake-export-{}", Uuid::new_v4()));
        fs::create_dir(&directory).unwrap();
        let path = directory.join("状态 导出.json");
        let json = sanitized_json(&json!({"name":"验收网络", "network_key":"secret"})).unwrap();
        export_json(path.to_str().unwrap(), &json).unwrap();
        let original = fs::read(&path).unwrap();
        let error = export_json(path.to_str().unwrap(), "{}").unwrap_err();
        assert_eq!(original, fs::read(&path).unwrap());
        assert!(!error.contains(path.to_str().unwrap()));
        let value: serde_json::Value = serde_json::from_slice(&original).unwrap();
        assert_eq!(value["name"], "验收网络");
        assert!(value.get("network_key").is_none());
        fs::remove_file(&path).unwrap();
        assert!(export_json(path.to_str().unwrap(), "").is_err());
        assert!(
            !path.exists(),
            "Failed serialization must not leave an empty destination"
        );
        fs::remove_dir(directory).unwrap();
    }
    #[test]
    fn status_details_never_include_nested_network_or_identity_secrets() {
        let value = json!({"networks":[{"name":"visible", "network_key":[1,2,3], "control_plane":{"password":"hidden"}}], "identity_secret_key":"hidden"});
        let safe = sanitized_json(&value).unwrap();
        assert!(safe.contains("visible"));
        for secret in ["network_key", "identity_secret_key", "password", "hidden"] {
            assert!(!safe.contains(secret));
        }
    }
    #[test]
    fn credential_import_uses_restricted_files_and_trims_line_endings() {
        let path = std::env::temp_dir().join(format!("meshlake-gui-test-{}", Uuid::new_v4()));
        meshlake_core::create_restricted_secret_file(&path, b"test-token\r\n").unwrap();
        let result = read_credential(path.to_str().unwrap());
        fs::remove_file(&path).unwrap();
        assert_eq!(result.unwrap(), "test-token");
    }
    #[test]
    fn failed_import_does_not_echo_file_contents_or_sensitive_path() {
        let result = read_credential("missing-secret-file-123").unwrap_err();
        assert!(!result.contains("missing-secret-file-123"));
    }
}
