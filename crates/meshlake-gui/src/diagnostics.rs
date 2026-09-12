use super::*;
use std::net::SocketAddr;

pub(super) struct DiagnosticFields {
    api_url: String,
    timeout: u64,
    tcp_enabled: bool,
    tcp_target: String,
}

impl Default for DiagnosticFields {
    fn default() -> Self {
        Self {
            api_url: LOCAL_API.into(),
            timeout: 30,
            tcp_enabled: false,
            tcp_target: String::new(),
        }
    }
}

fn local_endpoint(value: &str) -> Result<String, String> {
    let normalized = normalize_http_url(value, "local API URL", true)?;
    let parsed = url::Url::parse(&normalized).map_err(|e| e.to_string())?;
    let loopback = match parsed.host() {
        Some(url::Host::Domain(name)) => name.eq_ignore_ascii_case("localhost"),
        Some(url::Host::Ipv4(ip)) => ip.is_loopback(),
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => false,
    };
    if !loopback {
        return Err("本机 API 仅允许回环地址。 / Local API must use a loopback address.".into());
    }
    Ok(normalized.trim_end_matches('/').into())
}

impl App {
    fn apply_api_settings(&mut self) -> Result<(), String> {
        let base = local_endpoint(&self.diagnostics.api_url)?;
        if !(1..=3600).contains(&self.diagnostics.timeout) {
            return Err("请求超时必须为 1–3600 秒。 / Timeout must be 1–3600 seconds.".into());
        }
        let ca = normalize_optional_tls_ca(&self.controller_tls_ca_pem)?;
        let client = configured_http_client(
            ca.as_deref(),
            Duration::from_secs(self.diagnostics.timeout),
            true,
        )?;
        if base != self.api_base {
            self.status = None;
            self.sessions = None;
        }
        self.client = client;
        self.api_base = base;
        self.request_timeout = self.diagnostics.timeout;
        Ok(())
    }

    pub(super) fn diagnostics_panel(&mut self, ui: &mut egui::Ui) {
        design::card(ui, |ui| {
            ui.heading(self.t("连接设置与诊断", "Connection settings and diagnostics"));
            ui.label(self.t("本机 API 地址（包含 /v1）", "Local API URL (including /v1)"));
            ui.add(design::input(&mut self.diagnostics.api_url).desired_width(f32::INFINITY));
            ui.collapsing(self.t("本机 HTTPS 私有 CA", "Private CA for local HTTPS"), |ui| {
                self.ca_file_ui(ui);
                ui.label(self.t("与控制器私有 CA 共用证书设置，修改后点击应用连接设置。", "Shares the controller private CA certificate setting. Apply connection settings after changing it."));
            });
            ui.horizontal(|ui| {
                ui.label(self.t("请求超时（秒）", "Request timeout (seconds)"));
                ui.add(egui::DragValue::new(&mut self.diagnostics.timeout).range(1..=3600));
                if ui
                    .button(self.t("应用连接设置", "Apply connection settings"))
                    .clicked()
                {
                    self.message = match self.apply_api_settings() {
                        Ok(()) => self
                            .t(
                                "连接设置已应用，本次运行有效。",
                                "Connection settings applied for this run.",
                            )
                            .into(),
                        Err(error) => error,
                    };
                }
            });
            ui.small(format!(
                "{} {}",
                self.t("当前地址：", "Active endpoint:"),
                self.api_base
            ));
            let label = self.t("额外探测指定 TCP 地址", "Also probe a specific TCP address");
            ui.checkbox(&mut self.diagnostics.tcp_enabled, label);
            if self.diagnostics.tcp_enabled {
                ui.label(self.t(
                    "目标 IP:端口（IPv6 使用 [地址]:端口）",
                    "Target IP:port (IPv6 uses [address]:port)",
                ));
                ui.add(design::input(&mut self.diagnostics.tcp_target));
            }
            ui.small(self.t("诊断读取状态与会话；可选 TCP 探测只尝试连接，不发送应用数据。结果不代表完整网络验收。", "Diagnostics inspect status and sessions. Optional TCP probing connects without application data; it is not full network acceptance."));
            if ui.button(self.t("运行诊断", "Run diagnostics")).clicked() {
                let target = if self.diagnostics.tcp_enabled {
                    match self.diagnostics.tcp_target.trim().parse::<SocketAddr>() {
                        Ok(address) => Some(address),
                        Err(_) => {
                            self.message = self
                                .t(
                                    "TCP 目标必须是有效的 IP:端口。",
                                    "TCP target must be a valid IP:port.",
                                )
                                .into();
                            return;
                        }
                    }
                } else {
                    None
                };
                match self.apply_api_settings() {
                    Ok(()) => self.start_job(move |app| app.diagnose_sync(target)),
                    Err(error) => self.message = error,
                }
            }
        });
    }

    fn diagnose_sync(&mut self, tcp: Option<SocketAddr>) {
        let mut checks = Vec::new();
        let mut ok = true;
        for resource in ["status", "sessions"] {
            let result = (|| -> Result<serde_json::Value, String> {
                let response = self
                    .client
                    .get(format!("{}/{resource}", self.api_base))
                    .send()
                    .map_err(|_| "无法连接本机 API / Could not connect to local API".to_owned())?;
                if !response.status().is_success() {
                    return Err(format!("HTTP {}", response.status()));
                }
                if resource == "status" {
                    let status = response
                        .json::<AgentStatus>()
                        .map_err(|_| "Invalid status response")?;
                    self.status = Some(status.clone());
                    serde_json::to_value(status).map_err(|e| e.to_string())
                } else {
                    let sessions = response
                        .json::<SessionList>()
                        .map_err(|_| "Invalid sessions response")?;
                    self.sessions = Some(sessions.clone());
                    serde_json::to_value(sessions).map_err(|e| e.to_string())
                }
            })();
            match result {
                Ok(data) => checks.push(json!({"check":resource,"ok":true,"data":data})),
                Err(error) => {
                    ok = false;
                    if resource == "status" {
                        self.status = None;
                    } else {
                        self.sessions = None;
                    }
                    checks.push(json!({"check":resource,"ok":false,"error":error}));
                }
            }
        }
        if let Some(address) = tcp {
            let started = std::time::Instant::now();
            let result =
                TcpStream::connect_timeout(&address, Duration::from_secs(self.request_timeout));
            ok &= result.is_ok();
            checks.push(json!({"check":"tcp_connect","target":address.to_string(),"ok":result.is_ok(),
                "elapsed_ms":started.elapsed().as_millis(),"error":result.err().map(|e| e.to_string())}));
        }
        self.cli_output = file_io::sanitized_json(&json!({"schema_version":1,"ok":ok,"checks":checks,
            "scope":"Local API inspection and optional TCP connect only; not overlay, UDP, routing, DNS or failover acceptance."})).unwrap_or_else(|_| "Could not serialize diagnostic results".into());
        self.message = if ok {
            self.t("诊断检查通过。", "Diagnostic checks passed.")
        } else {
            self.t(
                "部分诊断检查失败，请查看执行结果。",
                "Some diagnostic checks failed; inspect the results.",
            )
        }
        .into();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn endpoint_accepts_only_loopback_without_credentials_or_redirects() {
        for value in [
            "http://127.0.0.1:1234/v1",
            "http://[::1]:1234/v1/",
            "http://localhost:1234/v1",
            "http://localhost:1234/proxy/v1",
        ] {
            assert!(local_endpoint(value).is_ok(), "{value}");
        }
        for value in [
            "https://remote.example/v1",
            "http://192.168.1.1/v1",
            "http://localhost/",
            "http://a:b@localhost/v1",
            "http://localhost/v1?token=secret",
            "http://localhost/v1#fragment",
        ] {
            assert!(local_endpoint(value).is_err(), "{value}");
        }
        let mut app = App::default();
        app.diagnostics.timeout = 0;
        assert!(app.apply_api_settings().is_err());
        assert_eq!(app.request_timeout, 30);
    }

    #[test]
    fn diagnostic_success_includes_tcp_without_sending_application_data() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let stub = crate::api_tests::Stub::new(vec![
            (
                200,
                json!({"device_id":Uuid::nil(),"adapter_state":"active","networks":[]}),
            ),
            (
                200,
                json!({"schema_version":1,"generated_at_unix_ms":0,"transport_revision":0,"sessions":[]}),
            ),
        ]);
        let mut app = stub.app();
        app.diagnose_sync(Some(address));
        let result: serde_json::Value = serde_json::from_str(&app.cli_output).unwrap();
        assert_eq!(result["ok"], true);
        assert_eq!(result["checks"][2]["check"], "tcp_connect");
        assert_eq!(result["checks"][2]["ok"], true);
        assert!(app.status.is_some() && app.sessions.is_some());
        listener.set_nonblocking(true).unwrap();
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut byte = [0u8; 1];
        assert_eq!(std::io::Read::read(&mut stream, &mut byte).unwrap(), 0);
        assert_eq!(stub.finish().len(), 2);
    }

    #[test]
    fn tcp_failure_does_not_report_overall_success_or_erase_api_results() {
        let stub = crate::api_tests::Stub::new(vec![
            (
                200,
                json!({"device_id":Uuid::nil(),"adapter_state":"active","networks":[]}),
            ),
            (
                200,
                json!({"schema_version":1,"generated_at_unix_ms":0,"transport_revision":0,"sessions":[]}),
            ),
        ]);
        let mut app = stub.app();
        app.request_timeout = 1;
        // Port zero is not a connectable TCP endpoint; no external listener is used.
        app.diagnose_sync(Some("127.0.0.1:0".parse().unwrap()));
        let result: serde_json::Value = serde_json::from_str(&app.cli_output).unwrap();
        assert_eq!(result["ok"], false);
        assert_eq!(result["checks"][0]["ok"], true);
        assert_eq!(result["checks"][1]["ok"], true);
        assert_eq!(result["checks"][2]["ok"], false);
        assert!(result["checks"][2]["error"].is_string());
        assert!(app.status.is_some() && app.sessions.is_some());
        assert_eq!(stub.finish().len(), 2);
    }

    #[test]
    fn diagnostic_failures_clear_stale_data_and_do_not_echo_response_secrets() {
        let stub = crate::api_tests::Stub::new(vec![
            (403, json!("fixture-admin")),
            (
                200,
                json!({
                    "schema_version":1,"generated_at_unix_ms":0,"transport_revision":0,"sessions":[]
                }),
            ),
        ]);
        let mut app = stub.app();
        app.status = Some(
            serde_json::from_value(
                json!({"device_id":Uuid::nil(),"adapter_state":"active","networks":[]}),
            )
            .unwrap(),
        );
        app.diagnose_sync(None);
        assert!(app.status.is_none());
        assert!(app.sessions.is_some());
        assert!(!app.cli_output.contains("fixture-admin"));
        let result: serde_json::Value = serde_json::from_str(&app.cli_output).unwrap();
        assert_eq!(result["ok"], false);
        assert_eq!(result["checks"].as_array().unwrap().len(), 2);
        let requests = stub.finish();
        assert_eq!(requests[0].path, "/v1/status");
        assert_eq!(requests[1].path, "/v1/sessions");
        assert!(requests
            .iter()
            .all(|r| !r.headers.contains("x-meshlake-admin-token")));
    }
}
