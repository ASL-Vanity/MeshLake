//! Loopback fixtures never bind the live agent port or use saved credentials.
use super::*;

#[test]
fn failed_and_malformed_api_responses_never_echo_submitted_secrets() {
    let stub = Stub::new(vec![
        (403, json!({"error":"fixture-admin"})),
        (200, json!({"device_id":"fixture-admin"})),
    ]);
    let mut app = stub.app();
    app.adapter_sync(true);
    assert!(app.message.contains("403"));
    assert!(!app.message.contains("fixture-admin"));
    app.sessions = Some(serde_json::from_value(json!({"schema_version":1,"generated_at_unix_ms":0,"transport_revision":0,"sessions":[]})).unwrap());
    app.refresh_sync();
    assert!(app.status.is_none());
    assert!(app.sessions.is_none());
    assert!(!app.message.contains("fixture-admin"));
    assert_eq!(stub.finish().len(), 2);
}
use std::{
    io::{Read, Write},
    net::TcpListener,
    sync::mpsc,
    time::Instant,
};

#[test]
fn standalone_token_needs_no_public_key_or_planet_and_clears_stale_secrets_on_failure() {
    let stub = Stub::new(vec![
        (200, json!({"token":"fixture-enrollment"})),
        (403, json!("fixture-admin")),
    ]);
    let mut app = stub.app();
    let network = Uuid::from_u128(1);
    app.invite_lifetime = 7200;
    app.generated_invite = "stale-link".into();
    app.issue_standalone_token_sync(network);
    assert_eq!(app.issued_token, "fixture-enrollment");
    assert!(app.controller_public_key.is_empty());
    assert!(app.generated_invite.is_empty());
    app.issue_standalone_token_sync(network);
    assert!(app.issued_token.is_empty());
    assert!(app.message.contains("403"));
    assert!(!app.message.contains("fixture-admin"));
    let requests = stub.finish();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].method, "POST");
    assert_eq!(
        requests[0].path,
        format!("/v1/networks/{network}/enrollment-tokens")
    );
    assert_eq!(requests[0].body, json!({"expires_in_seconds":7200}));
    assert!(requests[0]
        .headers
        .contains("x-meshlake-admin-token: fixture-admin"));
}

#[derive(Debug)]
pub(super) struct Request {
    pub(super) method: String,
    pub(super) path: String,
    pub(super) headers: String,
    pub(super) body: serde_json::Value,
}

pub(super) struct Stub {
    base: String,
    requests: mpsc::Receiver<Request>,
    thread: std::thread::JoinHandle<()>,
}
impl Stub {
    pub(super) fn new(responses: Vec<(u16, serde_json::Value)>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let (tx, requests) = mpsc::channel();
        let thread = std::thread::spawn(move || {
            for (code, body) in responses {
                let deadline = Instant::now() + Duration::from_secs(8);
                let mut socket = loop {
                    match listener.accept() {
                        Ok((socket, _)) => break socket,
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            assert!(Instant::now() < deadline, "mock accept timed out");
                            std::thread::sleep(Duration::from_millis(5));
                        }
                        Err(e) => panic!("{e}"),
                    }
                };
                socket.set_nonblocking(false).unwrap();
                socket
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .unwrap();
                let mut bytes = Vec::new();
                let header_end = loop {
                    let mut chunk = [0; 4096];
                    let n = socket.read(&mut chunk).unwrap();
                    assert!(n > 0);
                    bytes.extend_from_slice(&chunk[..n]);
                    assert!(bytes.len() < 1024 * 1024);
                    if let Some(pos) = bytes.windows(4).position(|b| b == b"\r\n\r\n") {
                        break pos + 4;
                    }
                };
                let headers = String::from_utf8(bytes[..header_end].to_vec()).unwrap();
                let length = headers
                    .lines()
                    .find_map(|line| {
                        let (key, value) = line.split_once(':')?;
                        key.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().unwrap())
                    })
                    .unwrap_or(0);
                while bytes.len() < header_end + length {
                    let mut chunk = [0; 4096];
                    let n = socket.read(&mut chunk).unwrap();
                    assert!(n > 0);
                    bytes.extend_from_slice(&chunk[..n]);
                }
                let first: Vec<_> = headers.lines().next().unwrap().split_whitespace().collect();
                tx.send(Request {
                    method: first[0].into(),
                    path: first[1].into(),
                    headers: headers.clone(),
                    body: if length == 0 {
                        serde_json::Value::Null
                    } else {
                        serde_json::from_slice(&bytes[header_end..header_end + length]).unwrap()
                    },
                })
                .unwrap();
                let body = body.to_string();
                write!(socket, "HTTP/1.1 {code} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
            }
        });
        Self {
            base,
            requests,
            thread,
        }
    }
    pub(super) fn app(&self) -> App {
        let mut app = App::default();
        app.client = Client::builder()
            .no_proxy()
            .timeout(Duration::from_secs(3))
            .build()
            .unwrap();
        app.api_base = format!("{}/v1", self.base);
        app.controller = self.base.clone();
        app.admin_token = "fixture-admin".into();
        app.admin_token_bound_value = app.admin_token.clone();
        app.admin_token_controller = Some(self.base.clone());
        app
    }
    pub(super) fn finish(self) -> Vec<Request> {
        self.thread.join().unwrap();
        self.requests.try_iter().collect()
    }
}

fn status() -> serde_json::Value {
    json!({"device_id": Uuid::nil(), "adapter_state": "active", "networks": []})
}

#[test]
fn manual_and_invitation_enrollment_forward_identity_and_trust_without_admin_credentials() {
    let network = Uuid::from_u128(71);
    let device = Uuid::from_u128(72);
    let key = vec![4u8; 32];
    let device_key = vec![5u8; 32];
    // Synthetic signatures are fixtures; this test checks GUI HTTP contracts,
    // while cryptographic verification remains the agent's responsibility.
    let enrolled = json!({"network":{"id":network,"name":"test","ipv4_prefix":"10.71.0.0/24","ipv6_prefix":null,"relay_policy":"Preferred"},
        "certificate":{"claims":{"network_id":network,"device_id":device,"device_public_key":device_key,
            "assigned_addresses":["10.71.0.2"],"allowed_routes":[],"issued_at_unix_seconds":1,"expires_at_unix_seconds":1000},
            "controller_public_key":key,"signature":[]},"network_key":vec![9u8;32],
        "authorization":{"version":1,"network_id":network,"authorization_epoch":1,"network_key_epoch":1,
            "active_members":[],"revoked_certificate_ids":[],"issued_at_unix_seconds":1,"expires_at_unix_seconds":1000,
            "controller_public_key":key,"signature":[]}});
    for invitation in [false, true] {
        let stub = Stub::new(vec![
            (
                200,
                json!({"device_id":device,"identity_public_key":device_key,"adapter_state":"active","networks":[]}),
            ),
            (200, enrolled.clone()),
            (200, json!({})),
            (200, status()),
        ]);
        let mut app = stub.app();
        app.status = Some(serde_json::from_value(json!({"device_id":Uuid::from_u128(99),"identity_public_key":vec![8u8;32],"adapter_state":"active","networks":[]})).unwrap());
        app.network_id = network.to_string();
        app.public_key = STANDARD.encode(&key);
        app.token = "fixture-enrollment".into();
        if invitation {
            app.invite_link =
                make_invite_link(&app.controller, network, &app.token, &app.public_key, None)
                    .unwrap();
            app.join_invite_link_sync();
        } else {
            app.join_network_sync(None);
        }
        assert!(app.token.is_empty(), "join failed: {}", app.message);
        let requests = stub.finish();
        assert_eq!(requests[0].path, "/v1/status");
        assert_eq!(requests[0].method, "GET");
        assert_eq!(requests[1].path, "/v1/enroll");
        assert_eq!(
            requests[1].body,
            json!({"network_id":network,"device_id":device,"device_public_key":device_key,"token":"fixture-enrollment"})
        );
        assert_eq!(requests[2].path, "/v1/networks/enroll");
        assert_eq!(
            requests[2].body["enrollment"]["network_key"],
            json!(vec![9u8; 32])
        );
        assert_eq!(requests[2].body["controller_public_key"], json!(key));
        assert!(requests
            .iter()
            .all(|r| !r.headers.contains("x-meshlake-admin-token")));
        assert!(!app.message.contains("fixture-enrollment"));
    }
}

#[test]
fn enrollment_identity_failures_never_contact_controller_or_consume_input() {
    for invitation in [false, true] {
        for response in [
            (403, json!({"error":"fixture-enrollment"})),
            (200, json!({"device_id":"not-a-uuid"})),
            (200, status()),
            (
                200,
                json!({"device_id":Uuid::nil(),"identity_public_key":[1],"adapter_state":"active","networks":[]}),
            ),
        ] {
            let stub = Stub::new(vec![response]);
            let controller = TcpListener::bind("127.0.0.1:0").unwrap();
            controller.set_nonblocking(true).unwrap();
            let mut app = stub.app();
            app.controller = format!("http://{}", controller.local_addr().unwrap());
            app.request_timeout = 1;
            app.status = Some(serde_json::from_value(json!({"device_id":Uuid::from_u128(99),"identity_public_key":vec![8u8;32],"adapter_state":"active","networks":[]})).unwrap());
            app.network_id = Uuid::from_u128(71).to_string();
            app.public_key = STANDARD.encode([4u8; 32]);
            app.token = "fixture-enrollment".into();
            let expected = (
                app.controller.clone(),
                app.network_id.clone(),
                app.public_key.clone(),
            );
            if invitation {
                app.invite_link = make_invite_link(
                    &app.controller,
                    Uuid::from_u128(71),
                    &app.token,
                    &app.public_key,
                    None,
                )
                .unwrap();
                app.join_invite_link_sync();
            } else {
                app.join_network_sync(None);
            }
            assert_eq!(app.token, "fixture-enrollment");
            assert_eq!(
                (
                    app.controller.clone(),
                    app.network_id.clone(),
                    app.public_key.clone()
                ),
                expected
            );
            assert!(app.message.contains("尚未提交"), "{}", app.message);
            assert!(!app.message.contains("fixture-enrollment"));
            assert!(
                matches!(controller.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
            );
            let requests = stub.finish();
            assert_eq!(requests.len(), 1);
            assert_eq!(requests[0].path, "/v1/status");
        }
    }
}

#[test]
fn enrollment_invalid_controller_key_is_rejected_before_agent_lookup() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let mut app = App::default();
    app.api_base = format!("http://{}/v1", listener.local_addr().unwrap());
    app.network_id = Uuid::from_u128(71).to_string();
    app.public_key = "invalid".into();
    app.token = "fixture-enrollment".into();
    app.join_network_sync(None);
    assert!(app.message.contains("Base64"));
    assert_eq!(app.token, "fixture-enrollment");
    assert!(
        matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
    );
}

#[test]
fn adapter_stop_and_leave_use_delete_and_keep_action_feedback() {
    let stub = Stub::new(vec![
        (200, json!({})),
        (200, status()),
        (
            200,
            json!({"schema_version":1,"generated_at_unix_ms":0,"transport_revision":0,"sessions":[]}),
        ),
        (200, json!({})),
        (200, status()),
    ]);
    let mut app = stub.app();
    let id = Uuid::new_v4();
    app.adapter_sync(false);
    assert!(app.message.contains("停止"), "{}", app.message);
    app.leave_network_sync(id);
    let requests = stub.finish();
    assert_eq!(requests[0].method, "DELETE");
    assert_eq!(requests[0].path, "/v1/adapter");
    assert_eq!(requests[3].method, "DELETE");
    assert_eq!(requests[3].path, format!("/v1/networks/{id}"));
    assert!(requests
        .iter()
        .all(|r| !r.headers.to_lowercase().contains("x-meshlake-admin-token")));
}

#[test]
fn relay_gateway_and_clear_match_cli_payloads() {
    let stub = Stub::new(vec![(200, json!({})); 4]);
    let mut app = stub.app();
    let id = Uuid::new_v4();
    app.exit_network_id = id.to_string();
    app.relay_endpoint = " relay.example:1234 ".into();
    app.stun_servers = "first:3478, second:3478,,".into();
    app.upnp_enabled = false;
    app.configure_relay_sync();
    app.egress_interface = "Ethernet 2".into();
    app.enable_ipv4_gateway = true;
    app.enable_ipv6_gateway = true;
    app.apply_exit_gateway_sync();
    app.clear_exit_selection_sync();
    app.remove_exit_gateway_sync();
    let requests = stub.finish();
    assert_eq!(
        requests[0].body,
        json!({"endpoint":"relay.example:1234", "enable_upnp":false,"stun_servers":["first:3478","second:3478"]})
    );
    assert_eq!(
        requests[1].body,
        json!({"egress_interface":"Ethernet 2","enable_ipv4":true,"enable_ipv6":true})
    );
    assert_eq!(
        requests[2].body,
        json!({"ipv4_gateway":null,"ipv6_gateway":null,"kill_switch":false})
    );
    assert_eq!(requests[3].method, "DELETE");
    assert_eq!(requests[3].path, format!("/v1/networks/{id}/exit-gateway"));
}

#[test]
fn controller_create_sends_all_options_and_binds_admin_header_only_to_mutation() {
    let stub = Stub::new(vec![(200, json!({})), (200, json!([]))]);
    let mut app = stub.app();
    app.name = " office ".into();
    app.managed_create_id = Uuid::from_u128(42).to_string();
    app.prefix = "100.64.10.0/24".into();
    app.ipv6_prefix = "fd00::/64".into();
    app.network_relay_policy = RelayPolicy::Required;
    app.create_managed_network_sync();
    let requests = stub.finish();
    assert_eq!(requests[0].body["name"], "office");
    assert_eq!(requests[0].body["id"], Uuid::from_u128(42).to_string());
    assert_eq!(requests[0].body["ipv6_prefix"], "fd00::/64");
    assert_eq!(requests[0].body["relay_policy"], "Required");
    assert!(requests[0]
        .headers
        .to_lowercase()
        .contains("x-meshlake-admin-token: fixture-admin"));
    assert!(!requests[1]
        .headers
        .to_lowercase()
        .contains("x-meshlake-admin-token"));
}

#[test]
fn invitation_lifetime_and_input_are_preserved() {
    let stub = Stub::new(vec![
        (
            200,
            json!({"public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}),
        ),
        (200, json!({"token":"fixture-enrollment"})),
    ]);
    let mut app = stub.app();
    app.invite_link = "existing-input".into();
    app.invite_lifetime = 3600;
    app.issue_enrollment_token_sync(Uuid::new_v4());
    assert_eq!(app.invite_link, "existing-input");
    assert!(parse_invite_link(&app.generated_invite).is_ok());
    let requests = stub.finish();
    assert_eq!(requests[1].body["expires_in_seconds"], 3600);
}

#[test]
fn failed_gateway_and_stale_status_never_report_success() {
    let stub = Stub::new(vec![
        (503, json!({"error":"unavailable"})),
        (500, json!({})),
    ]);
    let mut app = stub.app();
    app.exit_network_id = Uuid::new_v4().to_string();
    app.remove_exit_gateway_sync();
    assert!(app.message.contains("503"));
    assert!(!app.message.contains("已停用"));
    app.status = Some(serde_json::from_value(status()).unwrap());
    app.refresh_sync();
    assert!(app.status.is_none());
    stub.finish();
}

#[test]
fn local_network_create_keeps_optional_id_and_ipv6() {
    let stub = Stub::new(vec![(200, json!({})), (200, status())]);
    let mut app = stub.app();
    let id = Uuid::new_v4();
    app.network_id = id.to_string();
    app.name = "local".into();
    app.ipv6_prefix = "fd00:10::/64".into();
    app.network_relay_policy = RelayPolicy::Disabled;
    app.create_local_network_sync();
    let requests = stub.finish();
    assert_eq!(requests[0].path, "/v1/networks");
    assert_eq!(requests[0].body["id"], id.to_string());
    assert_eq!(requests[0].body["ipv6_prefix"], "fd00:10::/64");
    assert_eq!(requests[0].body["relay_policy"], "Disabled");
}

#[test]
fn asynchronous_controller_query_redacts_nested_secrets_and_has_no_admin_header() {
    let stub = Stub::new(vec![(
        200,
        json!({"version": 1, "nested":{"network_key":[1,2,3], "token":"fixture-private"}}),
    )]);
    let mut app = stub.app();
    app.read_controller_document("/v1/planet".into());
    let context = egui::Context::default();
    let deadline = Instant::now() + Duration::from_secs(5);
    while app.job.is_some() {
        assert!(Instant::now() < deadline, "GUI job did not complete");
        app.poll_job(&context);
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(app.controller_document.contains("version"));
    assert!(!app.controller_document.contains("network_key"));
    assert!(!app.controller_document.contains("fixture-private"));
    let requests = stub.finish();
    assert_eq!(requests[0].path, "/v1/planet");
    assert!(!requests[0]
        .headers
        .to_lowercase()
        .contains("x-meshlake-admin-token"));
}
