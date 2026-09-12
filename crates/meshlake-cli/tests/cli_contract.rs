//! Exercise the shipped command dispatcher and stdout/exit-code contract against
//! isolated loopback peers. No installed daemon or controller is contacted.
use std::{
    io::{Read, Write},
    net::TcpListener,
    process::{Command, Output},
    time::Duration,
};

fn cli(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_meshlake-cli"))
        .args(args)
        .output()
        .unwrap()
}

fn peer(body: String, delay: Duration) -> (String, std::thread::JoinHandle<String>) {
    peer_sequence(vec![body], delay)
}

fn peer_sequence(
    bodies: Vec<String>,
    delay: Duration,
) -> (String, std::thread::JoinHandle<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let url = format!("http://{}/v1", listener.local_addr().unwrap());
    let handle = std::thread::spawn(move || {
        let mut requests = Vec::new();
        for body in bodies {
            let deadline = std::time::Instant::now() + Duration::from_secs(10);
            let mut stream = loop {
                if let Ok((stream, _)) = listener.accept() {
                    break stream;
                }
                assert!(
                    std::time::Instant::now() < deadline,
                    "CLI did not contact isolated peer"
                );
                std::thread::sleep(Duration::from_millis(5));
            };
            stream.set_nonblocking(false).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut request = vec![0; 8192];
            let len = stream.read(&mut request).unwrap();
            request.truncate(len);
            std::thread::sleep(delay);
            let _ = write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len());
            requests.push(String::from_utf8(request).unwrap());
        }
        requests.join("\n")
    });
    (url, handle)
}

#[test]
fn diagnostic_reports_api_success_and_only_the_requested_tcp_check() {
    let status = serde_json::json!({"device_id":"00000000-0000-0000-0000-000000000001","adapter_state":"active","networks":[]});
    let sessions = serde_json::json!({"schema_version":1,"generated_at_unix_ms":0,"transport_revision":0,"sessions":[]});
    let (url, server) = peer_sequence(
        vec![status.to_string(), sessions.to_string()],
        Duration::ZERO,
    );
    let target = TcpListener::bind("127.0.0.1:0").unwrap();
    let target_address = target.local_addr().unwrap().to_string();
    let output = cli(&[
        "--api-url",
        &url,
        "diagnose",
        "--tcp",
        &target_address,
        "--json",
    ]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["ok"], true);
    assert_eq!(value["checks"][2]["check"], "tcp_connect");
    assert_eq!(value["checks"][2]["target"], target_address);
    assert_eq!(value["checks"][2]["ok"], true);
    let requests = server.join().unwrap();
    assert!(requests.contains("GET /v1/status HTTP/1.1"));
    assert!(requests.contains("GET /v1/sessions HTTP/1.1"));
}

#[test]
fn standalone_token_is_written_to_restricted_file_and_never_stdout() {
    let secret = "fixture-enrollment-secret";
    let (url, server) = peer(
        serde_json::json!({"token":secret,"expires_at_unix_seconds":1000,"invite_link":null})
            .to_string(),
        Duration::ZERO,
    );
    let base = url.strip_suffix("/v1").unwrap();
    let path = std::env::temp_dir().join(format!("meshlake-cli-token-{}", uuid::Uuid::new_v4()));
    let output = cli(&[
        "controller",
        "token",
        "--controller",
        base,
        "--network",
        "00000000-0000-0000-0000-000000000001",
        "--admin-token",
        "fixture-admin",
        "--token-file",
        path.to_str().unwrap(),
        "--json",
    ]);
    let contents = std::fs::read_to_string(&path);
    let _ = std::fs::remove_file(&path);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(contents.unwrap(), secret);
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["ok"], true);
    assert!(!String::from_utf8_lossy(&output.stdout).contains(secret));
    assert!(!String::from_utf8_lossy(&output.stderr).contains(secret));
    assert!(server.join().unwrap().starts_with(
        "POST /v1/networks/00000000-0000-0000-0000-000000000001/enrollment-tokens HTTP/1.1"
    ));
}

#[test]
fn json_network_list_removes_traffic_keys_and_uses_selected_api() {
    let body = serde_json::json!([{
        "network":{"id":"00000000-0000-0000-0000-000000000001","name":"test","ipv4_prefix":"10.2.0.0/24","ipv6_prefix":null,"relay_policy":"Preferred"},
        "assigned_addresses":["10.2.0.2"],"network_key":[90,91,92]
    }]);
    let (url, server) = peer(body.to_string(), Duration::ZERO);
    let output = cli(&["--api-url", &url, "network", "list", "--json"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value[0]["network"]["name"], "test");
    assert!(value[0].get("network_key").is_none());
    assert!(server
        .join()
        .unwrap()
        .starts_with("GET /v1/networks HTTP/1.1"));
}

#[test]
fn rejects_non_loopback_daemon_before_sending_requests() {
    let output = cli(&["status", "--api-url", "http://192.0.2.1:51821/v1", "--json"]);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let value: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(value["ok"], false);
    assert!(value["error"].as_str().unwrap().contains("loopback"));
}

#[test]
fn bounded_http_timeout_is_a_structured_failure() {
    let (url, server) = peer("[]".into(), Duration::from_secs(2));
    let output = cli(&[
        "--api-url",
        &url,
        "--timeout-seconds",
        "1",
        "network",
        "list",
        "--json",
    ]);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let value: serde_json::Value = serde_json::from_slice(&output.stderr).unwrap();
    assert_eq!(value["ok"], false);
    server.join().unwrap();
}

#[test]
fn global_help_exposes_management_and_native_tools() {
    let output = cli(&["--help"]);
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    for name in [
        "diagnose",
        "state",
        "autostart",
        "service",
        "--json",
        "--api-url",
        "--timeout-seconds",
    ] {
        assert!(text.contains(name), "missing {name}");
    }
}
