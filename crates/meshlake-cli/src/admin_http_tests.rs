use super::*;
use std::io::{Read, Write};

#[test]
fn command_tree_has_no_conflicting_argument_definitions() {
    use clap::CommandFactory;
    Cli::command().debug_assert();
}

#[test]
fn editable_policy_preserves_routes_dns_and_both_exit_families() {
    let certificate = serde_json::json!({
        "claims":{"network_id":Uuid::from_u128(1),"device_id":Uuid::from_u128(2),
            "device_public_key":[9],"assigned_addresses":["10.2.0.2"],"allowed_routes":["10.2.0.0/16"],
            "issued_at_unix_seconds":10,"expires_at_unix_seconds":1000},
        "controller_public_key":[7],"signature":[8]
    });
    let manifest = serde_json::json!({"version":2,"network_id":Uuid::from_u128(1),"policy_epoch":3,
        "routes":[{"prefix":"10.2.0.0/16","gateway_certificate":certificate}],
        "exit_nodes":[{"gateway_certificate":certificate,"supports_ipv4":true,"supports_ipv6":true}],
        "dns":{"servers":["10.2.0.1"],"search_domains":["mesh.test"]},
        "issued_at_unix_seconds":10,"expires_at_unix_seconds":1000,"controller_public_key":[7],"signature":[8]});
    let editable = controller_admin::editable_policy(manifest.clone()).unwrap();
    assert_eq!(editable["dns"], manifest["dns"]);
    assert_eq!(
        editable["routes"][0],
        serde_json::json!({"prefix":"10.2.0.0/16","gateway_device_id":Uuid::from_u128(2)})
    );
    assert_eq!(
        editable["exit_nodes"][0],
        serde_json::json!({"gateway_device_id":Uuid::from_u128(2),"supports_ipv4":true,"supports_ipv6":true})
    );
    assert!(editable.get("signature").is_none());
    assert!(controller_admin::editable_policy(serde_json::json!({"routes":[]})).is_err());
}

fn peer(status: &'static str, body: &'static str) -> (String, std::thread::JoinHandle<String>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let task = std::thread::spawn(move || {
        let until = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let mut stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(std::time::Instant::now() < until, "no CLI request arrived");
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
                Err(error) => panic!("{error}"),
            }
        };
        stream.set_nonblocking(false).unwrap();
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let mut bytes = Vec::new();
        loop {
            let mut chunk = [0; 2048];
            let size = stream.read(&mut chunk).unwrap();
            assert!(size > 0);
            bytes.extend_from_slice(&chunk[..size]);
            if let Some(end) = bytes.windows(4).position(|v| v == b"\r\n\r\n") {
                let header = String::from_utf8_lossy(&bytes[..end]).to_ascii_lowercase();
                let len: usize = header
                    .lines()
                    .find_map(|v| v.strip_prefix("content-length: "))
                    .unwrap_or("0")
                    .parse()
                    .unwrap();
                if bytes.len() >= end + 4 + len {
                    break;
                }
            }
        }
        write!(stream, "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
        String::from_utf8(bytes).unwrap()
    });
    (base, task)
}

async fn invoke_member(base: &str, operation: &str, extra: &[&str]) -> Result<()> {
    let mut args = vec![
        "meshlake",
        "controller",
        "member",
        operation,
        "--controller",
        base,
        "--network",
        "00000000-0000-0000-0000-000000000001",
        "--admin-token",
        "test-only-token",
    ];
    args.extend_from_slice(extra);
    let cli = Cli::try_parse_from(args)?;
    let Command::Controller {
        command: ControllerCommand::Member { command },
    } = cli.command
    else {
        panic!()
    };
    controller_admin::member(&Client::new(), false, command).await
}

#[tokio::test]
async fn member_http_methods_auth_and_route_replacement() {
    for (operation, method, extra, suffix) in [
        ("list", "GET", vec![], ""),
        (
            "remove",
            "DELETE",
            vec!["--device", "00000000-0000-0000-0000-000000000002"],
            "/00000000-0000-0000-0000-000000000002",
        ),
        (
            "routes",
            "POST",
            vec![
                "--device",
                "00000000-0000-0000-0000-000000000002",
                "--route",
                "10.2.0.0/16",
                "--route",
                "fd02::/64",
            ],
            "/00000000-0000-0000-0000-000000000002/allowed-routes",
        ),
        (
            "routes",
            "POST",
            vec![
                "--device",
                "00000000-0000-0000-0000-000000000002",
                "--clear",
            ],
            "/00000000-0000-0000-0000-000000000002/allowed-routes",
        ),
    ] {
        let (base, server) = peer("200 OK", "{}");
        invoke_member(&base, operation, &extra).await.unwrap();
        let request = server.join().unwrap();
        assert!(request.starts_with(&format!(
            "{method} /v1/networks/00000000-0000-0000-0000-000000000001/members{suffix} HTTP/1.1"
        )));
        assert!(request.contains("x-meshlake-admin-token: test-only-token"));
        if method == "POST" {
            let body: serde_json::Value =
                serde_json::from_str(request.split_once("\r\n\r\n").unwrap().1).unwrap();
            let expected = if extra.contains(&"--clear") {
                serde_json::json!([])
            } else {
                serde_json::json!(["10.2.0.0/16", "fd02::/64"])
            };
            assert_eq!(body["allowed_routes"], expected);
        }
    }
}

#[tokio::test]
async fn failed_member_request_does_not_reflect_secret() {
    let (base, server) = peer("403 Forbidden", "test-only-token");
    let error = invoke_member(&base, "list", &[]).await.unwrap_err();
    server.join().unwrap();
    assert!(error.to_string().contains("403"));
    assert!(!error.to_string().contains("test-only-token"));
}

#[tokio::test]
async fn policy_file_posts_complete_body_without_losing_dns_or_exits() {
    let (base, server) = peer("200 OK", "{}");
    let body = serde_json::json!({
        "routes": [{"prefix":"10.2.0.0/16", "gateway_device_id":Uuid::from_u128(2)}],
        "exit_nodes": [{"gateway_device_id":Uuid::from_u128(3), "supports_ipv4":true, "supports_ipv6":false}],
        "dns": {"servers":["10.2.0.1"], "search_domains":["mesh.test"]}
    });
    let path = std::env::temp_dir().join(format!("meshlake-cli-policy-{}.json", Uuid::new_v4()));
    std::fs::write(&path, serde_json::to_vec(&body).unwrap()).unwrap();
    let cli = Cli::try_parse_from([
        "meshlake",
        "controller",
        "policy",
        "set",
        "--controller",
        &base,
        "--network",
        "00000000-0000-0000-0000-000000000001",
        "--admin-token",
        "test-only-token",
        "--file",
        path.to_str().unwrap(),
    ])
    .unwrap();
    let Command::Controller {
        command: ControllerCommand::Policy { command },
    } = cli.command
    else {
        panic!()
    };
    let result = controller_admin::policy(&Client::new(), false, command).await;
    std::fs::remove_file(path).unwrap();
    result.unwrap();
    let request = server.join().unwrap();
    assert!(request
        .starts_with("POST /v1/networks/00000000-0000-0000-0000-000000000001/policy HTTP/1.1"));
    assert!(request.contains("x-meshlake-admin-token: test-only-token"));
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(request.split_once("\r\n\r\n").unwrap().1)
            .unwrap(),
        body
    );
}

#[tokio::test]
async fn health_handles_plain_text_response() {
    let (base, server) = peer("200 OK", "ok");
    controller_admin::read(&Client::new(), &base, "/health")
        .await
        .unwrap();
    assert!(server.join().unwrap().starts_with("GET /health HTTP/1.1"));
}
