//! Explicit acceptance uses only generated, isolated state and never starts a listener.
use super::*;
use meshlake_core::{write_protected_state_file, StateFileLock, AGENT_STATE_PROTECTION_PURPOSE};
use std::sync::{atomic::AtomicBool, Arc};

struct Directory(PathBuf);
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct OwnedChild(std::process::Child);
impl Drop for OwnedChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
#[ignore = "explicit loopback HTTPS acceptance; requires MESHLAKE_GUI_NATIVE_DIR"]
fn private_ca_https_accepts_only_the_configured_controller_certificate() {
    let binaries = PathBuf::from(
        std::env::var_os("MESHLAKE_GUI_NATIVE_DIR").expect("set reviewed native build directory"),
    );
    assert!(binaries.is_absolute());
    let directory =
        Directory(std::env::temp_dir().join(format!("MeshLake GUI HTTPS {}", Uuid::new_v4())));
    fs::create_dir(&directory.0).unwrap();
    let generated =
        rcgen::generate_simple_self_signed(vec!["localhost".into(), "127.0.0.1".into()]).unwrap();
    let ca = generated.cert.pem();
    let cert_path = directory.0.join("server.pem");
    let key_path = directory.0.join("server-key.pem");
    meshlake_core::create_restricted_secret_file(&cert_path, ca.as_bytes()).unwrap();
    meshlake_core::create_restricted_secret_file(
        &key_path,
        generated.signing_key.serialize_pem().as_bytes(),
    )
    .unwrap();
    let state = directory.0.join("controller.json");
    let admin_file = directory.0.join("initial-admin.secret");
    let log_path = directory.0.join("controller.log");
    meshlake_core::create_restricted_secret_file(&log_path, b"").unwrap();
    let log = fs::OpenOptions::new().append(true).open(&log_path).unwrap();
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let mut command = Command::new(binaries.join("meshlake-controller.exe"));
    command.args([
        "--bind",
        &port.to_string(),
        "--tls-certificate",
        cert_path.to_str().unwrap(),
        "--tls-private-key",
        key_path.to_str().unwrap(),
        "--state-file",
        state.to_str().unwrap(),
        "--initial-admin-token-file",
        admin_file.to_str().unwrap(),
    ]);
    command
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::from(log.try_clone().unwrap()))
        .stderr(std::process::Stdio::from(log));
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000);
    }
    let mut child = OwnedChild(command.spawn().unwrap());
    let endpoint = format!("https://{port}/health");
    let trusted = configured_http_client(Some(&ca), Duration::from_millis(300), true).unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(8);
    loop {
        if let Ok(response) = trusted.get(&endpoint).send() {
            assert!(response.status().is_success());
            break;
        }
        assert!(
            child.0.try_wait().unwrap().is_none(),
            "isolated HTTPS controller exited before health check"
        );
        assert!(
            std::time::Instant::now() < deadline,
            "private CA HTTPS health check timed out"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    let wrong = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let wrong_client =
        configured_http_client(Some(&wrong.cert.pem()), Duration::from_secs(1), true).unwrap();
    assert!(
        wrong_client.get(&endpoint).send().is_err(),
        "untrusted private CA was accepted"
    );
    let default_client = configured_http_client(None, Duration::from_secs(1), true).unwrap();
    assert!(
        default_client.get(&endpoint).send().is_err(),
        "private self-signed certificate bypassed trust validation"
    );
    println!("isolated HTTPS: configured private CA accepted; wrong CA and default trust rejected; no network membership or host configuration changed");
}

fn invoke(
    binary: &std::path::Path,
    state: &std::path::Path,
    operation: &str,
    backup: &std::path::Path,
    password: &str,
    force: bool,
) -> (bool, String) {
    let mut args = vec![
        "--state-file".into(),
        state.to_string_lossy().into_owned(),
        "state".into(),
        operation.into(),
        backup.to_string_lossy().into_owned(),
        "--password-stdin".into(),
    ];
    if force {
        args.push("--force".into());
    }
    let result = maintenance::execute_process(
        binary,
        &args,
        format!("{password}\n").into_bytes(),
        Arc::new(AtomicBool::new(false)),
        Duration::from_secs(30),
    )
    .unwrap();
    assert!(
        !result.1.contains(password),
        "native output reflected the test password"
    );
    result
}

#[test]
#[ignore = "explicit native acceptance; requires MESHLAKE_GUI_NATIVE_DIR with freshly built sibling services"]
fn isolated_agent_and_controller_backup_restore_roundtrip() {
    let binaries = PathBuf::from(
        std::env::var_os("MESHLAKE_GUI_NATIVE_DIR")
            .expect("set MESHLAKE_GUI_NATIVE_DIR to the reviewed local build directory"),
    );
    assert!(binaries.is_absolute());
    let directory =
        Directory(std::env::temp_dir().join(format!("MeshLake GUI native {}", Uuid::new_v4())));
    fs::create_dir(&directory.0).unwrap();
    let fixtures = [
        (
            "meshlaked.exe",
            AGENT_STATE_PROTECTION_PURPOSE,
            json!({"schema_version":4,"device_id":Uuid::from_u128(11),"identity_secret_key":vec![7u8;32],
                "networks":[],"relay_endpoint":null,"relay_endpoints":[],"upnp_enabled":false,
                "stun_servers":[],"root_servers":[],"authorizations":{},"planet":null,"exit_gateways":[]}),
        ),
        (
            "meshlake-controller.exe",
            CONTROLLER_STATE_PROTECTION_PURPOSE,
            json!({"schema_version":2,"signing_key":vec![9u8;32],"admin_token":"fixture-admin-only",
                "networks":{},"enrollment_tokens":{}}),
        ),
    ];
    for (name, purpose, fixture) in fixtures {
        let binary = binaries.join(name);
        assert!(binary.is_file(), "missing native acceptance binary {name}");
        let source = directory.0.join(format!("{name} source.json"));
        let restored = directory.0.join(format!("{name} restored.json"));
        let backup = directory.0.join(format!("{name} encrypted.mlb"));
        {
            let _lock = StateFileLock::acquire(&source).unwrap();
            write_protected_state_file(&source, &fixture, purpose).unwrap();
        }
        let password = "fixture-password-for-native-roundtrip";
        let (ok, output) = invoke(&binary, &source, "backup", &backup, password, false);
        assert!(ok, "{name} backup failed: {output}");
        let encrypted = fs::read(&backup).unwrap();
        assert!(!String::from_utf8_lossy(&encrypted).contains("fixture-admin-only"));
        assert!(!invoke(&binary, &source, "backup", &backup, password, false).0);
        assert_eq!(fs::read(&backup).unwrap(), encrypted);
        assert!(
            !invoke(
                &binary,
                &restored,
                "restore",
                &backup,
                "incorrect-test-password",
                false
            )
            .0
        );
        assert!(!restored.exists(), "wrong password wrote state");
        let (ok, output) = invoke(&binary, &restored, "restore", &backup, password, false);
        assert!(ok, "{name} restore failed: {output}");
        let bytes = fs::read(&restored).unwrap();
        let decoded = decode_protected_state::<serde_json::Value>(&bytes, purpose).unwrap();
        assert_eq!(decoded.value, fixture, "native roundtrip changed state");
        assert!(!invoke(&binary, &restored, "restore", &backup, password, false).0);
        assert_eq!(fs::read(&restored).unwrap(), bytes);
        {
            let _lock = StateFileLock::acquire(&restored).unwrap();
            assert!(!invoke(&binary, &restored, "restore", &backup, password, true).0);
            assert_eq!(
                fs::read(&restored).unwrap(),
                bytes,
                "locked restore changed state"
            );
        }
        let (ok, output) = invoke(&binary, &restored, "restore", &backup, password, true);
        assert!(ok, "{name} explicit replacement failed: {output}");
        assert_eq!(
            decode_protected_state::<serde_json::Value>(&fs::read(&restored).unwrap(), purpose)
                .unwrap()
                .value,
            fixture
        );
        println!("{name}: encrypted backup, wrong password, roundtrip, no-overwrite, lock and explicit replacement passed");
    }
}
