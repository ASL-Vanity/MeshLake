//! Explicitly run on authorized disposable lab guests only. Uses a unique
//! private directory and an owned loopback controller; never restarts the live agent.
use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};
use uuid::Uuid;

struct Lab {
    root: PathBuf,
    cli: PathBuf,
    cases: Vec<Value>,
}
impl Lab {
    fn record(&mut self, name: &str, passed: bool, detail: &str) -> Result<()> {
        self.cases
            .push(json!({"case":name,"passed":passed,"detail":detail}));
        fs::write(
            self.root.join("result.json"),
            serde_json::to_vec_pretty(&json!({"schema_version":1,"cases":self.cases}))?,
        )?;
        if !passed {
            bail!("case failed: {name}: {detail}");
        }
        Ok(())
    }
    fn cli(
        &mut self,
        name: &str,
        args: &[String],
        input: Option<&str>,
        success: bool,
    ) -> Result<String> {
        let mut child = Command::new(&self.cli)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let mut stdout = child.stdout.take().context("no stdout pipe")?;
        let mut stderr = child.stderr.take().context("no stderr pipe")?;
        let out = thread::spawn(move || {
            let mut s = String::new();
            stdout.read_to_string(&mut s).map(|_| s)
        });
        let err = thread::spawn(move || {
            let mut s = String::new();
            stderr.read_to_string(&mut s).map(|_| s)
        });
        if let Some(value) = input {
            child
                .stdin
                .as_mut()
                .context("no stdin pipe")?
                .write_all(value.as_bytes())?;
        }
        drop(child.stdin.take());
        let until = Instant::now() + Duration::from_secs(45);
        let status = loop {
            if let Some(status) = child.try_wait()? {
                break status;
            }
            if Instant::now() > until {
                let _ = child.kill();
                let _ = child.wait();
                bail!("CLI timeout: {name}");
            }
            thread::sleep(Duration::from_millis(25));
        };
        let stdout = out
            .join()
            .map_err(|_| anyhow::anyhow!("stdout worker failed"))??;
        let stderr = err
            .join()
            .map_err(|_| anyhow::anyhow!("stderr worker failed"))??;
        if status.success() != success {
            // Native command diagnostics may contain private fixture paths; retain
            // only inside the private guest directory, never include in the receipt.
            fs::write(self.root.join("failure.stderr.log"), &stderr)?;
        }
        self.record(
            name,
            status.success() == success,
            &format!("exit_code={}", status.code().unwrap_or(-1)),
        )?;
        Ok(stdout)
    }
    fn query(&mut self, name: &str, args: Vec<String>) -> Result<Value> {
        let mut args = args;
        args.push("--json".into());
        let text = self.cli(name, &args, None, true)?;
        serde_json::from_str(&text).with_context(|| format!("invalid JSON: {name}"))
    }
}
fn args(values: &[&str]) -> Vec<String> {
    values.iter().map(|v| (*v).into()).collect()
}
fn path(value: &Path) -> String {
    value.to_string_lossy().into_owned()
}

struct Controller {
    child: Child,
}
impl Controller {
    fn stop(&mut self) {
        if self.child.try_wait().ok().flatten().is_some() {
            return;
        }
        let pid = self.child.id().to_string();
        #[cfg(windows)]
        {
            let _ = Command::new("taskkill.exe")
                .args(["/PID", &pid, "/T", "/F"])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
        #[cfg(unix)]
        {
            let _ = Command::new("/bin/kill")
                .args(["-TERM", "--", &format!("-{pid}")])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
        let until = Instant::now() + Duration::from_secs(5);
        while self.child.try_wait().ok().flatten().is_none() && Instant::now() < until {
            thread::sleep(Duration::from_millis(50));
        }
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}
impl Drop for Controller {
    fn drop(&mut self) {
        self.stop();
    }
}

fn start_controller(lab: &Lab, port: u16, restored: bool) -> Result<Controller> {
    let mut command = Command::new(&lab.cli);
    command.args([
        "service",
        "controller",
        "--",
        "--bind",
        &format!("127.0.0.1:{port}"),
        "--state-file",
        &path(&lab.root.join("controller.json")),
        "--planet-controller-url",
        &format!("http://127.0.0.1:{port}"),
        "--allow-insecure-public-http",
        "--planet-relay-endpoint",
        "127.0.0.1:53920",
    ]);
    if !restored {
        command.args([
            "--initial-admin-token-file",
            &path(&lab.root.join("admin.secret")),
        ]);
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000);
    }
    let child = command
        .stdin(Stdio::null())
        .stdout(fs::File::create(lab.root.join("controller.stdout.log"))?)
        .stderr(fs::File::create(lab.root.join("controller.stderr.log"))?)
        .spawn()?;
    Ok(Controller { child })
}

async fn run(lab: &mut Lab, port: u16) -> Result<()> {
    let baseline = lab.query("agent_status", args(&["status"]))?;
    let before = lab.query("agent_network_list", args(&["network", "list"]))?;
    lab.query("agent_sessions", args(&["sessions"]))?;
    lab.query("diagnose", args(&["diagnose"]))?;
    lab.cli("version", &args(&["--version"]), None, true)?;
    for role in ["agent", "controller", "root", "relay"] {
        lab.cli(
            &format!("native_help_{role}"),
            &args(&["service", role, "--", "--help"]),
            None,
            true,
        )?;
    }
    lab.cli(
        "native_invalid_argument",
        &args(&["service", "relay", "--", "--not-a-real-option"]),
        None,
        false,
    )?;
    lab.query("autostart_status", args(&["autostart", "status"]))?;
    let fixture = lab.root.join("agent fixture.json");
    let backup = lab.root.join("agent backup.mlb");
    let restored = lab.root.join("agent restored.json");
    let fixture_id = Uuid::new_v4();
    fs::write(
        &fixture,
        serde_json::to_vec(
            &json!({"schema_version":4,"device_id":fixture_id,"identity_secret_key":vec![42u8;32],"networks":[]}),
        )?,
    )?;
    let password = format!("{}{}\n", Uuid::new_v4(), Uuid::new_v4());
    // This password protects only throwaway fixtures. It is never written to disk,
    // placed in argv, echoed or included in the result JSON.
    lab.query(
        "agent_state_path",
        args(&["agent", "state-path", "--state-file", &path(&fixture)]),
    )?;
    lab.cli(
        "agent_backup",
        &args(&[
            "state",
            "--state-file",
            &path(&fixture),
            "backup",
            &path(&backup),
            "--password-stdin",
            "--json",
        ]),
        Some(&password),
        true,
    )?;
    let envelope: Value = serde_json::from_slice(&fs::read(&fixture)?)?;
    #[cfg(windows)]
    lab.record(
        "agent_dpapi_protection",
        envelope.get("protection").and_then(Value::as_str) == Some("windows-dpapi-local-machine"),
        "machine-bound envelope",
    )?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = envelope;
        lab.record(
            "agent_file_permissions",
            fs::metadata(&fixture)?.permissions().mode() & 0o777 == 0o600,
            "mode 0600",
        )?;
    }
    lab.cli(
        "agent_restore",
        &args(&[
            "state",
            "--state-file",
            &path(&restored),
            "restore",
            &path(&backup),
            "--password-stdin",
            "--json",
        ]),
        Some(&password),
        true,
    )?;
    let original = fs::read(&restored)?;
    lab.cli(
        "agent_wrong_password",
        &args(&[
            "state",
            "--state-file",
            &path(&restored),
            "restore",
            &path(&backup),
            "--password-stdin",
            "--force",
            "--json",
        ]),
        Some("wrong-fixture-password\n"),
        false,
    )?;
    lab.record(
        "wrong_password_preserves_state",
        fs::read(&restored)? == original,
        "unchanged bytes",
    )?;
    lab.cli(
        "agent_restore_no_overwrite",
        &args(&[
            "state",
            "--state-file",
            &path(&restored),
            "restore",
            &path(&backup),
            "--password-stdin",
            "--json",
        ]),
        Some(&password),
        false,
    )?;
    lab.cli(
        "agent_restore_force",
        &args(&[
            "state",
            "--state-file",
            &path(&restored),
            "restore",
            &path(&backup),
            "--password-stdin",
            "--force",
            "--json",
        ]),
        Some(&password),
        true,
    )?;
    lab.cli(
        "agent_repair_requires_yes",
        &args(&[
            "state",
            "--state-file",
            &path(&restored),
            "repair-invalid-networks",
        ]),
        None,
        false,
    )?;
    lab.cli(
        "agent_repair_valid_state",
        &args(&[
            "state",
            "--state-file",
            &path(&restored),
            "repair-invalid-networks",
            "--yes",
            "--json",
        ]),
        None,
        true,
    )?;
    let bad = lab.root.join("agent malformed fixture.json");
    fs::write(
        &bad,
        serde_json::to_vec(
            &json!({"schema_version":4,"device_id":fixture_id,"identity_secret_key":vec![42u8;32],"networks":[{
        "network":{"id":Uuid::new_v4(),"name":"malformed-fixture","ipv4_prefix":"100.99.241.0/24","ipv6_prefix":null,"relay_policy":"Disabled"},"assigned_addresses":[],"network_key":[]}]}),
        )?,
    )?;
    lab.cli(
        "agent_repair_malformed_network",
        &args(&[
            "state",
            "--state-file",
            &path(&bad),
            "repair-invalid-networks",
            "--yes",
            "--json",
        ]),
        None,
        true,
    )?;
    lab.cli(
        "agent_backup_after_repair",
        &args(&[
            "state",
            "--state-file",
            &path(&bad),
            "backup",
            &path(&lab.root.join("repaired.mlb")),
            "--password-stdin",
        ]),
        Some(&password),
        true,
    )?;
    // Only this owned, non-default loopback port is used for the controller.
    drop(
        std::net::TcpListener::bind(("127.0.0.1", port))
            .context("fixture controller port is already in use")?,
    );
    let mut controller = start_controller(lab, port, false)?;
    let base = format!("http://127.0.0.1:{port}");
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(2))
        .build()?;
    let until = Instant::now() + Duration::from_secs(15);
    loop {
        if client.get(format!("{base}/health")).send().await.is_ok() {
            break;
        }
        if controller.child.try_wait()?.is_some() || Instant::now() > until {
            bail!("fixture controller did not become ready");
        }
        thread::sleep(Duration::from_millis(100));
    }
    lab.query(
        "controller_health",
        args(&["controller", "health", "--controller", &base]),
    )?;
    let public = lab.query(
        "controller_public_key",
        args(&["controller", "public-key", "--controller", &base]),
    )?;
    lab.query(
        "controller_planet",
        args(&["controller", "planet", "--controller", &base]),
    )?;
    let admin = path(&lab.root.join("admin.secret"));
    let network = lab.query(
        "controller_network_create",
        args(&[
            "controller",
            "network",
            "create",
            "--controller",
            &base,
            "--admin-token-file",
            &admin,
            "--name",
            "cli-lab-fixture",
            "--ipv4-prefix",
            "100.99.242.0/24",
            "--ipv6-prefix",
            "fd42:4d4c:242::/64",
            "--relay-policy",
            "disabled",
        ]),
    )?;
    let id = network["id"]
        .as_str()
        .context("created network has no ID")?
        .to_owned();
    lab.query(
        "controller_network_list",
        args(&["controller", "network", "list", "--controller", &base]),
    )?;
    lab.query(
        "controller_authorization",
        args(&[
            "controller",
            "authorization",
            "--controller",
            &base,
            "--network",
            &id,
        ]),
    )?;
    let policy = lab.query(
        "controller_policy_editable",
        args(&[
            "controller",
            "policy",
            "get",
            "--controller",
            &base,
            "--network",
            &id,
            "--editable",
        ]),
    )?;
    let policy_path = lab.root.join("policy.json");
    fs::write(&policy_path, serde_json::to_vec(&policy)?)?;
    lab.query(
        "controller_policy_set",
        args(&[
            "controller",
            "policy",
            "set",
            "--controller",
            &base,
            "--network",
            &id,
            "--file",
            &path(&policy_path),
            "--admin-token-file",
            &admin,
        ]),
    )?;
    let token_path = path(&lab.root.join("enrollment.secret"));
    lab.query(
        "controller_token",
        args(&[
            "controller",
            "token",
            "--controller",
            &base,
            "--network",
            &id,
            "--admin-token-file",
            &admin,
            "--token-file",
            &token_path,
        ]),
    )?;
    let link_path = path(&lab.root.join("invitation.secret"));
    lab.query(
        "controller_invite",
        args(&[
            "controller",
            "invite",
            "--controller",
            &base,
            "--network",
            &id,
            "--admin-token-file",
            &admin,
            "--invite-link-file",
            &link_path,
        ]),
    )?;
    lab.query(
        "controller_members_empty",
        args(&[
            "controller",
            "member",
            "list",
            "--controller",
            &base,
            "--network",
            &id,
            "--admin-token-file",
            &admin,
        ]),
    )?;
    let member_id = Uuid::new_v4().to_string();
    let enrollment_secret = fs::read_to_string(&token_path)?;
    let enrollment = client
        .post(format!("{base}/v1/enroll"))
        .json(&json!({"network_id":id,"device_id":member_id,
        "device_public_key":baseline["identity_public_key"],"token":enrollment_secret.trim()}))
        .send()
        .await?;
    lab.record(
        "fixture_member_enrollment",
        enrollment.status().is_success(),
        "owned controller fixture only; live agent not enrolled",
    )?;
    drop(enrollment);
    let members = lab.query(
        "controller_members_populated",
        args(&[
            "controller",
            "member",
            "list",
            "--controller",
            &base,
            "--network",
            &id,
            "--admin-token-file",
            &admin,
        ]),
    )?;
    lab.record(
        "member_list_contains_fixture",
        members.as_array().is_some_and(|m| m.len() == 1),
        "one fixture member",
    )?;
    lab.query(
        "member_allow_routes",
        args(&[
            "controller",
            "member",
            "routes",
            "--controller",
            &base,
            "--network",
            &id,
            "--device",
            &member_id,
            "--admin-token-file",
            &admin,
            "--route",
            "100.99.243.0/24",
        ]),
    )?;
    let configured = json!({"routes":[{"prefix":"100.99.243.0/24","gateway_device_id":member_id}],"exit_nodes":[],
        "dns":{"servers":["100.99.242.2"],"search_domains":["cli-fixture.invalid"]}});
    fs::write(&policy_path, serde_json::to_vec(&configured)?)?;
    lab.query(
        "policy_routes_and_dns",
        args(&[
            "controller",
            "policy",
            "set",
            "--controller",
            &base,
            "--network",
            &id,
            "--file",
            &path(&policy_path),
            "--admin-token-file",
            &admin,
        ]),
    )?;
    lab.cli(
        "controller_exit_grant",
        &args(&[
            "controller",
            "exit",
            "set",
            "--controller",
            &base,
            "--network",
            &id,
            "--device",
            &member_id,
            "--ipv4",
            "--admin-token-file",
            &admin,
            "--json",
        ]),
        None,
        true,
    )?;
    let retained = lab.query(
        "policy_after_exit_grant",
        args(&[
            "controller",
            "policy",
            "get",
            "--controller",
            &base,
            "--network",
            &id,
            "--editable",
        ]),
    )?;
    lab.record(
        "exit_grant_preserves_routes_dns",
        retained["routes"] == configured["routes"]
            && retained["dns"] == configured["dns"]
            && retained["exit_nodes"]
                .as_array()
                .is_some_and(|n| n.len() == 1),
        "unrelated policy sections preserved",
    )?;
    lab.cli(
        "controller_exit_clear",
        &args(&[
            "controller",
            "exit",
            "clear",
            "--controller",
            &base,
            "--network",
            &id,
            "--device",
            &member_id,
            "--admin-token-file",
            &admin,
            "--json",
        ]),
        None,
        true,
    )?;
    fs::write(&policy_path, serde_json::to_vec(&policy)?)?;
    lab.query(
        "policy_clear",
        args(&[
            "controller",
            "policy",
            "set",
            "--controller",
            &base,
            "--network",
            &id,
            "--file",
            &path(&policy_path),
            "--admin-token-file",
            &admin,
        ]),
    )?;
    lab.query(
        "member_clear_routes",
        args(&[
            "controller",
            "member",
            "routes",
            "--controller",
            &base,
            "--network",
            &id,
            "--device",
            &member_id,
            "--admin-token-file",
            &admin,
            "--clear",
        ]),
    )?;
    lab.cli(
        "controller_wrong_admin",
        &args(&[
            "controller",
            "member",
            "list",
            "--controller",
            &base,
            "--network",
            &id,
            "--admin-token-stdin",
            "--json",
        ]),
        Some("invalid-fixture-token\n"),
        false,
    )?;
    let controller_backup = path(&lab.root.join("controller backup.mlb"));
    let state = path(&lab.root.join("controller.json"));
    lab.cli(
        "controller_backup_locked",
        &args(&[
            "controller",
            "state",
            "--state-file",
            &state,
            "backup",
            &controller_backup,
            "--password-stdin",
            "--json",
        ]),
        Some(&password),
        false,
    )?;
    controller.stop();
    lab.cli(
        "controller_backup",
        &args(&[
            "controller",
            "state",
            "--state-file",
            &state,
            "backup",
            &controller_backup,
            "--password-stdin",
            "--json",
        ]),
        Some(&password),
        true,
    )?;
    lab.cli(
        "controller_restore_force",
        &args(&[
            "controller",
            "state",
            "--state-file",
            &state,
            "restore",
            &controller_backup,
            "--password-stdin",
            "--force",
            "--json",
        ]),
        Some(&password),
        true,
    )?;
    controller = start_controller(lab, port, true)?;
    let until = Instant::now() + Duration::from_secs(15);
    while client.get(format!("{base}/health")).send().await.is_err() {
        if Instant::now() > until {
            bail!("restored controller did not start");
        }
        thread::sleep(Duration::from_millis(100));
    }
    let after = lab.query(
        "controller_restored_identity",
        args(&["controller", "public-key", "--controller", &base]),
    )?;
    lab.record(
        "controller_identity_preserved",
        after == public,
        "same public identity",
    )?;
    lab.cli(
        "controller_member_remove",
        &args(&[
            "controller",
            "member",
            "remove",
            "--controller",
            &base,
            "--network",
            &id,
            "--device",
            &member_id,
            "--admin-token-file",
            &admin,
            "--json",
        ]),
        None,
        true,
    )?;
    lab.cli(
        "controller_network_delete",
        &args(&[
            "controller",
            "network",
            "delete",
            "--controller",
            &base,
            "--network",
            &id,
            "--admin-token-file",
            &admin,
            "--json",
        ]),
        None,
        true,
    )?;
    let final_networks = lab.query(
        "controller_networks_after_delete",
        args(&["controller", "network", "list", "--controller", &base]),
    )?;
    lab.record(
        "controller_cleanup",
        final_networks.as_array().is_some_and(|v| v.is_empty()),
        "fixture networks empty",
    )?;
    controller.stop();
    let after = lab.query("agent_network_list_after", args(&["network", "list"]))?;
    let status = lab.query("agent_status_after", args(&["status"]))?;
    lab.record(
        "live_agent_unchanged",
        after == before
            && status["device_id"] == baseline["device_id"]
            && status["adapter_state"] == baseline["adapter_state"],
        "network records, identity and adapter state preserved",
    )?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let root = std::env::current_exe()?
        .parent()
        .context("no executable directory")?
        .to_owned();
    anyhow::ensure!(
        root.file_name()
            .and_then(|s| s.to_str())
            .is_some_and(|s| s.starts_with("cli-accept-")),
        "run only from a private cli-accept-* directory"
    );
    let cli = root.join(format!("meshlake-cli{}", std::env::consts::EXE_SUFFIX));
    let mut lab = Lab {
        root,
        cli,
        cases: Vec::new(),
    };
    let result = run(&mut lab, 53922).await;
    let passed = result.is_ok();
    fs::write(
        lab.root.join("result.json"),
        serde_json::to_vec_pretty(
            &json!({"schema_version":1,"passed":passed,"checks":lab.cases.len(),"cases":lab.cases,
        "scope":"guest CLI, owned controller and throwaway state fixtures; existing agent read-only", "failure":result.as_ref().err().map(|e|e.to_string())}),
        )?,
    )?;
    println!("{}", json!({"passed":passed,"checks":lab.cases.len()}));
    result
}
