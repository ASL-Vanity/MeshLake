use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use clap::{Parser, Subcommand, ValueEnum};
use meshlake_core::{
    AgentStatus, EnrollmentResponse, JoinedNetwork, RelayPolicy, UpsertNetworkRequest,
    VirtualNetwork,
};
use reqwest::{Client, StatusCode};
use url::Url;
use uuid::Uuid;

const LOCAL_API: &str = "http://127.0.0.1:51821/v1";

#[derive(Parser)]
#[command(name = "meshlake", about = "MeshLake headless management CLI")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Status,
    Agent {
        #[command(subcommand)]
        command: AgentCommand,
    },
    Adapter {
        #[command(subcommand)]
        command: AdapterCommand,
    },
    Relay {
        #[command(subcommand)]
        command: RelayCommand,
    },
    Planet {
        #[command(subcommand)]
        command: PlanetCommand,
    },
    /// Manage a self-hosted controller without opening the graphical client.
    Controller {
        #[command(subcommand)]
        command: ControllerCommand,
    },
    Network {
        #[command(subcommand)]
        command: NetworkCommand,
    },
}

#[derive(Subcommand)]
enum AgentCommand {
    /// Gracefully stop meshlaked, its virtual adapter session and transport worker.
    Stop,
}

#[derive(Subcommand)]
enum AdapterCommand {
    Start,
    Stop,
}

#[derive(Subcommand)]
enum RelayCommand {
    /// Configure the UDP relay used after the next meshlaked restart.
    Set {
        #[arg(long)]
        endpoint: String,
        /// Optional STUN server (`host:port`). Repeat this option for multiple servers.
        #[arg(long = "stun")]
        stun_servers: Vec<String>,
        /// Disable PCP, NAT-PMP and UPnP automatic UDP port mapping.
        #[arg(long)]
        disable_port_mapping: bool,
    },
}

#[derive(Subcommand)]
enum PlanetCommand {
    /// Download a signed Planet manifest and save its controller, relay and STUN settings.
    Set {
        #[arg(long)]
        manifest: String,
        /// Base64 Ed25519 controller public key obtained through a trusted channel.
        #[arg(long)]
        controller_public_key_base64: String,
    },
}

#[derive(Subcommand)]
enum ControllerCommand {
    /// Manage networks hosted by a self-hosted controller.
    Network {
        #[command(subcommand)]
        command: ControllerNetworkCommand,
    },
    /// Print the controller public key used to verify membership and Planet signatures.
    PublicKey {
        #[arg(long)]
        controller: String,
    },
    /// Create a one-time URL that is all a new device needs to join.
    Invite {
        #[arg(long)]
        controller: String,
        #[arg(long)]
        network: Uuid,
        #[arg(long)]
        admin_token: String,
        /// Invitation lifetime in seconds (60 through 86400).
        #[arg(long, default_value_t = 900)]
        expires_in_seconds: u64,
    },
}

#[derive(Subcommand)]
enum ControllerNetworkCommand {
    Create {
        #[arg(long)]
        controller: String,
        #[arg(long)]
        admin_token: String,
        #[arg(long)]
        name: String,
        #[arg(long)]
        ipv4_prefix: String,
        #[arg(long)]
        ipv6_prefix: Option<String>,
        #[arg(long, value_enum, default_value = "preferred")]
        relay_policy: RelayPolicyArg,
    },
    List {
        #[arg(long)]
        controller: String,
    },
    Delete {
        #[arg(long)]
        controller: String,
        #[arg(long)]
        admin_token: String,
        #[arg(long)]
        network: Uuid,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum RelayPolicyArg {
    Preferred,
    Required,
    Disabled,
}

impl From<RelayPolicyArg> for RelayPolicy {
    fn from(value: RelayPolicyArg) -> Self {
        match value {
            RelayPolicyArg::Preferred => Self::Preferred,
            RelayPolicyArg::Required => Self::Required,
            RelayPolicyArg::Disabled => Self::Disabled,
        }
    }
}

#[derive(Subcommand)]
enum NetworkCommand {
    List,
    /// Join from one invitation URL instead of manually entering controller,
    /// network ID, token and public key.
    JoinLink {
        #[arg(long)]
        link: String,
    },
    Join {
        /// Controller URL, for example https://controller.example.com.
        #[arg(long)]
        controller: String,
        #[arg(long)]
        network: Uuid,
        #[arg(long)]
        token: String,
        /// Base64 controller Ed25519 public key obtained from a trusted administrator.
        #[arg(long)]
        controller_public_key_base64: String,
    },
    Leave {
        #[arg(long)]
        network: Uuid,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let client = Client::new();
    match Cli::parse().command {
        Command::Status => {
            print_status(client.get(format!("{LOCAL_API}/status")).send().await?).await?
        }
        Command::Agent {
            command: AgentCommand::Stop,
        } => {
            ensure_success(client.post(format!("{LOCAL_API}/shutdown")).send().await?).await?;
            println!("MeshLake agent stopped.");
        }
        Command::Adapter {
            command: AdapterCommand::Start,
        } => {
            ensure_success(client.post(format!("{LOCAL_API}/adapter")).send().await?).await?;
            println!("MeshLake adapter is active.");
        }
        Command::Relay {
            command:
                RelayCommand::Set {
                    endpoint,
                    stun_servers,
                    disable_port_mapping,
                },
        } => {
            ensure_success(
                client
                    .post(format!("{LOCAL_API}/relay"))
                    .json(&serde_json::json!({
                        "endpoint": endpoint,
                        "stun_servers": stun_servers,
                        "enable_upnp": !disable_port_mapping,
                    }))
                    .send()
                    .await?,
            )
            .await?;
            println!("Relay endpoint saved. Restart meshlaked to connect: {endpoint}");
        }
        Command::Planet {
            command:
                PlanetCommand::Set {
                    manifest,
                    controller_public_key_base64,
                },
        } => {
            ensure_success(
                client
                    .post(format!("{LOCAL_API}/planet"))
                    .json(&serde_json::json!({
                        "manifest_url": manifest,
                        "controller_public_key_base64": controller_public_key_base64,
                    }))
                    .send()
                    .await?,
            )
            .await?;
            println!("Planet settings saved. Restart meshlaked to connect to the relay.");
        }
        Command::Controller {
            command:
                ControllerCommand::Network {
                    command:
                        ControllerNetworkCommand::Create {
                            controller,
                            admin_token,
                            name,
                            ipv4_prefix,
                            ipv6_prefix,
                            relay_policy,
                        },
                },
        } => {
            let controller_url = controller.trim_end_matches('/');
            let request = UpsertNetworkRequest {
                id: None,
                name,
                ipv4_prefix,
                ipv6_prefix,
                relay_policy: relay_policy.into(),
            };
            let network: VirtualNetwork = ensure_success(
                client
                    .post(format!("{controller_url}/v1/networks"))
                    .header("x-meshlake-admin-token", admin_token)
                    .json(&request)
                    .send()
                    .await?,
            )
            .await?
            .json()
            .await?;
            print_controller_network(&network);
        }
        Command::Controller {
            command:
                ControllerCommand::Network {
                    command: ControllerNetworkCommand::List { controller },
                },
        } => {
            let controller_url = controller.trim_end_matches('/');
            let networks: Vec<VirtualNetwork> = ensure_success(
                client
                    .get(format!("{controller_url}/v1/networks"))
                    .send()
                    .await?,
            )
            .await?
            .json()
            .await?;
            if networks.is_empty() {
                println!("No controller networks.");
            } else {
                for network in &networks {
                    print_controller_network(network);
                }
            }
        }
        Command::Controller {
            command:
                ControllerCommand::Network {
                    command:
                        ControllerNetworkCommand::Delete {
                            controller,
                            admin_token,
                            network,
                        },
                },
        } => {
            let controller_url = controller.trim_end_matches('/');
            ensure_success(
                client
                    .delete(format!("{controller_url}/v1/networks/{network}"))
                    .header("x-meshlake-admin-token", admin_token)
                    .send()
                    .await?,
            )
            .await?;
            println!("Controller network {network} deleted.");
        }
        Command::Controller {
            command: ControllerCommand::PublicKey { controller },
        } => {
            let controller_url = controller.trim_end_matches('/');
            let response: serde_json::Value = ensure_success(
                client
                    .get(format!("{controller_url}/v1/public-key"))
                    .send()
                    .await?,
            )
            .await?
            .json()
            .await?;
            let public_key = response
                .get("public_key")
                .and_then(|value| value.as_str())
                .context("controller returned no public key")?;
            println!("{public_key}");
        }
        Command::Controller {
            command:
                ControllerCommand::Invite {
                    controller,
                    network,
                    admin_token,
                    expires_in_seconds,
                },
        } => {
            let controller_url = controller.trim_end_matches('/');
            let response: serde_json::Value = ensure_success(
                client
                    .post(format!(
                        "{controller_url}/v1/networks/{network}/enrollment-tokens"
                    ))
                    .header("x-meshlake-admin-token", admin_token)
                    .json(&serde_json::json!({
                        "expires_in_seconds": expires_in_seconds,
                    }))
                    .send()
                    .await?,
            )
            .await?
            .json()
            .await?;
            let link = response
                .get("invite_link")
                .and_then(|value| value.as_str())
                .filter(|value| !value.is_empty())
                .context(
                    "this controller does not publish a Planet URL; start it with --planet-controller-url and --planet-relay-endpoint to enable one-link joins",
                )?;
            println!("{link}");
        }
        Command::Adapter {
            command: AdapterCommand::Stop,
        } => {
            ensure_success(client.delete(format!("{LOCAL_API}/adapter")).send().await?).await?;
            println!("MeshLake adapter session stopped.");
        }
        Command::Network {
            command: NetworkCommand::List,
        } => print_networks(client.get(format!("{LOCAL_API}/networks")).send().await?).await?,
        Command::Network {
            command: NetworkCommand::JoinLink { link },
        } => {
            let invitation = InviteLink::parse(&link)?;
            if let Some(planet) = invitation.planet.as_deref() {
                ensure_success(
                    client
                        .post(format!("{LOCAL_API}/planet"))
                        .json(&serde_json::json!({
                            "manifest_url": planet,
                            "controller_public_key_base64": invitation.controller_public_key_base64,
                        }))
                        .send()
                        .await?,
                )
                .await?;
            }
            join_network(
                &client,
                &invitation.controller,
                invitation.network,
                &invitation.token,
                &invitation.controller_public_key_base64,
            )
            .await?;
            println!("Network joined. If this was the first Planet setup, restart meshlaked to start its UDP discovery and relay worker.");
        }
        Command::Network {
            command:
                NetworkCommand::Join {
                    controller,
                    network,
                    token,
                    controller_public_key_base64,
                },
        } => {
            join_network(
                &client,
                &controller,
                network,
                &token,
                &controller_public_key_base64,
            )
            .await?;
        }
        Command::Network {
            command: NetworkCommand::Leave { network },
        } => {
            ensure_success(
                client
                    .delete(format!("{LOCAL_API}/networks/{network}"))
                    .send()
                    .await?,
            )
            .await?;
        }
    }
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
struct InviteLink {
    controller: String,
    network: Uuid,
    token: String,
    controller_public_key_base64: String,
    planet: Option<String>,
}

impl InviteLink {
    fn parse(value: &str) -> Result<Self> {
        let url = Url::parse(value.trim()).context("invitation link is not a valid URL")?;
        if url.scheme() != "meshlake" || url.host_str() != Some("join") {
            bail!("invitation link must start with meshlake://join?");
        }
        let parameter = |name: &str| {
            url.query_pairs()
                .find(|(key, _)| key == name)
                .map(|(_, value)| value.into_owned())
                .filter(|value| !value.is_empty())
                .with_context(|| format!("invitation link is missing {name}"))
        };
        let controller = parameter("controller")?;
        if !(controller.starts_with("https://") || controller.starts_with("http://")) {
            bail!("invitation controller must use https:// or http://");
        }
        let network = parameter("network_id")?
            .parse::<Uuid>()
            .context("invitation network_id is invalid")?;
        let controller_public_key_base64 = parameter("public_key")?;
        let decoded_key = STANDARD
            .decode(&controller_public_key_base64)
            .context("invitation public_key is not valid base64")?;
        if decoded_key.len() != 32 {
            bail!("invitation public_key must contain exactly 32 bytes");
        }
        let planet = url
            .query_pairs()
            .find(|(key, _)| key == "planet")
            .map(|(_, value)| value.into_owned())
            .filter(|value| value.starts_with("https://") || value.starts_with("http://"));
        Ok(Self {
            controller,
            network,
            token: parameter("token")?,
            controller_public_key_base64,
            planet,
        })
    }
}

async fn join_network(
    client: &Client,
    controller: &str,
    network: Uuid,
    token: &str,
    controller_public_key_base64: &str,
) -> Result<()> {
    let controller_public_key = STANDARD
        .decode(controller_public_key_base64)
        .context("controller public key is not valid base64")?;
    if controller_public_key.len() != 32 {
        bail!("controller public key must contain exactly 32 bytes");
    }
    let status: AgentStatus =
        ensure_success(client.get(format!("{LOCAL_API}/status")).send().await?)
            .await?
            .json()
            .await?;
    let controller_url = controller.trim_end_matches('/');
    let enrollment: EnrollmentResponse = ensure_success(
        client
            .post(format!("{controller_url}/v1/enroll"))
            .json(&serde_json::json!({
                "network_id": network,
                "device_id": status.device_id.0,
                "device_public_key": status.identity_public_key,
                "token": token,
            }))
            .send()
            .await?,
    )
    .await?
    .json()
    .await?;
    print_network(
        client
            .post(format!("{LOCAL_API}/networks/enroll"))
            .json(&serde_json::json!({
                "enrollment": enrollment,
                "controller_public_key": controller_public_key,
            }))
            .send()
            .await?,
    )
    .await
}

async fn ensure_success(response: reqwest::Response) -> Result<reqwest::Response> {
    if response.status().is_success() {
        return Ok(response);
    }
    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    if status == StatusCode::CONFLICT
        || status == StatusCode::NOT_FOUND
        || status == StatusCode::BAD_REQUEST
    {
        bail!("agent rejected request ({status}): {body}");
    }
    bail!("agent request failed ({status}): {body}")
}
async fn print_status(response: reqwest::Response) -> Result<()> {
    let status: AgentStatus = ensure_success(response)
        .await?
        .json()
        .await
        .context("invalid agent response")?;
    println!(
        "Device: {}\nAdapter: {}\nNetworks: {}\nTransport worker: {}",
        status.device_id.0,
        status.adapter_state,
        status.networks.len(),
        if status.transport.worker_running {
            "running"
        } else {
            "stopped"
        }
    );
    println!(
        "Roots: {}/{} responsive\nRelays: {}/{} healthy",
        status.transport.responsive_roots.len(),
        status.transport.configured_roots.len(),
        status.transport.healthy_relays.len(),
        status.transport.configured_relays.len()
    );
    for relay in &status.transport.configured_relays {
        println!(
            "  relay {}  {}",
            relay,
            if status.transport.healthy_relays.contains(relay) {
                "healthy"
            } else {
                "waiting"
            }
        );
    }
    for root in &status.transport.configured_roots {
        println!(
            "  root  {}  {}",
            root,
            if status.transport.responsive_roots.contains(root) {
                "responsive"
            } else {
                "waiting"
            }
        );
    }
    println!("Direct peer paths: {}", status.transport.peer_paths.len());
    for path in &status.transport.peer_paths {
        let rtt = path
            .smoothed_rtt_ms
            .map(|milliseconds| format!("{milliseconds} ms"))
            .unwrap_or_else(|| "measuring".to_owned());
        println!(
            "  peer {}  network {}  {}  RTT {}  failures {}",
            path.device_id.0, path.network_id.0, path.endpoint, rtt, path.consecutive_failures
        );
    }
    for network in status.networks {
        println!(
            "  {}  {}  IPv4 {}  IPv6 {}",
            network.network.id.0,
            network.network.name,
            network.network.ipv4_prefix,
            network.network.ipv6_prefix.as_deref().unwrap_or("-")
        );
    }
    Ok(())
}
async fn print_networks(response: reqwest::Response) -> Result<()> {
    for network in ensure_success(response)
        .await?
        .json::<Vec<JoinedNetwork>>()
        .await?
    {
        println!(
            "{}\t{}\tIPv4={}\tIPv6={}",
            network.network.id.0,
            network.network.name,
            network.network.ipv4_prefix,
            network.network.ipv6_prefix.as_deref().unwrap_or("-")
        );
    }
    Ok(())
}

fn print_controller_network(network: &VirtualNetwork) {
    println!(
        "{}\t{}\tIPv4={}\tIPv6={}\tRelay={:?}",
        network.id.0,
        network.name,
        network.ipv4_prefix,
        network.ipv6_prefix.as_deref().unwrap_or("-"),
        network.relay_policy
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_one_link_join_with_planet() {
        let invite = InviteLink::parse(
            "meshlake://join?controller=https%3A%2F%2Fplanet.example.com&network_id=2a2d7ed1-5a22-4f60-b6c5-573ac589c514&token=one-time-token&public_key=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA%3D&planet=https%3A%2F%2Fplanet.example.com%2Fv1%2Fplanet",
        )
        .expect("link should parse");
        assert_eq!(invite.controller, "https://planet.example.com");
        assert_eq!(
            invite.planet.as_deref(),
            Some("https://planet.example.com/v1/planet")
        );
    }

    #[test]
    fn rejects_untrusted_link_scheme() {
        assert!(InviteLink::parse(
            "https://example.com/join?controller=https%3A%2F%2Fplanet.example.com&network_id=2a2d7ed1-5a22-4f60-b6c5-573ac589c514&token=x&public_key=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA%3D"
        )
        .is_err());
    }

    #[test]
    fn parses_dual_stack_controller_network_create() {
        let cli = Cli::try_parse_from([
            "meshlake",
            "controller",
            "network",
            "create",
            "--controller",
            "http://127.0.0.1:51822",
            "--admin-token",
            "secret",
            "--name",
            "home",
            "--ipv4-prefix",
            "100.64.50.0/24",
            "--ipv6-prefix",
            "fd42:4d4c:50::/64",
            "--relay-policy",
            "preferred",
        ])
        .unwrap();
        let Command::Controller {
            command:
                ControllerCommand::Network {
                    command:
                        ControllerNetworkCommand::Create {
                            ipv4_prefix,
                            ipv6_prefix,
                            ..
                        },
                },
        } = cli.command
        else {
            panic!("expected controller network create command");
        };
        assert_eq!(ipv4_prefix, "100.64.50.0/24");
        assert_eq!(ipv6_prefix.as_deref(), Some("fd42:4d4c:50::/64"));
    }
}
async fn print_network(response: reqwest::Response) -> Result<()> {
    let network: JoinedNetwork = ensure_success(response).await?.json().await?;
    println!(
        "Network enrolled: {} ({})",
        network.network.name, network.network.id.0
    );
    Ok(())
}
