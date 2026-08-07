mod secret_input;

use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use clap::{Args, Parser, Subcommand, ValueEnum};
use meshlake_core::{
    create_restricted_secret_file, AgentStatus, EnrollmentResponse, JoinedNetwork, RelayPolicy,
    SessionList, SessionObservation, SessionPath, SessionState, UpsertNetworkRequest,
    VirtualNetwork,
};
use reqwest::{Certificate, Client, StatusCode};
use std::{
    fs,
    io::{self, IsTerminal, Write},
    path::PathBuf,
};
use url::Url;
use uuid::Uuid;

use secret_input::{AdminTokenInputArgs, EnrollmentTokenInputArgs, JoinLinkInputArgs, SecretInput};

const LOCAL_API: &str = "http://127.0.0.1:51821/v1";

#[derive(Parser)]
#[command(name = "meshlake", about = "MeshLake headless management CLI")]
struct Cli {
    /// PEM CA certificate trusted exclusively for controller HTTPS requests.
    #[arg(long, global = true, value_name = "CA_CERTIFICATE_PEM")]
    tls_ca_certificate: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Status,
    /// List sanitized pairwise-session state from the local daemon.
    Sessions {
        /// Print the versioned /v1/sessions response without lossy reformatting.
        #[arg(long)]
        json: bool,
    },
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
        #[command(flatten)]
        admin_token: AdminTokenInputArgs,
        #[command(flatten)]
        output: InviteLinkOutputArgs,
        /// Invitation lifetime in seconds (60 through 86400).
        #[arg(long, default_value_t = 900)]
        expires_in_seconds: u64,
    },
    /// Authorize or revoke a member as an exit-node candidate for one network.
    Exit {
        #[command(subcommand)]
        command: ControllerExitCommand,
    },
}

#[derive(Subcommand)]
enum ControllerExitCommand {
    Set {
        #[arg(long)]
        controller: String,
        #[arg(long)]
        network: Uuid,
        #[arg(long)]
        device: Uuid,
        #[command(flatten)]
        admin_token: AdminTokenInputArgs,
        /// Authorize this candidate for an IPv4 default route.
        #[arg(long)]
        ipv4: bool,
        /// Authorize this candidate for an IPv6 default route.
        #[arg(long)]
        ipv6: bool,
    },
    Clear {
        #[arg(long)]
        controller: String,
        #[arg(long)]
        network: Uuid,
        #[arg(long)]
        device: Uuid,
        #[command(flatten)]
        admin_token: AdminTokenInputArgs,
    },
}

#[derive(Args)]
#[group(id = "invite_link_output", required = true, multiple = false)]
struct InviteLinkOutputArgs {
    /// Show the complete one-time join link only on an attached terminal.
    #[arg(long, group = "invite_link_output")]
    claim_invite_link: bool,
    /// Write the complete one-time join link to a new restricted file.
    #[arg(long, group = "invite_link_output", value_name = "SECRET_FILE")]
    invite_link_file: Option<PathBuf>,
}

enum InviteLinkOutput {
    AttachedTerminal,
    RestrictedFile(PathBuf),
}

impl From<InviteLinkOutputArgs> for InviteLinkOutput {
    fn from(args: InviteLinkOutputArgs) -> Self {
        if args.claim_invite_link {
            Self::AttachedTerminal
        } else if let Some(path) = args.invite_link_file {
            Self::RestrictedFile(path)
        } else {
            unreachable!("clap requires exactly one invitation output")
        }
    }
}

#[derive(Subcommand)]
enum ControllerNetworkCommand {
    Create {
        #[arg(long)]
        controller: String,
        #[command(flatten)]
        admin_token: AdminTokenInputArgs,
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
        #[command(flatten)]
        admin_token: AdminTokenInputArgs,
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
        #[command(flatten)]
        link: JoinLinkInputArgs,
    },
    Join {
        /// Controller URL, for example https://controller.example.com.
        #[arg(long)]
        controller: String,
        #[arg(long)]
        network: Uuid,
        #[command(flatten)]
        token: EnrollmentTokenInputArgs,
        /// Base64 controller Ed25519 public key obtained from a trusted administrator.
        #[arg(long)]
        controller_public_key_base64: String,
    },
    Leave {
        #[arg(long)]
        network: Uuid,
    },
    /// Select or clear a locally enabled exit gateway. This never changes the
    /// controller policy and requires a current signed exit candidate.
    Exit {
        #[command(subcommand)]
        command: NetworkExitCommand,
    },
    /// Enable or disable this device as a locally operated forwarding/NAT exit
    /// gateway after the controller has authorized it as a candidate.
    Gateway {
        #[command(subcommand)]
        command: NetworkGatewayCommand,
    },
}

#[derive(Subcommand)]
enum NetworkExitCommand {
    Select {
        #[arg(long)]
        network: Uuid,
        #[arg(long)]
        ipv4_gateway: Option<Uuid>,
        #[arg(long)]
        ipv6_gateway: Option<Uuid>,
        /// Block physical-network fallback if the selected exit cannot be
        /// applied. Platform enforcement is introduced in the next stage-4
        /// increment.
        #[arg(long)]
        kill_switch: bool,
    },
    Clear {
        #[arg(long)]
        network: Uuid,
    },
}

#[derive(Subcommand)]
enum NetworkGatewayCommand {
    Enable {
        #[arg(long)]
        network: Uuid,
        /// Physical egress interface, for example `Ethernet`, `eth0`, or
        /// `ens3`. It is always passed as data, never evaluated by a shell.
        #[arg(long)]
        egress_interface: String,
        #[arg(long)]
        ipv4: bool,
        #[arg(long)]
        ipv6: bool,
    },
    Disable {
        #[arg(long)]
        network: Uuid,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let tls_ca = load_tls_ca_file(cli.tls_ca_certificate.as_deref())?;
    let client = controller_client(tls_ca.as_ref())?;
    match cli.command {
        Command::Status => {
            print_status(client.get(format!("{LOCAL_API}/status")).send().await?).await?
        }
        Command::Sessions { json } => {
            print_sessions(
                client.get(format!("{LOCAL_API}/sessions")).send().await?,
                json,
            )
            .await?
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
            println!("Relay endpoint saved and applied: {endpoint}");
        }
        Command::Planet {
            command:
                PlanetCommand::Set {
                    manifest,
                    controller_public_key_base64,
                },
        } => {
            let manifest = normalize_http_url(&manifest, "Planet manifest URL", true)?;
            validate_tls_url_pair(&manifest, None, tls_ca.is_some())?;
            ensure_success(
                client
                    .post(format!("{LOCAL_API}/planet"))
                    .json(&serde_json::json!({
                        "manifest_url": manifest,
                        "controller_public_key_base64": controller_public_key_base64,
                        "tls_ca_certificate_pem": tls_ca.as_ref().map(|ca| ca.pem.clone()),
                    }))
                    .send()
                    .await?,
            )
            .await?;
            println!("Planet settings verified, saved and applied.");
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
            let admin_token = SecretInput::from(admin_token).resolve("administrator token")?;
            let controller_url = controller_base_url(&controller, tls_ca.is_some())?;
            let request = UpsertNetworkRequest {
                id: None,
                name,
                ipv4_prefix,
                ipv6_prefix,
                relay_policy: relay_policy.into(),
            };
            let network: VirtualNetwork = ensure_sensitive_success(
                client
                    .post(format!("{controller_url}/v1/networks"))
                    .header("x-meshlake-admin-token", admin_token.as_str())
                    .json(&request)
                    .send()
                    .await?,
                "controller network creation",
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
            let controller_url = controller_base_url(&controller, tls_ca.is_some())?;
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
            let admin_token = SecretInput::from(admin_token).resolve("administrator token")?;
            let controller_url = controller_base_url(&controller, tls_ca.is_some())?;
            ensure_sensitive_success(
                client
                    .delete(format!("{controller_url}/v1/networks/{network}"))
                    .header("x-meshlake-admin-token", admin_token.as_str())
                    .send()
                    .await?,
                "controller network deletion",
            )
            .await?;
            println!("Controller network {network} deleted.");
        }
        Command::Controller {
            command: ControllerCommand::PublicKey { controller },
        } => {
            let controller_url = controller_base_url(&controller, tls_ca.is_some())?;
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
                    output,
                    expires_in_seconds,
                },
        } => {
            let admin_token = SecretInput::from(admin_token).resolve("administrator token")?;
            let controller_url = controller_base_url(&controller, tls_ca.is_some())?;
            let response: serde_json::Value = ensure_sensitive_success(
                client
                    .post(format!(
                        "{controller_url}/v1/networks/{network}/enrollment-tokens"
                    ))
                    .header("x-meshlake-admin-token", admin_token.as_str())
                    .json(&serde_json::json!({
                        "expires_in_seconds": expires_in_seconds,
                    }))
                    .send()
                    .await?,
                "controller invitation creation",
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
            let stdout = io::stdout();
            let attached_terminal = stdout.is_terminal();
            deliver_invite_link(
                link,
                InviteLinkOutput::from(output),
                attached_terminal,
                &mut stdout.lock(),
            )?;
        }
        Command::Controller {
            command:
                ControllerCommand::Exit {
                    command:
                        ControllerExitCommand::Set {
                            controller,
                            network,
                            device,
                            admin_token,
                            ipv4,
                            ipv6,
                        },
                },
        } => {
            if !ipv4 && !ipv6 {
                bail!("choose at least one of --ipv4 or --ipv6 for an exit candidate");
            }
            let admin_token = SecretInput::from(admin_token).resolve("administrator token")?;
            let controller_url = controller_base_url(&controller, tls_ca.is_some())?;
            update_controller_exit_candidate(
                &client,
                &controller_url,
                network,
                device,
                Some((ipv4, ipv6)),
                admin_token.as_str(),
            )
            .await?;
            println!("Exit candidate {device} saved for controller network {network}.");
        }
        Command::Controller {
            command:
                ControllerCommand::Exit {
                    command:
                        ControllerExitCommand::Clear {
                            controller,
                            network,
                            device,
                            admin_token,
                        },
                },
        } => {
            let admin_token = SecretInput::from(admin_token).resolve("administrator token")?;
            let controller_url = controller_base_url(&controller, tls_ca.is_some())?;
            update_controller_exit_candidate(
                &client,
                &controller_url,
                network,
                device,
                None,
                admin_token.as_str(),
            )
            .await?;
            println!("Exit candidate {device} cleared for controller network {network}.");
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
            command:
                NetworkCommand::Exit {
                    command:
                        NetworkExitCommand::Select {
                            network,
                            ipv4_gateway,
                            ipv6_gateway,
                            kill_switch,
                        },
                },
        } => {
            ensure_success(
                client
                    .post(format!("{LOCAL_API}/networks/{network}/exit-selection"))
                    .json(&serde_json::json!({
                        "ipv4_gateway": ipv4_gateway,
                        "ipv6_gateway": ipv6_gateway,
                        "kill_switch": kill_switch,
                    }))
                    .send()
                    .await?,
            )
            .await?;
            println!("Local exit selection saved for network {network}.");
        }
        Command::Network {
            command:
                NetworkCommand::Exit {
                    command: NetworkExitCommand::Clear { network },
                },
        } => {
            ensure_success(
                client
                    .post(format!("{LOCAL_API}/networks/{network}/exit-selection"))
                    .json(&serde_json::json!({
                        "ipv4_gateway": null,
                        "ipv6_gateway": null,
                        "kill_switch": false,
                    }))
                    .send()
                    .await?,
            )
            .await?;
            println!("Local exit selection cleared for network {network}.");
        }
        Command::Network {
            command:
                NetworkCommand::Gateway {
                    command:
                        NetworkGatewayCommand::Enable {
                            network,
                            egress_interface,
                            ipv4,
                            ipv6,
                        },
                },
        } => {
            if !ipv4 && !ipv6 {
                bail!("choose at least one of --ipv4 or --ipv6 for an exit gateway");
            }
            ensure_success(
                client
                    .post(format!("{LOCAL_API}/networks/{network}/exit-gateway"))
                    .json(&serde_json::json!({
                        "egress_interface": egress_interface,
                        "enable_ipv4": ipv4,
                        "enable_ipv6": ipv6,
                    }))
                    .send()
                    .await?,
            )
            .await?;
            println!("Local exit gateway enabled for network {network}.");
        }
        Command::Network {
            command:
                NetworkCommand::Gateway {
                    command: NetworkGatewayCommand::Disable { network },
                },
        } => {
            ensure_success(
                client
                    .delete(format!("{LOCAL_API}/networks/{network}/exit-gateway"))
                    .send()
                    .await?,
            )
            .await?;
            println!("Local exit gateway disabled for network {network}.");
        }
        Command::Network {
            command: NetworkCommand::JoinLink { link },
        } => {
            let link = SecretInput::from(link).resolve("join link")?;
            let invitation = InviteLink::parse(&link)?;
            let effective_tls_ca =
                select_effective_tls_ca(invitation.tls_ca.as_ref(), tls_ca.as_ref())?;
            validate_tls_url_pair(
                &invitation.controller,
                invitation.planet_manifest_url.as_deref(),
                effective_tls_ca.is_some(),
            )?;
            let control_plane = invitation.control_plane(effective_tls_ca.as_ref());
            let enrollment_client = controller_client(effective_tls_ca.as_ref())?;
            join_network(
                &enrollment_client,
                &invitation.controller,
                invitation.network,
                &invitation.token,
                &invitation.controller_public_key_base64,
                Some(control_plane),
            )
            .await?;
            println!("Network joined.");
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
            let token = SecretInput::from(token).resolve("enrollment token")?;
            let controller = controller_base_url(&controller, tls_ca.is_some())?;
            let control_plane = EnrollmentControlPlane {
                controller_url: controller.clone(),
                planet_manifest_url: None,
                controller_tls_ca_pem: tls_ca.as_ref().map(|ca| ca.pem.clone()),
            };
            join_network(
                &client,
                &controller,
                network,
                &token,
                &controller_public_key_base64,
                Some(control_plane),
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

/// Reads the current signed policy, changes only one exit candidate, then
/// submits the controller's compact policy-update representation. Keeping this
/// transformation in the CLI prevents an exit update from accidentally
/// deleting existing split routes or DNS settings.
async fn update_controller_exit_candidate(
    client: &Client,
    controller_url: &str,
    network: Uuid,
    device: Uuid,
    capability: Option<(bool, bool)>,
    admin_token: &str,
) -> Result<()> {
    let manifest: serde_json::Value = ensure_success(
        client
            .get(format!("{controller_url}/v1/networks/{network}/policy"))
            .send()
            .await?,
    )
    .await?
    .json()
    .await?;
    let routes = manifest
        .get("routes")
        .and_then(serde_json::Value::as_array)
        .context("controller returned an invalid signed policy route list")?
        .iter()
        .map(|route| {
            let prefix = route
                .get("prefix")
                .and_then(serde_json::Value::as_str)
                .context("controller policy route has no prefix")?;
            let gateway = route
                .pointer("/gateway_certificate/claims/device_id")
                .and_then(serde_json::Value::as_str)
                .context("controller policy route has no gateway device")?;
            Ok(serde_json::json!({
                "prefix": prefix,
                "gateway_device_id": gateway,
            }))
        })
        .collect::<Result<Vec<_>>>()?;
    let mut exit_nodes = manifest
        .get("exit_nodes")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .map(|exit_node| {
            let gateway = exit_node
                .pointer("/gateway_certificate/claims/device_id")
                .and_then(serde_json::Value::as_str)
                .context("controller exit candidate has no gateway device")?;
            let supports_ipv4 = exit_node
                .get("supports_ipv4")
                .and_then(serde_json::Value::as_bool)
                .context("controller exit candidate has no IPv4 capability")?;
            let supports_ipv6 = exit_node
                .get("supports_ipv6")
                .and_then(serde_json::Value::as_bool)
                .context("controller exit candidate has no IPv6 capability")?;
            Ok(serde_json::json!({
                "gateway_device_id": gateway,
                "supports_ipv4": supports_ipv4,
                "supports_ipv6": supports_ipv6,
            }))
        })
        .collect::<Result<Vec<_>>>()?;
    exit_nodes.retain(|exit_node| {
        exit_node
            .get("gateway_device_id")
            .and_then(serde_json::Value::as_str)
            .and_then(|value| value.parse::<Uuid>().ok())
            != Some(device)
    });
    if let Some((supports_ipv4, supports_ipv6)) = capability {
        exit_nodes.push(serde_json::json!({
            "gateway_device_id": device,
            "supports_ipv4": supports_ipv4,
            "supports_ipv6": supports_ipv6,
        }));
    }
    ensure_sensitive_success(
        client
            .post(format!("{controller_url}/v1/networks/{network}/policy"))
            .header("x-meshlake-admin-token", admin_token)
            .json(&serde_json::json!({
                "routes": routes,
                "exit_nodes": exit_nodes,
                "dns": manifest.get("dns").cloned().unwrap_or_else(|| serde_json::json!({})),
            }))
            .send()
            .await?,
        "controller exit candidate update",
    )
    .await?;
    Ok(())
}

#[derive(PartialEq, Eq)]
struct InviteLink {
    controller: String,
    network: Uuid,
    token: String,
    controller_public_key_base64: String,
    planet_manifest_url: Option<String>,
    tls_ca: Option<NormalizedTlsCa>,
}

impl std::fmt::Debug for InviteLink {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("InviteLink")
            .field("controller", &self.controller)
            .field("network", &self.network)
            .field("token", &"[REDACTED]")
            .field(
                "controller_public_key_base64",
                &self.controller_public_key_base64,
            )
            .field("planet_manifest_url", &self.planet_manifest_url)
            .field("tls_ca", &self.tls_ca)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NormalizedTlsCa {
    pem: String,
    certificates_der: Vec<Vec<u8>>,
}

impl InviteLink {
    fn parse(value: &str) -> Result<Self> {
        let url = Url::parse(value.trim()).context("invitation link is not a valid URL")?;
        if url.scheme() != "meshlake" || url.host_str() != Some("join") {
            bail!("invitation link must start with meshlake://join?");
        }
        if !url.username().is_empty()
            || url.password().is_some()
            || !url.path().is_empty()
            || url.fragment().is_some()
        {
            bail!("invitation link contains unsupported URL components");
        }
        let parameter = |name: &str| {
            url.query_pairs()
                .find(|(key, _)| key == name)
                .map(|(_, value)| value.into_owned())
                .filter(|value| !value.is_empty())
                .with_context(|| format!("invitation link is missing {name}"))
        };
        let controller =
            normalize_http_url(&parameter("controller")?, "invitation controller", false)?;
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
        let planet_manifest_url = url
            .query_pairs()
            .find(|(key, _)| key == "planet")
            .map(|(_, value)| value.into_owned())
            .filter(|value| !value.is_empty())
            .map(|value| normalize_http_url(&value, "invitation Planet manifest", true))
            .transpose()?;
        let tls_ca = url
            .query_pairs()
            .find(|(key, _)| key == "tls_ca")
            .map(|(_, value)| value.into_owned())
            .filter(|value| !value.is_empty())
            .map(|encoded| {
                let decoded = STANDARD
                    .decode(encoded)
                    .context("invitation tls_ca is not valid base64")?;
                if decoded.is_empty() || decoded.len() > 64 * 1024 {
                    bail!("invitation tls_ca must contain between 1 byte and 64 KiB");
                }
                let pem = String::from_utf8(decoded)
                    .context("invitation tls_ca is not a UTF-8 PEM certificate")?;
                normalize_tls_ca_pem(&pem)
            })
            .transpose()?;
        validate_tls_url_pair(
            &controller,
            planet_manifest_url.as_deref(),
            tls_ca.is_some(),
        )?;
        Ok(Self {
            controller,
            network,
            token: parameter("token")?,
            controller_public_key_base64,
            planet_manifest_url,
            tls_ca,
        })
    }

    /// Converts the optional Planet part of a complete invitation into the
    /// control-plane payload understood by recent local agents.  This keeps
    /// the Planet update in the same local transaction as enrollment instead
    /// of mutating the device-wide Planet setting before enrollment succeeds.
    fn control_plane(&self, tls_ca: Option<&NormalizedTlsCa>) -> EnrollmentControlPlane {
        EnrollmentControlPlane {
            controller_url: self.controller.clone(),
            planet_manifest_url: self.planet_manifest_url.clone(),
            controller_tls_ca_pem: tls_ca.map(|ca| ca.pem.clone()),
        }
    }
}

/// Optional signed discovery metadata carried by a complete invitation URL.
/// The local agent fetches and verifies the manifest with the pinned public
/// key only after it has verified the enrollment response.
#[derive(Debug, Clone, PartialEq, Eq)]
struct EnrollmentControlPlane {
    controller_url: String,
    planet_manifest_url: Option<String>,
    controller_tls_ca_pem: Option<String>,
}

impl EnrollmentControlPlane {
    fn into_json(self) -> serde_json::Value {
        serde_json::json!({
            "controller_url": self.controller_url,
            "planet_manifest_url": self.planet_manifest_url,
            "controller_tls_ca_pem": self.controller_tls_ca_pem,
        })
    }
}

/// Creates the local agent request that atomically stores membership and its
/// control-plane metadata. `control_plane` is omitted for legacy/manual joins.
fn local_enrollment_request(
    enrollment: serde_json::Value,
    controller_public_key: Vec<u8>,
    control_plane: Option<EnrollmentControlPlane>,
) -> serde_json::Value {
    let mut request = serde_json::json!({
        "enrollment": enrollment,
        "controller_public_key": controller_public_key,
    });
    if let Some(control_plane) = control_plane {
        request
            .as_object_mut()
            .expect("enrollment request must be a JSON object")
            .insert("control_plane".to_owned(), control_plane.into_json());
    }
    request
}

async fn join_network(
    client: &Client,
    controller: &str,
    network: Uuid,
    token: &str,
    controller_public_key_base64: &str,
    control_plane: Option<EnrollmentControlPlane>,
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
    let enrollment: EnrollmentResponse = ensure_sensitive_success(
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
        "controller enrollment",
    )
    .await?
    .json()
    .await?;
    let enrollment = serde_json::to_value(enrollment)
        .context("could not serialize controller enrollment for the local agent")?;
    let response = ensure_sensitive_success(
        client
            .post(format!("{LOCAL_API}/networks/enroll"))
            .json(&local_enrollment_request(
                enrollment,
                controller_public_key,
                control_plane,
            ))
            .send()
            .await?,
        "local enrollment persistence",
    )
    .await?;
    print_network(response).await
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

async fn ensure_sensitive_success(
    response: reqwest::Response,
    operation: &'static str,
) -> Result<reqwest::Response> {
    if response.status().is_success() {
        return Ok(response);
    }
    let status = response.status();
    bail!(
        "{operation} failed ({status}); response body omitted because the request contained secret material"
    )
}

fn deliver_invite_link(
    link: &str,
    output: InviteLinkOutput,
    attached_terminal: bool,
    terminal: &mut dyn Write,
) -> Result<()> {
    match output {
        InviteLinkOutput::AttachedTerminal => {
            if !attached_terminal {
                bail!("--claim-invite-link requires stdout to be an attached terminal");
            }
            writeln!(terminal, "{link}")
                .context("cannot write invitation link to the attached terminal")?;
            terminal
                .flush()
                .context("cannot flush invitation link terminal output")?;
        }
        InviteLinkOutput::RestrictedFile(path) => {
            create_restricted_secret_file(&path, link.as_bytes())
                .context("cannot create restricted invitation-link file")?;
            println!("Invitation link written to {}", path.display());
        }
    }
    Ok(())
}

fn load_tls_ca_file(path: Option<&std::path::Path>) -> Result<Option<NormalizedTlsCa>> {
    let Some(path) = path else {
        return Ok(None);
    };
    let bytes = fs::read(path)
        .with_context(|| format!("cannot read TLS CA certificate {}", path.display()))?;
    if bytes.is_empty() || bytes.len() > 64 * 1024 {
        bail!("TLS CA certificate must contain between 1 byte and 64 KiB");
    }
    let pem = String::from_utf8(bytes).context("TLS CA certificate is not UTF-8 PEM")?;
    Ok(Some(normalize_tls_ca_pem(&pem)?))
}

fn normalize_tls_ca_pem(pem: &str) -> Result<NormalizedTlsCa> {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    if pem.is_empty() || pem.len() > 64 * 1024 {
        bail!("TLS CA certificate must contain between 1 byte and 64 KiB");
    }
    let mut certificates_der = Vec::new();
    let mut current = None::<String>;
    for line in pem.lines().map(str::trim) {
        match line {
            BEGIN => {
                if current.is_some() {
                    bail!("TLS CA PEM contains a nested certificate block");
                }
                current = Some(String::new());
            }
            END => {
                let encoded = current
                    .take()
                    .context("TLS CA PEM contains an unmatched certificate end marker")?;
                if encoded.is_empty() {
                    bail!("TLS CA PEM contains an empty certificate block");
                }
                certificates_der.push(
                    STANDARD
                        .decode(encoded)
                        .context("TLS CA PEM certificate is not valid Base64")?,
                );
            }
            "" => {}
            value => {
                let Some(encoded) = current.as_mut() else {
                    bail!("TLS CA PEM contains data outside a certificate block");
                };
                if !value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'='))
                {
                    bail!("TLS CA PEM certificate contains invalid characters");
                }
                encoded.push_str(value);
            }
        }
    }
    if current.is_some() {
        bail!("TLS CA PEM certificate block is missing its end marker");
    }
    if certificates_der.is_empty() {
        bail!("TLS CA PEM bundle contains no certificates");
    }
    certificates_der.sort();
    certificates_der.dedup();

    // Building a rustls client forces every DER entry through its root-store
    // parser now, so malformed X.509 data is rejected before a token is used.
    let mut builder = Client::builder().tls_built_in_root_certs(false);
    for certificate in &certificates_der {
        builder = builder.add_root_certificate(
            Certificate::from_der(certificate).context("TLS CA certificate DER is invalid")?,
        );
    }
    builder
        .build()
        .context("TLS CA bundle contains an invalid X.509 certificate")?;

    let mut normalized = String::new();
    for certificate in &certificates_der {
        normalized.push_str(BEGIN);
        normalized.push('\n');
        let encoded = STANDARD.encode(certificate);
        for line in encoded.as_bytes().chunks(64) {
            normalized.push_str(std::str::from_utf8(line).expect("base64 is ASCII"));
            normalized.push('\n');
        }
        normalized.push_str(END);
        normalized.push('\n');
    }
    Ok(NormalizedTlsCa {
        pem: normalized,
        certificates_der,
    })
}

fn controller_client(tls_ca: Option<&NormalizedTlsCa>) -> Result<Client> {
    let mut builder = Client::builder().redirect(reqwest::redirect::Policy::none());
    if let Some(tls_ca) = tls_ca {
        builder = builder.tls_built_in_root_certs(false);
        for certificate in &tls_ca.certificates_der {
            builder = builder.add_root_certificate(
                Certificate::from_der(certificate).context("TLS CA certificate DER is invalid")?,
            );
        }
    }
    builder.build().context("cannot construct HTTPS client")
}

fn select_effective_tls_ca(
    invitation: Option<&NormalizedTlsCa>,
    command_line: Option<&NormalizedTlsCa>,
) -> Result<Option<NormalizedTlsCa>> {
    match (invitation, command_line) {
        (None, None) => Ok(None),
        (Some(ca), None) | (None, Some(ca)) => Ok(Some(ca.clone())),
        (Some(invitation), Some(command_line))
            if invitation.certificates_der == command_line.certificates_der =>
        {
            Ok(Some(invitation.clone()))
        }
        (Some(_), Some(_)) => {
            bail!("invitation TLS CA conflicts with --tls-ca-certificate; refusing enrollment")
        }
    }
}

fn normalize_http_url(value: &str, description: &str, allow_path: bool) -> Result<String> {
    let value = value.trim();
    let Some((raw_scheme, authority_and_path)) = value.split_once("://") else {
        bail!("{description} must use http:// or https://");
    };
    let raw_authority = authority_and_path
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default();
    if !matches!(raw_scheme.to_ascii_lowercase().as_str(), "http" | "https")
        || authority_and_path.is_empty()
        || authority_and_path.starts_with('/')
        || value.contains('\\')
        || raw_authority.contains('@')
    {
        bail!("{description} must include a valid HTTP authority");
    }
    let mut url = Url::parse(value).with_context(|| format!("{description} is not a valid URL"))?;
    if !matches!(url.scheme(), "http" | "https") {
        bail!("{description} must use http:// or https://");
    }
    if url.host_str().is_none() {
        bail!("{description} must include a host");
    }
    if !url.username().is_empty() || url.password().is_some() {
        bail!("{description} must not contain credentials");
    }
    if url.query().is_some() || url.fragment().is_some() {
        bail!("{description} must not contain a query or fragment");
    }
    if !allow_path && url.path() != "/" {
        bail!("{description} must not contain a path");
    }
    if allow_path && url.path() == "/" {
        bail!("{description} must include a manifest path");
    }
    if !allow_path {
        url.set_path("");
    }
    Ok(url.to_string().trim_end_matches('/').to_owned())
}

fn validate_tls_url_pair(
    controller_url: &str,
    planet_manifest_url: Option<&str>,
    has_private_ca: bool,
) -> Result<()> {
    if !has_private_ca {
        return Ok(());
    }
    if Url::parse(controller_url)?.scheme() != "https" {
        bail!("a private TLS CA requires an https:// controller URL");
    }
    if let Some(planet_manifest_url) = planet_manifest_url {
        if Url::parse(planet_manifest_url)?.scheme() != "https" {
            bail!("a private TLS CA requires an https:// Planet manifest URL");
        }
    }
    Ok(())
}

fn controller_base_url(value: &str, has_private_ca: bool) -> Result<String> {
    let url = normalize_http_url(value, "controller URL", false)?;
    validate_tls_url_pair(&url, None, has_private_ca)?;
    Ok(url)
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
    println!(
        "TLS relays: {}/{} connected  failures={}  frames={}/{}  queue_drops={}",
        status.transport.tls_relay_connected,
        status.transport.tls_relay_configured,
        status.transport.tls_relay_connection_failures,
        status.transport.tls_relay_frames_sent,
        status.transport.tls_relay_frames_received,
        status.transport.tls_relay_queue_drops,
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

async fn print_sessions(response: reqwest::Response, json: bool) -> Result<()> {
    let sessions: SessionList = ensure_success(response)
        .await?
        .json()
        .await
        .context("invalid session response")?;
    if json {
        println!("{}", render_sessions_json(&sessions)?);
        return Ok(());
    }
    print!("{}", render_sessions(&sessions));
    Ok(())
}

fn render_sessions_json(response: &SessionList) -> Result<String> {
    serde_json::to_string_pretty(response).context("could not serialize session response")
}

fn render_sessions(response: &SessionList) -> String {
    if response.sessions.is_empty() {
        return format!(
            "No pairwise sessions. Transport revision {}.\n",
            response.transport_revision
        );
    }
    let mut output = format!(
        "Pairwise sessions: {} (transport revision {})\n",
        response.sessions.len(),
        response.transport_revision
    );
    for session in &response.sessions {
        output.push_str(&render_session(session));
    }
    output
}

fn render_session(session: &SessionObservation) -> String {
    let state = match session.state {
        SessionState::Pending => "pending",
        SessionState::Established => "established",
        SessionState::Expired => "expired",
    };
    let path = match session.path {
        SessionPath::Unknown => "unknown",
        SessionPath::Direct => "direct",
        SessionPath::Relay => "relay",
        SessionPath::TlsRelay => "tls_relay",
    };
    format!(
        "  network {}  peer {}  {} via {}  age={}ms  queue={}/{} dropped={}  security={{attempts:{}, retries:{}, tx:{}, rx_auth:{}, rx_rejected:{}}}\n",
        session.network_id.0,
        session.peer_device_id.0,
        state,
        path,
        session.age_ms,
        session.queue.queued_packets,
        session.queue.queue_capacity,
        session.queue.dropped_packets,
        session.security.handshake_attempts,
        session.security.handshake_retries,
        session.security.encrypted_packets_sent,
        session.security.authenticated_packets_received,
        session.security.rejected_packets_received,
    )
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

    fn generated_test_ca_pem() -> String {
        let rcgen::CertifiedKey { cert, .. } =
            rcgen::generate_simple_self_signed(vec!["planet.example.com".into()]).unwrap();
        cert.pem()
    }

    fn encoded_query_value(value: &str) -> String {
        url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
    }

    #[test]
    fn parses_one_link_join_with_planet() {
        let invite = InviteLink::parse(
            "meshlake://join?controller=https%3A%2F%2Fplanet.example.com&network_id=2a2d7ed1-5a22-4f60-b6c5-573ac589c514&token=one-time-token&public_key=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA%3D&planet=https%3A%2F%2Fplanet.example.com%2Fv1%2Fplanet",
        )
        .expect("link should parse");
        assert_eq!(invite.controller, "https://planet.example.com");
        assert_eq!(
            invite.planet_manifest_url.as_deref(),
            Some("https://planet.example.com/v1/planet")
        );
        assert_eq!(
            invite.control_plane(None),
            EnrollmentControlPlane {
                controller_url: "https://planet.example.com".into(),
                planet_manifest_url: Some("https://planet.example.com/v1/planet".into()),
                controller_tls_ca_pem: None,
            }
        );
    }

    #[test]
    fn invitation_can_pin_a_private_tls_ca() {
        let pem = generated_test_ca_pem();
        let normalized = normalize_tls_ca_pem(&pem).unwrap();
        let link = format!(
            "meshlake://join?controller=https%3A%2F%2Fplanet.example.com&network_id=2a2d7ed1-5a22-4f60-b6c5-573ac589c514&token=single-use&public_key=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA%3D&planet=https%3A%2F%2Fplanet.example.com%2Fv1%2Fplanet&tls_ca={}",
            encoded_query_value(&STANDARD.encode(&pem))
        );
        let invite = InviteLink::parse(&link).unwrap();
        let ca = invite.tls_ca.as_ref().unwrap();
        assert_eq!(ca, &normalized);
        assert_eq!(
            invite
                .control_plane(Some(ca))
                .controller_tls_ca_pem
                .as_deref(),
            Some(normalized.pem.as_str())
        );
    }

    #[test]
    fn rejects_malformed_tls_ca_and_http_tls_ca_combinations() {
        let malformed = STANDARD
            .encode(b"-----BEGIN CERTIFICATE-----\nnot-a-certificate\n-----END CERTIFICATE-----\n");
        let malformed_link = format!(
            "meshlake://join?controller=https%3A%2F%2Fplanet.example.com&network_id=2a2d7ed1-5a22-4f60-b6c5-573ac589c514&token=x&public_key=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA%3D&tls_ca={}",
            encoded_query_value(&malformed)
        );
        assert!(InviteLink::parse(&malformed_link).is_err());

        let valid = STANDARD.encode(generated_test_ca_pem());
        let http_link = format!(
            "meshlake://join?controller=http%3A%2F%2Fplanet.example.com&network_id=2a2d7ed1-5a22-4f60-b6c5-573ac589c514&token=x&public_key=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA%3D&tls_ca={}",
            encoded_query_value(&valid)
        );
        assert!(InviteLink::parse(&http_link).is_err());
    }

    #[test]
    fn rejects_private_ca_conflicts_instead_of_silently_overriding() {
        let invitation_pem = generated_test_ca_pem();
        let invitation = normalize_tls_ca_pem(&invitation_pem).unwrap();
        let other = normalize_tls_ca_pem(&generated_test_ca_pem()).unwrap();
        assert!(select_effective_tls_ca(Some(&invitation), Some(&other)).is_err());

        let same_with_crlf = normalize_tls_ca_pem(&invitation_pem.replace('\n', "\r\n"))
            .expect("equivalent PEM formatting should normalize");
        assert_eq!(
            select_effective_tls_ca(Some(&invitation), Some(&same_with_crlf))
                .unwrap()
                .unwrap(),
            invitation
        );
    }

    #[test]
    fn command_line_ca_is_persisted_when_invitation_has_none() {
        let invite = InviteLink::parse(
            "meshlake://join?controller=https%3A%2F%2Fplanet.example.com&network_id=2a2d7ed1-5a22-4f60-b6c5-573ac589c514&token=one-time-token&public_key=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA%3D&planet=https%3A%2F%2Fplanet.example.com%2Fv1%2Fplanet",
        )
        .unwrap();
        let command_line = normalize_tls_ca_pem(&generated_test_ca_pem()).unwrap();
        let effective = select_effective_tls_ca(invite.tls_ca.as_ref(), Some(&command_line))
            .unwrap()
            .unwrap();
        assert_eq!(
            invite
                .control_plane(Some(&effective))
                .controller_tls_ca_pem
                .as_deref(),
            Some(command_line.pem.as_str())
        );
    }

    #[test]
    fn normalizes_http_urls_and_rejects_ambiguous_authorities() {
        assert_eq!(
            normalize_http_url(" HTTPS://Example.COM:443/ ", "controller URL", false).unwrap(),
            "https://example.com"
        );
        assert_eq!(
            normalize_http_url(
                " HTTPS://Example.COM:443/v1/planet/// ",
                "Planet manifest URL",
                true,
            )
            .unwrap(),
            "https://example.com/v1/planet"
        );
        for value in [
            "https://user@example.com",
            "https://@example.com",
            "https://example.com\\unexpected",
            "https:127.0.0.1:1",
            "https://example.com/api",
            "https://example.com/#fragment",
        ] {
            assert!(controller_base_url(value, false).is_err(), "{value}");
        }
    }

    #[test]
    fn local_enrollment_request_embeds_control_plane_atomically() {
        let request = local_enrollment_request(
            serde_json::json!({"network": {"name": "home"}}),
            vec![7; 32],
            Some(EnrollmentControlPlane {
                controller_url: "https://controller.example".into(),
                planet_manifest_url: Some("https://controller.example/v1/planet".into()),
                controller_tls_ca_pem: None,
            }),
        );
        assert_eq!(
            request["control_plane"]["controller_url"],
            "https://controller.example"
        );
        assert_eq!(
            request["control_plane"]["planet_manifest_url"],
            "https://controller.example/v1/planet"
        );
        assert!(request["control_plane"]["controller_tls_ca_pem"].is_null());
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

    #[test]
    fn parses_controller_and_local_exit_commands() {
        let controller = Cli::try_parse_from([
            "meshlake",
            "controller",
            "exit",
            "set",
            "--controller",
            "https://controller.example",
            "--network",
            "00000000-0000-0000-0000-000000000001",
            "--device",
            "00000000-0000-0000-0000-000000000002",
            "--ipv4",
            "--admin-token-stdin",
        ])
        .unwrap();
        assert!(matches!(
            controller.command,
            Command::Controller {
                command: ControllerCommand::Exit {
                    command: ControllerExitCommand::Set {
                        ipv4: true,
                        ipv6: false,
                        ..
                    }
                }
            }
        ));
        let local = Cli::try_parse_from([
            "meshlake",
            "network",
            "exit",
            "select",
            "--network",
            "00000000-0000-0000-0000-000000000001",
            "--ipv4-gateway",
            "00000000-0000-0000-0000-000000000002",
            "--kill-switch",
        ])
        .unwrap();
        assert!(matches!(
            local.command,
            Command::Network {
                command: NetworkCommand::Exit {
                    command: NetworkExitCommand::Select {
                        kill_switch: true,
                        ..
                    }
                }
            }
        ));
        let gateway = Cli::try_parse_from([
            "meshlake",
            "network",
            "gateway",
            "enable",
            "--network",
            "00000000-0000-0000-0000-000000000001",
            "--egress-interface",
            "Ethernet",
            "--ipv4",
        ])
        .unwrap();
        assert!(matches!(
            gateway.command,
            Command::Network {
                command: NetworkCommand::Gateway {
                    command: NetworkGatewayCommand::Enable {
                        ipv4: true,
                        ipv6: false,
                        ..
                    }
                }
            }
        ));
    }

    #[test]
    fn secret_sources_are_required_and_mutually_exclusive() {
        assert!(Cli::try_parse_from(["meshlake", "network", "join-link", "--link-stdin",]).is_ok());
        assert!(Cli::try_parse_from([
            "meshlake",
            "network",
            "join-link",
            "--link",
            "meshlake://join?token=deprecated",
            "--link-file",
            "join.secret",
        ])
        .is_err());
        assert!(Cli::try_parse_from(["meshlake", "network", "join-link"]).is_err());

        assert!(Cli::try_parse_from([
            "meshlake",
            "controller",
            "network",
            "delete",
            "--controller",
            "http://127.0.0.1:51822",
            "--network",
            "2a2d7ed1-5a22-4f60-b6c5-573ac589c514",
            "--admin-token-file",
            "admin.secret",
        ])
        .is_ok());

        let invite_base = [
            "meshlake",
            "controller",
            "invite",
            "--controller",
            "http://127.0.0.1:51822",
            "--network",
            "2a2d7ed1-5a22-4f60-b6c5-573ac589c514",
            "--admin-token-stdin",
        ];
        assert!(Cli::try_parse_from(invite_base).is_err());
        assert!(
            Cli::try_parse_from(invite_base.into_iter().chain(["--claim-invite-link"])).is_ok()
        );
    }

    #[test]
    fn invite_output_requires_tty_or_a_new_restricted_file() {
        let secret = "meshlake://join?token=invite-output-secret";
        let mut terminal = Vec::new();
        let error = deliver_invite_link(
            secret,
            InviteLinkOutput::AttachedTerminal,
            false,
            &mut terminal,
        )
        .unwrap_err();
        assert!(error.to_string().contains("attached terminal"));
        assert!(terminal.is_empty());

        let path = std::env::temp_dir().join(format!("meshlake-invite-output-{}", Uuid::new_v4()));
        deliver_invite_link(
            secret,
            InviteLinkOutput::RestrictedFile(path.clone()),
            false,
            &mut terminal,
        )
        .unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), secret);
        let error = deliver_invite_link(
            "replacement-secret",
            InviteLinkOutput::RestrictedFile(path.clone()),
            false,
            &mut terminal,
        )
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("cannot create restricted invitation-link file"));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), secret);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn invite_debug_redacts_the_enrollment_token() {
        let secret = "enrollment-token-that-must-not-be-logged";
        let invite = InviteLink::parse(&format!(
            "meshlake://join?controller=https%3A%2F%2Fcontroller.example&network_id=2a2d7ed1-5a22-4f60-b6c5-573ac589c514&token={secret}&public_key=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA%3D"
        ))
        .unwrap();
        assert!(!format!("{invite:?}").contains(secret));
    }

    #[tokio::test]
    async fn sensitive_request_errors_omit_reflected_response_bodies() {
        use std::io::{Read, Write};

        let secret = "reflected-administrator-token";
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = [0_u8; 1024];
            let _ = stream.read(&mut request);
            let body = format!("controller reflected {secret}");
            write!(
                stream,
                "HTTP/1.1 401 Unauthorized\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            )
            .unwrap();
        });
        let response = Client::new()
            .get(format!("http://{address}/"))
            .send()
            .await
            .unwrap();
        let error = ensure_sensitive_success(response, "test secret request")
            .await
            .unwrap_err();
        server.join().unwrap();
        assert!(!error.to_string().contains(secret));
        assert!(error.to_string().contains("response body omitted"));
    }

    #[test]
    fn parses_sessions_json_command() {
        let cli = Cli::try_parse_from(["meshlake", "sessions", "--json"]).unwrap();
        assert!(matches!(cli.command, Command::Sessions { json: true }));
    }

    #[test]
    fn session_json_output_is_versioned_and_stable() {
        let response = SessionList {
            schema_version: 1,
            generated_at_unix_ms: 123,
            transport_revision: 7,
            sessions: vec![SessionObservation {
                network_id: meshlake_core::NetworkId(Uuid::from_u128(1)),
                peer_device_id: meshlake_core::DeviceId(Uuid::from_u128(2)),
                state: SessionState::Established,
                path: SessionPath::Relay,
                age_ms: 45,
                queue: meshlake_core::SessionQueueCounters {
                    queued_packets: 0,
                    queue_capacity: 8,
                    dropped_packets: 1,
                },
                security: meshlake_core::SessionSecurityCounters {
                    handshake_attempts: 2,
                    handshake_retries: 1,
                    encrypted_packets_sent: 3,
                    authenticated_packets_received: 4,
                    rejected_packets_received: 5,
                },
            }],
        };

        assert_eq!(
            render_sessions_json(&response).unwrap(),
            r#"{
  "schema_version": 1,
  "generated_at_unix_ms": 123,
  "transport_revision": 7,
  "sessions": [
    {
      "network_id": "00000000-0000-0000-0000-000000000001",
      "peer_device_id": "00000000-0000-0000-0000-000000000002",
      "state": "established",
      "path": "relay",
      "age_ms": 45,
      "queue": {
        "queued_packets": 0,
        "queue_capacity": 8,
        "dropped_packets": 1
      },
      "security": {
        "handshake_attempts": 2,
        "handshake_retries": 1,
        "encrypted_packets_sent": 3,
        "authenticated_packets_received": 4,
        "rejected_packets_received": 5
      }
    }
  ]
}"#
        );
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
