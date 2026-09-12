use super::{controller_base_url, ensure_sensitive_success, AdminTokenInputArgs, SecretInput};
use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use reqwest::{Client, Response};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use uuid::Uuid;

#[derive(Args)]
pub(crate) struct NetworkArgs {
    #[arg(long)]
    controller: String,
    #[arg(long)]
    network: Uuid,
}

#[derive(Subcommand)]
pub(crate) enum MemberCommand {
    List {
        #[command(flatten)]
        target: NetworkArgs,
        #[command(flatten)]
        admin_token: AdminTokenInputArgs,
    },
    /// Revoke membership and rotate the network key epoch.
    Remove {
        #[command(flatten)]
        target: NetworkArgs,
        #[command(flatten)]
        admin_token: AdminTokenInputArgs,
        #[arg(long)]
        device: Uuid,
    },
    /// Replace route authorizations. Use --clear to revoke all allowed routes.
    Routes {
        #[command(flatten)]
        target: NetworkArgs,
        #[command(flatten)]
        admin_token: AdminTokenInputArgs,
        #[arg(long)]
        device: Uuid,
        #[arg(
            long = "route",
            required_unless_present = "clear",
            conflicts_with = "clear"
        )]
        routes: Vec<String>,
        #[arg(long)]
        clear: bool,
    },
}

#[derive(Subcommand)]
pub(crate) enum PolicyCommand {
    Get {
        #[command(flatten)]
        target: NetworkArgs,
        /// Output an editable complete policy accepted by policy set --file.
        #[arg(long)]
        editable: bool,
    },
    /// Replace the COMPLETE policy using a JSON file containing routes, exit_nodes and dns.
    Set {
        #[command(flatten)]
        target: NetworkArgs,
        #[command(flatten)]
        admin_token: AdminTokenInputArgs,
        #[arg(long)]
        file: PathBuf,
    },
}

// Require every section and reject unknown keys: a typo must not silently erase policy.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyUpdate {
    routes: Vec<Route>,
    exit_nodes: Vec<ExitNode>,
    dns: Dns,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Dns {
    #[serde(default)]
    servers: Vec<std::net::IpAddr>,
    #[serde(default)]
    search_domains: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Route {
    prefix: String,
    gateway_device_id: Uuid,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExitNode {
    gateway_device_id: Uuid,
    supports_ipv4: bool,
    supports_ipv6: bool,
}

async fn output(response: Response, operation: &'static str) -> Result<()> {
    let response = ensure_sensitive_success(response, operation).await?;
    if response.status() == reqwest::StatusCode::NO_CONTENT {
        println!("{{\"ok\":true}}");
    } else {
        let value: serde_json::Value = response.json().await?;
        super::print_json(&value)?;
    }
    Ok(())
}

pub(crate) async fn read(client: &Client, base: &str, path: &str) -> Result<()> {
    let response = client.get(format!("{base}{path}")).send().await?;
    if path == "/health" {
        let response = ensure_sensitive_success(response, "controller health").await?;
        println!("{}", serde_json::json!({"health": response.text().await?}));
        Ok(())
    } else {
        output(response, "controller query").await
    }
}

pub(crate) async fn member(
    client: &Client,
    private_ca: bool,
    command: MemberCommand,
) -> Result<()> {
    let (target, token, method, suffix, body) = match command {
        MemberCommand::List {
            target,
            admin_token,
        } => (
            target,
            admin_token,
            reqwest::Method::GET,
            String::new(),
            None,
        ),
        MemberCommand::Remove {
            target,
            admin_token,
            device,
        } => (
            target,
            admin_token,
            reqwest::Method::DELETE,
            format!("/{device}"),
            None,
        ),
        MemberCommand::Routes {
            target,
            admin_token,
            device,
            routes,
            ..
        } => (
            target,
            admin_token,
            reqwest::Method::POST,
            format!("/{device}/allowed-routes"),
            Some(serde_json::json!({"allowed_routes": routes})),
        ),
    };
    let base = controller_base_url(&target.controller, private_ca)?;
    let token = SecretInput::from(token).resolve("administrator token")?;
    let mut request = client
        .request(
            method,
            format!("{base}/v1/networks/{}/members{suffix}", target.network),
        )
        .header("x-meshlake-admin-token", token.as_str());
    if let Some(body) = body {
        request = request.json(&body);
    }
    output(request.send().await?, "controller member management").await
}

pub(crate) async fn policy(
    client: &Client,
    private_ca: bool,
    command: PolicyCommand,
) -> Result<()> {
    match command {
        PolicyCommand::Get { target, editable } => {
            let base = controller_base_url(&target.controller, private_ca)?;
            let response = ensure_sensitive_success(
                client
                    .get(format!("{base}/v1/networks/{}/policy", target.network))
                    .send()
                    .await?,
                "controller policy query",
            )
            .await?;
            let value: serde_json::Value = response.json().await?;
            let value = if editable {
                editable_policy(value)?
            } else {
                value
            };
            super::print_json(&value)?;
            Ok(())
        }
        PolicyCommand::Set {
            target,
            admin_token,
            file,
        } => {
            let body: PolicyUpdate =
                serde_json::from_slice(&std::fs::read(&file).context("cannot read policy file")?)
                    .context("invalid complete policy JSON")?;
            let base = controller_base_url(&target.controller, private_ca)?;
            let token = SecretInput::from(admin_token).resolve("administrator token")?;
            output(
                client
                    .post(format!("{base}/v1/networks/{}/policy", target.network))
                    .header("x-meshlake-admin-token", token.as_str())
                    .json(&body)
                    .send()
                    .await?,
                "controller policy update",
            )
            .await
        }
    }
}

pub(crate) fn editable_policy(value: serde_json::Value) -> Result<serde_json::Value> {
    let manifest: meshlake_core::NetworkPolicyManifest =
        serde_json::from_value(value).context("controller returned an invalid policy manifest")?;
    let body = PolicyUpdate {
        routes: manifest
            .routes
            .into_iter()
            .map(|route| Route {
                prefix: route.prefix,
                gateway_device_id: route.gateway_certificate.claims.device_id.0,
            })
            .collect(),
        exit_nodes: manifest
            .exit_nodes
            .into_iter()
            .map(|node| ExitNode {
                gateway_device_id: node.gateway_certificate.claims.device_id.0,
                supports_ipv4: node.supports_ipv4,
                supports_ipv6: node.supports_ipv6,
            })
            .collect(),
        dns: Dns {
            servers: manifest.dns.servers,
            search_domains: manifest.dns.search_domains,
        },
    };
    Ok(serde_json::to_value(body)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn route_replacement_requires_explicit_routes_or_clear() {
        let args = [
            "meshlake",
            "controller",
            "member",
            "routes",
            "--controller",
            "http://127.0.0.1:51822",
            "--network",
            "00000000-0000-0000-0000-000000000001",
            "--device",
            "00000000-0000-0000-0000-000000000002",
            "--admin-token-stdin",
        ];
        assert!(crate::Cli::try_parse_from(args).is_err());
        assert!(crate::Cli::try_parse_from(args.into_iter().chain(["--clear"])).is_ok());
        assert!(
            crate::Cli::try_parse_from(args.into_iter().chain(["--route", "10.0.0.0/24"])).is_ok()
        );
        assert!(crate::Cli::try_parse_from(args.into_iter().chain([
            "--route",
            "10.0.0.0/24",
            "--clear"
        ]))
        .is_err());
    }

    #[test]
    fn policy_rejects_omitted_or_misspelled_sections() {
        assert!(serde_json::from_str::<PolicyUpdate>(r#"{"routes":[],"dns":{}}"#).is_err());
        assert!(serde_json::from_str::<PolicyUpdate>(
            r#"{"routes":[],"exit_nodes":[],"dns":{},"route":[]}"#
        )
        .is_err());
        assert!(
            serde_json::from_str::<PolicyUpdate>(r#"{"routes":[],"exit_nodes":[],"dns":{}}"#)
                .is_ok()
        );
    }
}
