use anyhow::Result;
use clap::Args;
use reqwest::Client;
use serde_json::{json, Value};
use std::{
    net::{SocketAddr, TcpStream},
    time::{Duration, Instant},
};

#[derive(Args)]
pub(crate) struct DiagnoseArgs {
    /// Explicit IP:port (IPv6 uses [address]:port). Connect only; sends no application payload.
    #[arg(long)]
    tcp: Option<SocketAddr>,
}

pub(crate) async fn run(
    client: &Client,
    base: &str,
    timeout: u64,
    args: DiagnoseArgs,
) -> Result<bool> {
    let mut checks = Vec::<Value>::new();
    let mut ok = true;
    for resource in ["status", "sessions"] {
        let result = async {
            let response = super::ensure_sensitive_success(
                client.get(format!("{base}/{resource}")).send().await?,
                "local diagnostic query",
            )
            .await?;
            let value = if resource == "status" {
                serde_json::to_value(response.json::<meshlake_core::AgentStatus>().await?)?
            } else {
                serde_json::to_value(response.json::<meshlake_core::SessionList>().await?)?
            };
            Ok::<Value, anyhow::Error>(value)
        }
        .await;
        match result {
            Ok(value) => checks.push(json!({"check":resource,"ok":true,"data":value})),
            Err(error) => {
                ok = false;
                checks.push(json!({"check":resource,"ok":false,"error":error.to_string()}));
            }
        }
    }
    if let Some(address) = args.tcp {
        let started = Instant::now();
        let result = tokio::task::spawn_blocking(move || {
            TcpStream::connect_timeout(&address, Duration::from_secs(timeout))
        })
        .await?;
        let passed = result.is_ok();
        ok &= passed;
        checks.push(json!({"check":"tcp_connect","target":address.to_string(),"ok":passed,
            "elapsed_ms":started.elapsed().as_millis(), "error":result.err().map(|error| error.to_string())}));
    }
    super::print_json(&json!({"schema_version":1,"ok":ok,"checks":checks,
        "scope":"Local API inspection; optional TCP connect only. Does not verify encrypted overlay traffic, UDP, routing, DNS or failover."}))?;
    Ok(ok)
}
