use std::net::SocketAddr;

use anyhow::{Context, Result};
use asira_tunnel::{connect_client, ClientConfig};
use clap::Parser;

#[derive(Debug, Parser)]
#[command(name = "asira-client", about = "Selective IPv4 tunnel client harness")]
struct Args {
    #[arg(long)]
    server: SocketAddr,
    #[arg(long, value_delimiter = ',')]
    routes: Vec<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let passphrase = std::env::var("ASIRA_ROUTER_PASSPHRASE").context(
        "set ASIRA_ROUTER_PASSPHRASE instead of placing the passphrase in process arguments",
    )?;
    let route_text = args.routes.join("\n");
    let config = ClientConfig::from_route_text(args.server, passphrase, &route_text)?;
    let session = connect_client(config).await.context("connecting client")?;
    println!("connected as {}", session.status.assigned_ipv4);
    tokio::signal::ctrl_c().await?;
    session.disconnect().await
}
