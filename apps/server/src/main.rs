use std::path::PathBuf;

use anyhow::{Context, Result};
use asira_tunnel::{run_server, ServerConfig};
use clap::Parser;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

#[derive(Debug, Parser)]
#[command(name = "asira-server", about = "Selective IPv4 QUIC tunnel server")]
struct Args {
    #[arg(long, default_value = "/etc/asira-router/server.toml")]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    ensure_private_config_permissions(&args.config)?;
    let text = std::fs::read_to_string(&args.config)
        .with_context(|| format!("reading {}", args.config.display()))?;
    let config: ServerConfig = toml::from_str(&text).context("parsing server TOML")?;
    run_server(config).await
}

fn ensure_private_config_permissions(_path: &std::path::Path) -> Result<()> {
    #[cfg(unix)]
    {
        let mode = std::fs::metadata(_path)
            .with_context(|| format!("checking permissions for {}", _path.display()))?
            .permissions()
            .mode();
        if mode & 0o077 != 0 {
            return Err(anyhow::anyhow!(
                "server config {} must not be readable by group or other users; run chmod 600",
                _path.display()
            ));
        }
    }
    Ok(())
}
