# Asira Router

Asira Router is a selective IPv4 tunnel. The Windows client installs only the
CIDR routes entered by the user and sends those packets through the Ubuntu VPS.
All other traffic stays on the normal local connection.

This repository currently contains an MVP with a Windows installer build. The
server and client use one shared passphrase from the server configuration.
Multiple clients can use the same passphrase; each connected client receives a
different private tunnel address.

## Repository layout

- `apps/server`: VPS daemon.
- `apps/client`: command-line client harness for development.
- `apps/tauri-client`: Windows Tauri GUI.
- `crates/protocol`: wire messages and IPv4 validation.
- `crates/tunnel`: shared server/client tunnel implementation.

## Server setup (Ubuntu)

### Install a prebuilt release

Tagged releases publish a ready-to-run Ubuntu x86_64 server package. The VPS
does not need Rust, Node.js, or a compiler. The GitHub repository is
`rehabdev/router`:

```text
curl --fail --location https://github.com/rehabdev/router/releases/latest/download/install-server.sh -o install-server.sh
less install-server.sh
sudo bash install-server.sh
```

Because this repository is private, create a fine-grained GitHub token with
read-only access to this repository before installing on a VPS. Keep it only
in the current shell and pass it through the environment; the installer uses it
only for downloading the release assets and never writes it to disk:

```text
export GITHUB_TOKEN='paste-your-read-only-token-here'
sudo -E bash install-server.sh
unset GITHUB_TOKEN
```

For a public repository, omit `GITHUB_TOKEN` and run `sudo bash install-server.sh`.

The installer verifies the package SHA-256 checksum, installs
`/usr/local/bin/asira-server`, creates a systemd service, creates the protected
config at `/etc/asira-router/server.toml`, prompts for the shared passphrase,
and starts the service. For a specific release, add
`--version v0.1.2 --repository rehabdev/router` to the installer command.
It intentionally does not change forwarding or firewall rules because the
public network interface differs between VPS providers.

After installation, check the service with:

```text
sudo systemctl status asira-router
sudo journalctl -u asira-router -e
```

### Build from source

Build the server on Ubuntu with a current stable Rust toolchain:

```text
cargo build --release -p asira-server
```

Copy `apps/server/server.toml.example` to `/etc/asira-router/server.toml`, set a
long random passphrase of at least 16 bytes, and protect the file because the
passphrase is stored in it:

```text
sudo chmod 600 /etc/asira-router/server.toml
```

The server refuses the example placeholder passphrase and refuses to start if
the config is readable by group or other users. The default listener is UDP
port `4433`; open that UDP port in the VPS provider firewall and Ubuntu
firewall.

The server must be allowed to forward and NAT the private tunnel network. The
following is an example using nftables; replace `eth0` with the VPS's public
interface and keep the rules aligned with the VPS firewall policy:

```text
sudo sysctl -w net.ipv4.ip_forward=1
sudo nft add table ip asira_router
sudo nft 'add chain ip asira_router postrouting { type nat hook postrouting priority srcnat; policy accept; }'
sudo nft add rule ip asira_router postrouting ip saddr 10.88.0.0/24 oifname "eth0" masquerade
```

Persist `net.ipv4.ip_forward=1` in `/etc/sysctl.d/99-asira-router.conf` and
persist the firewall rules using the distribution's normal nftables service.

Start the server as root (or with the privileges required to create a TUN
device):

```text
sudo /usr/local/bin/asira-server --config /etc/asira-router/server.toml
```

The server creates a TUN device named `asira0`, assigns `10.88.0.1/24`, and
allocates client addresses starting at `10.88.0.2`. The daemon does not change
the VPS firewall automatically.

## Windows client setup

The client requires:

- Windows 10 or newer, IPv4 connectivity, and administrator privileges.
- The `wintun.dll` matching the application's architecture beside the client
  executable. Download it from the official WireGuard/Wintun distribution and
  verify its origin before packaging it.
- A VPS IP address, the configured UDP port, the shared passphrase, and one or
  more destination CIDRs.

Example destinations:

```text
203.0.113.0/24
198.51.100.17/32
```

The client intentionally rejects `0.0.0.0/0`, routes that include the VPS
endpoint address, malformed CIDRs, and overlapping duplicate entries. The VPS
endpoint must remain reachable over the normal ISP route.

For a development build:

```text
cd apps/tauri-client
npm install
npm run tauri build
```

The command-line client harness reads the passphrase from the
`ASIRA_ROUTER_PASSPHRASE` environment variable so it does not appear in the
process command line:

```text
$env:ASIRA_ROUTER_PASSPHRASE = "use-a-long-random-passphrase"
cargo run -p asira-client -- --server 203.0.113.10 --port 4433 --routes 203.0.113.0/24
```

The generated MSI and NSIS installer are written under
`target/debug/bundle/`. Install and run the generated application as
administrator. Enter the VPS address, UDP port, passphrase, and destination
CIDRs, then connect. Disconnect removes the routes and stops the TUN device.
The GUI saves these settings under the per-user AppData folder. The ordinary
fields are stored in `settings.json`; Windows protects the saved passphrase
with DPAPI in a separate file, so it is not written as plaintext.
The client uses a custom frameless titlebar; its minimize control sends the
window to the normal Windows taskbar, and its close control exits the app.

## Development checks

```text
cargo fmt --all -- --check
cargo test --workspace
cargo check --workspace
cargo audit
cd apps/tauri-client
npm run build
```

End-to-end testing requires a real Ubuntu VPS, a configured forwarding/NAT
policy, an open UDP port, and the Windows TUN driver. A successful compile does
not prove that a provider's routing or firewall policy permits the tunnel.

## Current limitations

- IPv4 only.
- One shared passphrase; there is no per-device revocation.
- The MVP does not yet pin the server's self-signed QUIC certificate. The
  channel is encrypted with QUIC TLS. The server certificate is self-signed,
  but the passphrase proof is bound to the negotiated TLS channel, so a party
  without the passphrase cannot complete an active man-in-the-middle session.
  Certificate pinning remains a future defense-in-depth improvement.
- No automatic Windows service, tray minimization, or route persistence yet.
- The server's forwarding/NAT setup remains an administrator responsibility.
- The full Cargo lockfile audit currently reports two non-fatal advisories in
  GTK/glib and an unmaintained macro helper used by Tauri's non-Windows GUI
  dependency graph. They are not present in the Ubuntu server or Windows
  client target graphs; review them before adding another GUI target.

