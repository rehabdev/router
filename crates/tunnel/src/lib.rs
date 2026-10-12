use std::{
    collections::{hash_map::Entry, HashMap},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::Path,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex,
    },
};

use anyhow::{anyhow, Context, Result};
use asira_protocol::{
    decode_control_message, encode_control_message, parse_selective_routes, validate_ipv4_packet,
    validate_passphrase, AuthRequest, AuthResponse, ProtocolError, PROTOCOL_VERSION,
};
use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use hmac::{Hmac, Mac};
use ipnet::Ipv4Net;
use quinn::{Connection, Endpoint, RecvStream, SendStream};
use rcgen::generate_simple_self_signed;
use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime},
    DigitallySignedStruct, Error as RustlsError, SignatureScheme,
};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tokio::sync::{mpsc, oneshot};
use tokio::time::{timeout, Duration};
use tokio_util::codec::{FramedRead, FramedWrite};
use tun::{create_as_async, AbstractDevice, AsyncDevice, TunPacketCodec};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

// Keep the IP MTU below QUIC's conservative minimum datagram payload so the
// selected routes do not emit packets that QUIC cannot carry as one datagram.
const TUN_MTU: u16 = 1200;
const TUN_NETWORK: Ipv4Net = Ipv4Net::new_assert(Ipv4Addr::new(10, 88, 0, 0), 24);
const FIRST_CLIENT_HOST: u8 = 2;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(12);
const AUTH_TIMEOUT: Duration = Duration::from_secs(10);
const KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(5);
const AUTH_EXPORTER_LABEL: &[u8] = b"EXPORTER-asira-router-auth-v1";
const AUTH_EXPORTER_CONTEXT: &[u8] = b"asira-router-auth-v1";

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub bind: SocketAddr,
    pub passphrase: String,
    #[serde(default = "default_tun_name")]
    pub tun_name: String,
    #[serde(default = "default_tun_address")]
    pub tun_address: Ipv4Addr,
    #[serde(default = "default_cert_path")]
    pub certificate_path: String,
    #[serde(default = "default_key_path")]
    pub key_path: String,
}

#[derive(Debug, Clone)]
pub struct ClientConfig {
    pub server: SocketAddr,
    pub passphrase: String,
    pub routes: Vec<Ipv4Net>,
}

#[derive(Debug, Clone)]
pub struct ClientStatus {
    pub assigned_ipv4: Ipv4Addr,
    pub routes: Vec<Ipv4Net>,
}

pub struct ClientSession {
    shutdown: Option<oneshot::Sender<()>>,
    task: Option<tokio::task::JoinHandle<Result<()>>>,
    route_manager: Option<RouteManager>,
    task_error: Arc<Mutex<Option<String>>>,
    metrics: Arc<ClientMetrics>,
    pub status: ClientStatus,
}

#[derive(Default)]
struct ClientMetrics {
    packets_sent: AtomicU64,
    bytes_sent: AtomicU64,
    packets_received: AtomicU64,
    bytes_received: AtomicU64,
}

#[derive(Debug, Clone, Copy, Serialize)]
pub struct ClientMetricsSnapshot {
    pub packets_sent: u64,
    pub bytes_sent: u64,
    pub packets_received: u64,
    pub bytes_received: u64,
}

impl ClientMetrics {
    fn snapshot(&self) -> ClientMetricsSnapshot {
        ClientMetricsSnapshot {
            packets_sent: self.packets_sent.load(Ordering::Relaxed),
            bytes_sent: self.bytes_sent.load(Ordering::Relaxed),
            packets_received: self.packets_received.load(Ordering::Relaxed),
            bytes_received: self.bytes_received.load(Ordering::Relaxed),
        }
    }
}

#[derive(Clone)]
struct ServerSession {
    connection: Connection,
    routes: Vec<Ipv4Net>,
}

impl ServerConfig {
    pub fn validate(&self) -> Result<()> {
        validate_passphrase(&self.passphrase).map_err(|error| anyhow!(error))?;
        if self.passphrase == "replace-this-with-a-long-random-passphrase" {
            return Err(anyhow!(
                "server passphrase must be changed from the example value"
            ));
        }
        if self.bind.port() == 0 {
            return Err(anyhow!("server port cannot be zero"));
        }
        if !self.bind.ip().is_ipv4() {
            return Err(anyhow!("server bind address must be IPv4"));
        }
        if self.tun_address != Ipv4Addr::new(10, 88, 0, 1) {
            return Err(anyhow!(
                "tun_address must be 10.88.0.1 for the current address pool"
            ));
        }
        Ok(())
    }
}

impl ClientConfig {
    pub fn from_route_text(
        server: SocketAddr,
        passphrase: String,
        route_text: &str,
    ) -> Result<Self> {
        if server.port() == 0 {
            return Err(anyhow!("server port cannot be zero"));
        }
        let routes = parse_selective_routes(route_text).map_err(|err| anyhow!(err))?;
        let server_ip = match server.ip() {
            IpAddr::V4(ip) => ip,
            IpAddr::V6(_) => return Err(anyhow!("IPv6 server addresses are not supported")),
        };
        if routes.iter().any(|route| route.contains(&server_ip)) {
            return Err(anyhow!("a selective route would capture the VPS address"));
        }
        validate_passphrase(&passphrase).map_err(|error| anyhow!(error))?;
        Ok(Self {
            server,
            passphrase,
            routes,
        })
    }
}

pub async fn run_server(config: ServerConfig) -> Result<()> {
    config.validate()?;
    let endpoint = make_server_endpoint(&config).context("creating QUIC endpoint")?;
    let tun = create_tun(
        &config.tun_name,
        config.tun_address,
        TUN_NETWORK.prefix_len(),
        Ipv4Addr::new(10, 88, 0, 2),
    )
    .context("creating server TUN device")?;
    let (tun_writer, tun_reader) = tun.split().context("splitting server TUN device")?;
    let mut tun_reader = FramedRead::new(tun_reader, TunPacketCodec::new(TUN_MTU as usize));
    let mut tun_writer = FramedWrite::new(tun_writer, TunPacketCodec::new(TUN_MTU as usize));

    let sessions: Arc<Mutex<HashMap<Ipv4Addr, ServerSession>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let (to_tun_tx, mut to_tun_rx) = mpsc::channel::<Vec<u8>>(512);
    let _writer_task = tokio::spawn(async move {
        while let Some(packet) = to_tun_rx.recv().await {
            tun_writer
                .send(packet)
                .await
                .context("writing packet to server TUN device")?;
        }
        Ok::<(), anyhow::Error>(())
    });

    let reader_sessions = Arc::clone(&sessions);
    let _reader_task = tokio::spawn(async move {
        while let Some(packet) = tun_reader.next().await {
            let packet = packet.context("reading packet from server TUN device")?;
            let (_, destination) = match validate_ipv4_packet(&packet) {
                Ok(value) => value,
                Err(_) => continue,
            };
            let connection = reader_sessions
                .lock()
                .expect("session registry poisoned")
                .get(&destination)
                .map(|session| session.connection.clone());
            if let Some(connection) = connection {
                // Wait for QUIC datagram capacity instead of silently dropping
                // return packets when the send queue is temporarily full.
                let _ = connection.send_datagram_wait(Bytes::from(packet)).await;
            }
        }
        Ok::<(), anyhow::Error>(())
    });

    println!("Asira Router listening on {}", config.bind);
    println!("Tunnel network: {TUN_NETWORK}");
    loop {
        let Some(connecting) = endpoint.accept().await else {
            return Ok(());
        };
        let sessions = Arc::clone(&sessions);
        let to_tun_tx = to_tun_tx.clone();
        let passphrase = config.passphrase.clone();
        tokio::spawn(async move {
            if let Err(error) =
                handle_server_connection(connecting, passphrase, sessions, to_tun_tx).await
            {
                eprintln!("client connection closed: {error:#}");
            }
        });
    }
}

async fn handle_server_connection(
    connecting: quinn::Incoming,
    expected_passphrase: String,
    sessions: Arc<Mutex<HashMap<Ipv4Addr, ServerSession>>>,
    to_tun_tx: mpsc::Sender<Vec<u8>>,
) -> Result<()> {
    let connection = connecting.await.context("completing QUIC handshake")?;
    let (mut send, mut recv) = timeout(AUTH_TIMEOUT, connection.accept_bi())
        .await
        .context("timed out waiting for authentication stream")?
        .context("accepting auth stream")?;
    let request: AuthRequest = timeout(AUTH_TIMEOUT, read_control_message(&mut recv))
        .await
        .context("timed out waiting for authentication")??;
    let accepted = request.version == PROTOCOL_VERSION
        && verify_auth_proof(&connection, &expected_passphrase, &request.client_proof)?;
    if !accepted {
        write_control_message(
            &mut send,
            &AuthResponse {
                version: PROTOCOL_VERSION,
                accepted: false,
                assigned_ipv4: None,
                message: "authentication failed".to_owned(),
            },
        )
        .await?;
        let _ = send.finish();
        connection.close(0u32.into(), b"authentication failed");
        return Err(anyhow!("authentication failed"));
    }

    let routes = parse_selective_routes(&request.routes.join("\n"))
        .map_err(|error| anyhow!("invalid client route policy: {error}"))?;
    let assigned_ipv4 = reserve_client_ip(&sessions, connection.clone(), routes)?;
    if let Err(error) = write_control_message(
        &mut send,
        &AuthResponse {
            version: PROTOCOL_VERSION,
            accepted: true,
            assigned_ipv4: Some(assigned_ipv4),
            message: "connected".to_owned(),
        },
    )
    .await
    {
        sessions
            .lock()
            .expect("session registry poisoned")
            .remove(&assigned_ipv4);
        return Err(error);
    }
    let _ = send.finish();

    let allowed_routes = sessions
        .lock()
        .expect("session registry poisoned")
        .get(&assigned_ipv4)
        .map(|session| session.routes.clone())
        .ok_or_else(|| anyhow!("client session reservation disappeared"))?;

    let result = async {
        loop {
            let packet = connection
                .read_datagram()
                .await
                .context("reading QUIC datagram")?;
            if packet.len() > TUN_MTU as usize {
                return Err(anyhow!("client sent a packet larger than the tunnel MTU"));
            }
            let (source, destination) =
                validate_ipv4_packet(&packet).map_err(|err| anyhow!(err))?;
            if source != assigned_ipv4
                || !allowed_routes
                    .iter()
                    .any(|route| route.contains(&destination))
            {
                return Err(anyhow!(
                    "client sent a packet outside its assigned source or route policy"
                ));
            }
            to_tun_tx
                .send(packet.to_vec())
                .await
                .context("sending packet to TUN writer")?;
        }
    }
    .await;

    sessions
        .lock()
        .expect("session registry poisoned")
        .remove(&assigned_ipv4);
    result
}

fn reserve_client_ip(
    sessions: &Arc<Mutex<HashMap<Ipv4Addr, ServerSession>>>,
    connection: Connection,
    routes: Vec<Ipv4Net>,
) -> Result<Ipv4Addr> {
    let mut sessions = sessions.lock().expect("session registry poisoned");
    for host in FIRST_CLIENT_HOST..=254 {
        let candidate = Ipv4Addr::new(10, 88, 0, host);
        if let Entry::Vacant(entry) = sessions.entry(candidate) {
            entry.insert(ServerSession {
                connection: connection.clone(),
                routes: routes.clone(),
            });
            return Ok(candidate);
        }
    }
    Err(anyhow!("the tunnel address pool is full"))
}

pub async fn connect_client(config: ClientConfig) -> Result<ClientSession> {
    let mut endpoint = Endpoint::client("0.0.0.0:0".parse()?)?;
    endpoint.set_default_client_config(make_client_config()?);
    let connecting = endpoint
        .connect(config.server, "asira-router")
        .context("starting connection to VPS")?;
    let connection = timeout(CONNECT_TIMEOUT, connecting)
        .await
        .context("timed out connecting to VPS; check the VPS address and UDP port")?
        .context("connecting to VPS")?;

    let (mut send, mut recv) = connection.open_bi().await.context("opening auth stream")?;
    let client_proof = auth_proof(&connection, &config.passphrase)?;
    let route_policy = config
        .routes
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    write_control_message(
        &mut send,
        &AuthRequest {
            version: PROTOCOL_VERSION,
            client_proof,
            routes: route_policy,
        },
    )
    .await?;
    let _ = send.finish();
    let response: AuthResponse = timeout(AUTH_TIMEOUT, read_control_message(&mut recv))
        .await
        .context("timed out waiting for authentication response")??;
    if response.version != PROTOCOL_VERSION {
        return Err(anyhow!("server returned an unsupported protocol version"));
    }
    if !response.accepted {
        return Err(anyhow!("server rejected authentication"));
    }
    let assigned_ipv4 = response
        .assigned_ipv4
        .ok_or_else(|| anyhow!("server did not assign a tunnel address"))?;
    let assigned_octet = assigned_ipv4.octets()[3];
    if !TUN_NETWORK.contains(&assigned_ipv4) || !(FIRST_CLIENT_HOST..=254).contains(&assigned_octet)
    {
        return Err(anyhow!("server assigned an invalid tunnel address"));
    }

    let tun = create_tun(
        "AsiraRouter",
        assigned_ipv4,
        TUN_NETWORK.prefix_len(),
        Ipv4Addr::new(10, 88, 0, 1),
    )
    .context("creating Windows TUN device")?;
    let tun_index = tun
        .tun_index()
        .context("reading Windows TUN interface index")?;
    let (tun_writer, tun_reader) = tun.split().context("splitting client TUN device")?;
    let mut tun_reader = FramedRead::new(tun_reader, TunPacketCodec::new(TUN_MTU as usize));
    let mut tun_writer = FramedWrite::new(tun_writer, TunPacketCodec::new(TUN_MTU as usize));

    let route_manager = RouteManager::install(config.server, &config.routes, tun_index)?;
    let (shutdown_tx, mut shutdown_rx) = oneshot::channel();
    let connection_for_task = connection.clone();
    let allowed_routes = config.routes.clone();
    let task_error = Arc::new(Mutex::new(None));
    let task_error_for_task = Arc::clone(&task_error);
    let metrics = Arc::new(ClientMetrics::default());
    let metrics_for_task = Arc::clone(&metrics);
    let task = tokio::spawn(async move {
        let result = async {
            loop {
            tokio::select! {
                _ = &mut shutdown_rx => {
                    connection_for_task.close(0u32.into(), b"client disconnect");
                    return Ok(());
                }
                packet = tun_reader.next() => {
                    let Some(packet) = packet else { return Ok(()); };
                    let packet = packet.context("reading packet from client TUN device")?;
                    if packet.len() > TUN_MTU as usize {
                        return Err(anyhow!("client TUN produced a packet larger than the tunnel MTU"));
                    }
                    let (source, destination) = validate_ipv4_packet(&packet).map_err(|err| anyhow!(err))?;
                    if source != assigned_ipv4 || !allowed_routes.iter().any(|route| route.contains(&destination)) {
                        // Windows can emit housekeeping or locally generated IPv4 packets on a
                        // Wintun interface. They must never cross the tunnel, but they also
                        // must not tear down an otherwise healthy selective route session.
                        continue;
                    }
                    let packet_len = packet.len() as u64;
                    connection_for_task
                        .send_datagram_wait(Bytes::from(packet))
                        .await
                        .context("sending QUIC datagram")?;
                    metrics_for_task.packets_sent.fetch_add(1, Ordering::Relaxed);
                    metrics_for_task.bytes_sent.fetch_add(packet_len, Ordering::Relaxed);
                }
                packet = connection_for_task.read_datagram() => {
                    let packet = packet.context("reading QUIC datagram")?;
                    if packet.len() > TUN_MTU as usize {
                        return Err(anyhow!("server sent a packet larger than the tunnel MTU"));
                    }
                    validate_ipv4_packet(&packet).map_err(|err| anyhow!(err))?;
                    tun_writer.send(packet.to_vec()).await.context("writing packet to client TUN device")?;
                    metrics_for_task.packets_received.fetch_add(1, Ordering::Relaxed);
                    metrics_for_task.bytes_received.fetch_add(packet.len() as u64, Ordering::Relaxed);
                }
            }
        }
        }
        .await;
        if let Err(error) = &result {
            *task_error_for_task
                .lock()
                .expect("client task error state poisoned") = Some(format!("{error:#}"));
        }
        result
    });

    Ok(ClientSession {
        shutdown: Some(shutdown_tx),
        task: Some(task),
        route_manager: Some(route_manager),
        task_error,
        metrics,
        status: ClientStatus {
            assigned_ipv4,
            routes: config.routes,
        },
    })
}

impl ClientSession {
    pub fn is_finished(&self) -> bool {
        self.task
            .as_ref()
            .map(tokio::task::JoinHandle::is_finished)
            .unwrap_or(true)
    }

    pub fn failure_message(&self) -> Option<String> {
        self.task_error
            .lock()
            .expect("client task error state poisoned")
            .clone()
    }

    pub fn metrics(&self) -> ClientMetricsSnapshot {
        self.metrics.snapshot()
    }

    pub async fn disconnect(mut self) -> Result<()> {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
        let route_result = self
            .route_manager
            .take()
            .map(|route_manager| route_manager.remove())
            .unwrap_or(Ok(()));
        // A deliberate disconnect closes QUIC while the packet task may still be
        // waiting in read_datagram(). That expected transport error is not a
        // cleanup failure; route removal is the result that matters here.
        route_result
    }
}

impl Drop for ClientSession {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(route_manager) = self.route_manager.take() {
            let _ = route_manager.remove();
        }
    }
}

struct RouteManager {
    routes: Vec<Ipv4Net>,
    gateway: Ipv4Addr,
    interface_index: i32,
}

impl RouteManager {
    fn install(server: SocketAddr, routes: &[Ipv4Net], interface_index: i32) -> Result<Self> {
        match server.ip() {
            IpAddr::V4(_) => {}
            IpAddr::V6(_) => return Err(anyhow!("IPv6 server addresses are not supported")),
        }
        let gateway = Ipv4Addr::new(10, 88, 0, 1);
        let mut installed = Vec::new();
        for route in routes {
            if let Err(error) = add_windows_route(*route, gateway, interface_index) {
                for previous in installed {
                    let _ = remove_windows_route(previous, gateway, interface_index);
                }
                return Err(error);
            }
            installed.push(*route);
        }
        Ok(Self {
            routes: routes.to_vec(),
            gateway,
            interface_index,
        })
    }

    fn remove(&self) -> Result<()> {
        let mut first_error = None;
        for route in &self.routes {
            if let Err(error) = remove_windows_route(*route, self.gateway, self.interface_index) {
                first_error.get_or_insert(error);
            }
        }
        first_error.map_or(Ok(()), Err)
    }
}

#[cfg(windows)]
fn add_windows_route(route: Ipv4Net, gateway: Ipv4Addr, interface_index: i32) -> Result<()> {
    let output = std::process::Command::new("route")
        .args([
            "ADD",
            &route.network().to_string(),
            "MASK",
            &route.netmask().to_string(),
            &gateway.to_string(),
            "METRIC",
            "1",
            "IF",
            &interface_index.to_string(),
        ])
        .output()
        .context("starting route.exe")?;
    if !output.status.success() {
        return Err(anyhow!(
            "route.exe could not add {} through interface {}: {}",
            route,
            interface_index,
            command_output(&output)
        ));
    }
    Ok(())
}

#[cfg(not(windows))]
fn add_windows_route(_route: Ipv4Net, _gateway: Ipv4Addr, _interface_index: i32) -> Result<()> {
    Err(anyhow!(
        "the client route manager currently supports Windows only"
    ))
}

#[cfg(windows)]
fn remove_windows_route(route: Ipv4Net, gateway: Ipv4Addr, interface_index: i32) -> Result<()> {
    let _ = gateway;
    let output = std::process::Command::new("route")
        .args([
            "DELETE",
            &route.network().to_string(),
            "MASK",
            &route.netmask().to_string(),
            "IF",
            &interface_index.to_string(),
        ])
        .output()
        .context("starting route.exe")?;
    if !output.status.success() {
        return Err(anyhow!(
            "route.exe could not remove {} through interface {}: {}",
            route,
            interface_index,
            command_output(&output)
        ));
    }
    Ok(())
}

#[cfg(not(windows))]
fn remove_windows_route(_route: Ipv4Net, _gateway: Ipv4Addr, _interface_index: i32) -> Result<()> {
    Ok(())
}

#[cfg(windows)]
fn command_output(output: &std::process::Output) -> String {
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
    if !stderr.is_empty() {
        return stderr;
    }
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    if !stdout.is_empty() {
        return stdout;
    }
    format!("exit status {}", output.status)
}

fn create_tun(
    name: &str,
    address: Ipv4Addr,
    prefix_len: u8,
    peer: Ipv4Addr,
) -> Result<AsyncDevice> {
    let mut config = tun::Configuration::default();
    let netmask = prefix_to_netmask(prefix_len)?;
    config
        .tun_name(name)
        .address(address)
        .netmask(netmask)
        .destination(peer)
        .mtu(TUN_MTU)
        .up();
    #[cfg(target_os = "windows")]
    {
        let wintun_path = locate_wintun_dll()?;
        config.platform_config(|platform| platform.wintun_file(wintun_path));
    }
    #[cfg(target_os = "linux")]
    config.platform_config(|platform| {
        platform.ensure_root_privileges(true);
    });
    create_as_async(&config).context("opening configured TUN device")
}

#[cfg(target_os = "windows")]
fn locate_wintun_dll() -> Result<std::path::PathBuf> {
    let executable = std::env::current_exe().context("locating Asira Router executable")?;
    let directory = executable
        .parent()
        .ok_or_else(|| anyhow!("Asira Router executable has no parent directory"))?;
    let candidates = [
        directory.join("wintun.dll"),
        directory.join("resources").join("wintun.dll"),
    ];
    candidates
        .into_iter()
        .find(|path| path.is_file())
        .ok_or_else(|| {
            anyhow!(
                "Wintun runtime is missing; reinstall Asira Router so wintun.dll is installed with the app"
            )
        })
}

fn prefix_to_netmask(prefix: u8) -> Result<Ipv4Addr> {
    if prefix > 32 {
        return Err(anyhow!("invalid IPv4 prefix length"));
    }
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    Ok(Ipv4Addr::from(mask))
}

fn auth_proof(connection: &Connection, passphrase: &str) -> Result<[u8; 32]> {
    let mut exporter = [0u8; 32];
    connection
        .export_keying_material(&mut exporter, AUTH_EXPORTER_LABEL, AUTH_EXPORTER_CONTEXT)
        .map_err(|error| anyhow!("deriving authentication channel binding: {error:?}"))?;

    let mut mac = HmacSha256::new_from_slice(passphrase.as_bytes())
        .map_err(|_| anyhow!("invalid authentication key"))?;
    mac.update(&exporter);
    let digest = mac.finalize().into_bytes();
    let mut proof = [0u8; 32];
    proof.copy_from_slice(&digest);
    Ok(proof)
}

fn verify_auth_proof(connection: &Connection, passphrase: &str, proof: &[u8; 32]) -> Result<bool> {
    let mut exporter = [0u8; 32];
    connection
        .export_keying_material(&mut exporter, AUTH_EXPORTER_LABEL, AUTH_EXPORTER_CONTEXT)
        .map_err(|error| anyhow!("deriving authentication channel binding: {error:?}"))?;

    let mut mac = HmacSha256::new_from_slice(passphrase.as_bytes())
        .map_err(|_| anyhow!("invalid authentication key"))?;
    mac.update(&exporter);
    Ok(mac.verify_slice(proof).is_ok())
}

async fn write_control_message<T: Serialize>(stream: &mut SendStream, message: &T) -> Result<()> {
    let encoded = encode_control_message(message).map_err(|err| anyhow!(err))?;
    tokio::io::AsyncWriteExt::write_all(stream, &encoded).await?;
    Ok(())
}

async fn read_control_message<T: serde::de::DeserializeOwned>(
    stream: &mut RecvStream,
) -> Result<T> {
    let mut length = [0u8; 4];
    tokio::io::AsyncReadExt::read_exact(stream, &mut length).await?;
    let size = u32::from_be_bytes(length) as usize;
    if size > asira_protocol::MAX_CONTROL_MESSAGE {
        return Err(anyhow!(ProtocolError::MessageTooLarge));
    }
    let mut body = vec![0u8; size];
    tokio::io::AsyncReadExt::read_exact(stream, &mut body).await?;
    let mut framed = Vec::with_capacity(4 + size);
    framed.extend_from_slice(&length);
    framed.extend_from_slice(&body);
    decode_control_message(&framed).map_err(|err| anyhow!(err))
}

fn make_server_endpoint(config: &ServerConfig) -> Result<Endpoint> {
    install_crypto_provider();
    let (cert_der, key_der) =
        load_or_create_certificate(&config.certificate_path, &config.key_path)?;
    let cert_chain = vec![CertificateDer::from(cert_der)];
    let key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(key_der));
    let mut server_config = quinn::ServerConfig::with_single_cert(cert_chain, key)?;
    server_config.transport_config(Arc::new(transport_config()));
    Ok(Endpoint::server(server_config, config.bind)?)
}

fn make_client_config() -> Result<quinn::ClientConfig> {
    install_crypto_provider();
    let crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
        .with_no_client_auth();
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(crypto)?;
    let mut client_config = quinn::ClientConfig::new(Arc::new(crypto));
    client_config.transport_config(Arc::new(transport_config()));
    Ok(client_config)
}

fn transport_config() -> quinn::TransportConfig {
    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_bidi_streams(1u32.into());
    transport.max_concurrent_uni_streams(0u32.into());
    transport.keep_alive_interval(Some(KEEP_ALIVE_INTERVAL));
    transport.datagram_receive_buffer_size(Some(1024 * 1024));
    transport.datagram_send_buffer_size(1024 * 1024);
    transport
}

fn install_crypto_provider() {
    // Quinn and other dependencies may enable more than one Rustls provider.
    // Select ring explicitly so a GUI command cannot panic while building TLS.
    let _ = rustls::crypto::ring::default_provider().install_default();
}

fn load_or_create_certificate(cert_path: &str, key_path: &str) -> Result<(Vec<u8>, Vec<u8>)> {
    if Path::new(cert_path).exists() && Path::new(key_path).exists() {
        let key = std::fs::read(key_path)?;
        restrict_private_key_permissions(Path::new(key_path))?;
        return Ok((std::fs::read(cert_path)?, key));
    }
    let certified = generate_simple_self_signed(vec!["asira-router".to_owned()])?;
    let cert = certified.cert.der().to_vec();
    let key = certified.key_pair.serialize_der();
    if let Some(parent) = Path::new(cert_path)
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent)?;
    }
    if let Some(parent) = Path::new(key_path)
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(cert_path, &cert)?;
    std::fs::write(key_path, &key)?;
    restrict_private_key_permissions(Path::new(key_path))?;
    Ok((cert, key))
}

fn restrict_private_key_permissions(_path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        let mut permissions = std::fs::metadata(_path)?.permissions();
        permissions.set_mode(0o600);
        std::fs::set_permissions(_path, permissions)?;
    }
    Ok(())
}

#[derive(Debug)]
struct SkipServerVerification;

impl ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, RustlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ED25519,
            SignatureScheme::RSA_PSS_SHA256,
        ]
    }
}

fn default_tun_name() -> String {
    "asira0".to_owned()
}

fn default_tun_address() -> Ipv4Addr {
    Ipv4Addr::new(10, 88, 0, 1)
}

fn default_cert_path() -> String {
    "/etc/asira-router/server.crt.der".to_owned()
}

fn default_key_path() -> String {
    "/etc/asira-router/server.key.der".to_owned()
}

#[cfg(test)]
mod tests {
    use super::make_client_config;

    #[test]
    fn client_crypto_provider_is_available() {
        make_client_config().expect("client TLS configuration should be constructible");
    }
}
