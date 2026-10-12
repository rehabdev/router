use std::{
    collections::{hash_map::Entry, HashMap},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::Path,
    sync::{Arc, Mutex},
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
use tun::{create_as_async, AsyncDevice, TunPacketCodec};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

const TUN_MTU: u16 = 1400;
const TUN_NETWORK: Ipv4Net = Ipv4Net::new_assert(Ipv4Addr::new(10, 88, 0, 0), 24);
const FIRST_CLIENT_HOST: u8 = 2;
const AUTH_TIMEOUT: Duration = Duration::from_secs(10);
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
    pub status: ClientStatus,
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
                let _ = connection.send_datagram(Bytes::from(packet));
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
    let connection = endpoint
        .connect(config.server, "asira-router")?
        .await
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
    let (tun_writer, tun_reader) = tun.split().context("splitting client TUN device")?;
    let mut tun_reader = FramedRead::new(tun_reader, TunPacketCodec::new(TUN_MTU as usize));
    let mut tun_writer = FramedWrite::new(tun_writer, TunPacketCodec::new(TUN_MTU as usize));

    let route_manager = RouteManager::install(config.server, &config.routes)?;
    let (shutdown_tx, mut shutdown_rx) = oneshot::channel();
    let connection_for_task = connection.clone();
    let allowed_routes = config.routes.clone();
    let task = tokio::spawn(async move {
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
                        return Err(anyhow!("client TUN produced a packet outside its assigned source or route policy"));
                    }
                    connection_for_task.send_datagram(Bytes::from(packet)).context("sending QUIC datagram")?;
                }
                packet = connection_for_task.read_datagram() => {
                    let packet = packet.context("reading QUIC datagram")?;
                    if packet.len() > TUN_MTU as usize {
                        return Err(anyhow!("server sent a packet larger than the tunnel MTU"));
                    }
                    validate_ipv4_packet(&packet).map_err(|err| anyhow!(err))?;
                    tun_writer.send(packet.to_vec()).await.context("writing packet to client TUN device")?;
                }
            }
        }
    });

    Ok(ClientSession {
        shutdown: Some(shutdown_tx),
        task: Some(task),
        route_manager: Some(route_manager),
        status: ClientStatus {
            assigned_ipv4,
            routes: config.routes,
        },
    })
}

impl ClientSession {
    pub async fn disconnect(mut self) -> Result<()> {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        let task_result = if let Some(task) = self.task.take() {
            task.await.context("waiting for client tunnel shutdown")?
        } else {
            Ok(())
        };
        let route_result = self
            .route_manager
            .take()
            .map(|route_manager| route_manager.remove())
            .unwrap_or(Ok(()));
        task_result?;
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
}

impl RouteManager {
    fn install(server: SocketAddr, routes: &[Ipv4Net]) -> Result<Self> {
        match server.ip() {
            IpAddr::V4(_) => {}
            IpAddr::V6(_) => return Err(anyhow!("IPv6 server addresses are not supported")),
        }
        let gateway = Ipv4Addr::new(10, 88, 0, 1);
        let mut installed = Vec::new();
        for route in routes {
            if let Err(error) = add_windows_route(*route, gateway) {
                for previous in installed {
                    let _ = remove_windows_route(previous, gateway);
                }
                return Err(error);
            }
            installed.push(*route);
        }
        Ok(Self {
            routes: routes.to_vec(),
            gateway,
        })
    }

    fn remove(&self) -> Result<()> {
        let mut first_error = None;
        for route in &self.routes {
            if let Err(error) = remove_windows_route(*route, self.gateway) {
                first_error.get_or_insert(error);
            }
        }
        first_error.map_or(Ok(()), Err)
    }
}

#[cfg(windows)]
fn add_windows_route(route: Ipv4Net, gateway: Ipv4Addr) -> Result<()> {
    let output = std::process::Command::new("route")
        .args([
            "ADD",
            &route.network().to_string(),
            "MASK",
            &route.netmask().to_string(),
            &gateway.to_string(),
        ])
        .output()
        .context("starting route.exe")?;
    if !output.status.success() {
        return Err(anyhow!("route.exe could not add {}", route));
    }
    Ok(())
}

#[cfg(not(windows))]
fn add_windows_route(_route: Ipv4Net, _gateway: Ipv4Addr) -> Result<()> {
    Err(anyhow!(
        "the client route manager currently supports Windows only"
    ))
}

#[cfg(windows)]
fn remove_windows_route(route: Ipv4Net, gateway: Ipv4Addr) -> Result<()> {
    let _ = gateway;
    let output = std::process::Command::new("route")
        .args([
            "DELETE",
            &route.network().to_string(),
            "MASK",
            &route.netmask().to_string(),
        ])
        .output()
        .context("starting route.exe")?;
    if !output.status.success() {
        return Err(anyhow!("route.exe could not remove {}", route));
    }
    Ok(())
}

#[cfg(not(windows))]
fn remove_windows_route(_route: Ipv4Net, _gateway: Ipv4Addr) -> Result<()> {
    Ok(())
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
    #[cfg(target_os = "linux")]
    config.platform_config(|platform| {
        platform.ensure_root_privileges(true);
    });
    create_as_async(&config).map_err(Into::into)
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
    let (cert_der, key_der) =
        load_or_create_certificate(&config.certificate_path, &config.key_path)?;
    let cert_chain = vec![CertificateDer::from(cert_der)];
    let key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(key_der));
    let mut server_config = quinn::ServerConfig::with_single_cert(cert_chain, key)?;
    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_bidi_streams(1u32.into());
    transport.max_concurrent_uni_streams(0u32.into());
    transport.datagram_receive_buffer_size(Some(1024 * 1024));
    transport.datagram_send_buffer_size(1024 * 1024);
    server_config.transport_config(Arc::new(transport));
    Ok(Endpoint::server(server_config, config.bind)?)
}

fn make_client_config() -> Result<quinn::ClientConfig> {
    let crypto = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
        .with_no_client_auth();
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(crypto)?;
    Ok(quinn::ClientConfig::new(Arc::new(crypto)))
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
