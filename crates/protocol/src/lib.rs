use std::net::Ipv4Addr;

use ipnet::Ipv4Net;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use thiserror::Error;

pub const PROTOCOL_VERSION: u8 = 2;
pub const MAX_CONTROL_MESSAGE: usize = 16 * 1024;
pub const MAX_IPV4_PACKET: usize = 65_535;
pub const MAX_SELECTIVE_ROUTES: usize = 64;
pub const MIN_PASSPHRASE_LENGTH: usize = 16;
pub const MAX_PASSPHRASE_LENGTH: usize = 512;

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("control message is too large")]
    MessageTooLarge,
    #[error("control message has an invalid length")]
    InvalidMessageLength,
    #[error("control message is not valid JSON: {0}")]
    InvalidJson(#[from] serde_json::Error),
    #[error("packet is not a valid IPv4 packet")]
    InvalidIpv4Packet,
    #[error("route must be an IPv4 CIDR")]
    InvalidRoute,
    #[error("default route is not allowed")]
    DefaultRouteNotAllowed,
    #[error("overlapping routes are not allowed")]
    OverlappingRoutes,
    #[error("too many selective routes")]
    TooManyRoutes,
    #[error("passphrase length must be between 16 and 512 bytes")]
    InvalidPassphraseLength,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthRequest {
    pub version: u8,
    pub client_proof: [u8; 32],
    pub routes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthResponse {
    pub version: u8,
    pub accepted: bool,
    pub assigned_ipv4: Option<Ipv4Addr>,
    pub message: String,
}

pub fn encode_control_message<T: Serialize>(message: &T) -> Result<Vec<u8>, ProtocolError> {
    let body = serde_json::to_vec(message)?;
    if body.len() > MAX_CONTROL_MESSAGE {
        return Err(ProtocolError::MessageTooLarge);
    }

    let mut framed = Vec::with_capacity(4 + body.len());
    framed.extend_from_slice(&(body.len() as u32).to_be_bytes());
    framed.extend_from_slice(&body);
    Ok(framed)
}

pub fn decode_control_message<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, ProtocolError> {
    if bytes.len() < 4 {
        return Err(ProtocolError::InvalidMessageLength);
    }

    let declared = u32::from_be_bytes(bytes[..4].try_into().expect("length checked")) as usize;
    let framed_length = declared
        .checked_add(4)
        .ok_or(ProtocolError::InvalidMessageLength)?;
    if declared > MAX_CONTROL_MESSAGE || bytes.len() != framed_length {
        return Err(ProtocolError::InvalidMessageLength);
    }

    Ok(serde_json::from_slice(&bytes[4..])?)
}

pub fn validate_ipv4_packet(packet: &[u8]) -> Result<(Ipv4Addr, Ipv4Addr), ProtocolError> {
    if packet.len() < 20 || packet.len() > MAX_IPV4_PACKET {
        return Err(ProtocolError::InvalidIpv4Packet);
    }

    let version = packet[0] >> 4;
    let ihl = (packet[0] & 0x0f) as usize * 4;
    if version != 4 || ihl < 20 || ihl > packet.len() {
        return Err(ProtocolError::InvalidIpv4Packet);
    }

    let total_length = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    if total_length < ihl || total_length != packet.len() {
        return Err(ProtocolError::InvalidIpv4Packet);
    }

    let source = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
    let destination = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    Ok((source, destination))
}

pub fn parse_selective_routes(input: &str) -> Result<Vec<Ipv4Net>, ProtocolError> {
    let mut routes: Vec<Ipv4Net> = Vec::new();

    for raw in input.lines().map(str::trim).filter(|line| !line.is_empty()) {
        if routes.len() >= MAX_SELECTIVE_ROUTES {
            return Err(ProtocolError::TooManyRoutes);
        }
        let route: Ipv4Net = raw.parse().map_err(|_| ProtocolError::InvalidRoute)?;
        if route.prefix_len() == 0 {
            return Err(ProtocolError::DefaultRouteNotAllowed);
        }
        if routes.iter().any(|existing| {
            existing.contains(&route.network()) || route.contains(&existing.network())
        }) {
            return Err(ProtocolError::OverlappingRoutes);
        }
        routes.push(route);
    }

    if routes.is_empty() {
        return Err(ProtocolError::InvalidRoute);
    }

    Ok(routes)
}

pub fn validate_passphrase(passphrase: &str) -> Result<(), ProtocolError> {
    let length = passphrase.len();
    if !(MIN_PASSPHRASE_LENGTH..=MAX_PASSPHRASE_LENGTH).contains(&length) {
        return Err(ProtocolError::InvalidPassphraseLength);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_message_round_trips() {
        let request = AuthRequest {
            version: PROTOCOL_VERSION,
            client_proof: [7; 32],
            routes: vec!["198.51.100.0/24".to_owned()],
        };
        let encoded = encode_control_message(&request).unwrap();
        let decoded: AuthRequest = decode_control_message(&encoded).unwrap();
        assert_eq!(decoded.client_proof, [7; 32]);
        assert_eq!(decoded.routes, vec!["198.51.100.0/24"]);
    }

    #[test]
    fn ipv4_header_is_validated() {
        let packet = [
            0x45, 0, 0, 20, 0, 0, 0, 0, 64, 17, 0, 0, 10, 0, 0, 2, 1, 1, 1, 1,
        ];
        assert_eq!(
            validate_ipv4_packet(&packet).unwrap(),
            (Ipv4Addr::new(10, 0, 0, 2), Ipv4Addr::new(1, 1, 1, 1))
        );
    }

    #[test]
    fn ipv4_trailing_bytes_are_rejected() {
        let mut packet = vec![
            0x45, 0, 0, 20, 0, 0, 0, 0, 64, 17, 0, 0, 10, 0, 0, 2, 1, 1, 1, 1,
        ];
        packet.push(0);
        assert!(matches!(
            validate_ipv4_packet(&packet),
            Err(ProtocolError::InvalidIpv4Packet)
        ));
    }

    #[test]
    fn default_route_is_rejected() {
        assert!(matches!(
            parse_selective_routes("0.0.0.0/0"),
            Err(ProtocolError::DefaultRouteNotAllowed)
        ));
    }

    #[test]
    fn overlapping_routes_are_rejected() {
        assert!(matches!(
            parse_selective_routes("198.51.100.0/24\n198.51.100.0/25"),
            Err(ProtocolError::OverlappingRoutes)
        ));
    }

    #[test]
    fn route_count_is_bounded() {
        let routes = (0..=MAX_SELECTIVE_ROUTES)
            .map(|octet| format!("198.51.{octet}.0/24"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(matches!(
            parse_selective_routes(&routes),
            Err(ProtocolError::TooManyRoutes)
        ));
    }

    #[test]
    fn weak_passphrases_are_rejected() {
        assert!(matches!(
            validate_passphrase("too-short"),
            Err(ProtocolError::InvalidPassphraseLength)
        ));
        assert!(validate_passphrase("a-secure-passphrase").is_ok());
    }
}
