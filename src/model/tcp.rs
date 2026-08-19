//! TCP observation types.

use std::net::SocketAddr;

/// A single TCP connect attempt to one destination socket address.
///
/// `latency_ms` is the time to establish the connection (including the SYN
/// handshake) on success. `failure` carries the classified failure mode and
/// a human message; it is `None` when `success` is true.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct TcpObservation {
    /// Destination socket address probed.
    pub destination: SocketAddr,
    /// Whether the TCP connection was established.
    pub success: bool,
    /// Connect latency in milliseconds on success.
    pub latency_ms: Option<u64>,
    /// Classified failure mode and context, when not successful.
    pub failure: Option<super::ProbeError>,
}
