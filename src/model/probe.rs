//! Repeated-probe result types.

use std::net::SocketAddr;

use super::latency::LatencySummary;
use super::FailureKind;

/// A single failure-mode count within a repeated probe.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct FailureCount {
    /// The classified failure mode.
    pub kind: FailureKind,
    /// Number of attempts that failed this way.
    pub count: usize,
}

/// A single HTTP status-code count within a repeated HTTP probe.
///
/// Present only for the HTTP repeat probes (`http`/`http2`/`http3`); the
/// transport-repeat probes (`tcp`/`tls`) have an empty list. Surfacing the
/// observed statuses is what lets a repeat probe reveal status flapping
/// (e.g. `200` on most attempts but `503` occasionally), independently of the
/// transport-success semantics (a completed response with any status counts as
/// a successful exchange).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct StatusCount {
    /// The HTTP response status code observed.
    pub status: u16,
    /// How many attempts returned that status.
    pub count: usize,
}

/// Aggregated result of repeatedly probing one destination socket address.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ProbeResult {
    /// Destination socket address probed.
    pub destination: SocketAddr,
    /// Total attempts.
    pub attempts: usize,
    /// Successful attempts.
    pub successes: usize,
    /// Failed attempts.
    pub failures: usize,
    /// Success rate in `0.0..=1.0`.
    pub success_rate: f64,
    /// Latency statistics over the successful attempts.
    pub latency: LatencySummary,
    /// Time-to-first-byte statistics over the successful HTTP attempts (the
    /// server-response latency: request sent → response headers arrived).
    /// Only the HTTP repeat probes (`http`/`http2`/`http3`) populate it; the
    /// transport-repeat probes (`tcp`/`tls`) leave it empty.
    pub ttfb: LatencySummary,
    /// Failure distribution (count per failure kind).
    pub failure_counts: Vec<FailureCount>,
    /// HTTP status-code distribution over the attempts (empty for the
    /// `tcp`/`tls` transport-repeat probes).
    pub status_counts: Vec<StatusCount>,
}
