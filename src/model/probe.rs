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
    /// Failure distribution (count per failure kind).
    pub failure_counts: Vec<FailureCount>,
}
