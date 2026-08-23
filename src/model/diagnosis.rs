//! Diagnosis model: the output of the deterministic diagnostic engine.

use serde::Serialize;

/// How severe a diagnosis is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    /// Informational; no anomaly.
    Info,
    /// Minor anomaly.
    Low,
    /// Moderate anomaly.
    Medium,
    /// Significant anomaly.
    High,
}

/// How strongly observations support a diagnosis.
///
/// The engine must never claim `High` confidence from a single observation
/// type. Confidence accumulates only when multiple independent signals align.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Confidence {
    /// Not enough evidence to commit to any conclusion.
    Unknown,
    /// Weak, possibly coincidental support.
    Low,
    /// Several observations agree.
    Medium,
    /// Multiple independent observations strongly agree.
    High,
}

/// A high-level category a diagnosis belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagnosticCategory {
    /// All observed layers succeed.
    Healthy,
    /// DNS resolution failed or is inconsistent.
    Dns,
    /// IPv4 works while IPv6 fails (or vice versa).
    AddressFamily,
    /// Connectivity to some destination addresses fails.
    PartialConnectivity,
    /// All destination addresses fail identically.
    TotalConnectivityLoss,
    /// Intermittent / partial success over repeated attempts.
    Intermittent,
    /// TCP-layer failures.
    Tcp,
    /// TLS-layer failures.
    Tls,
    /// Serving certificate is expired or expiring soon.
    Certificate,
    /// HTTP/application-layer failures.
    Http,
    /// Failures appear only on the QUIC/UDP path.
    Quic,
    /// Possible network filtering / interference (conservative).
    PossibleNetworkFiltering,
    /// A diagnosis was attempted but no conclusion could be reached.
    Unknown,
}

/// A single corroborating observation referenced by a [`Diagnosis`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Evidence {
    /// Human-readable description of the observation.
    pub detail: String,
}

/// A single, deterministic diagnostic conclusion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Diagnosis {
    /// Severity of the anomaly.
    pub severity: Severity,
    /// Category of the diagnosis.
    pub category: DiagnosticCategory,
    /// How well the evidence supports this conclusion.
    pub confidence: Confidence,
    /// One-line summary.
    pub summary: String,
    /// Observations supporting the conclusion.
    pub evidence: Vec<Evidence>,
    /// Alternative explanations that remain consistent with the evidence.
    pub possible_causes: Vec<String>,
}
