//! Error types for the network diagnostics toolkit.
//!
//! Every error preserves context: the operation, the destination, the
//! protocol layer and (where available) the underlying cause.

use std::net::SocketAddr;
use thiserror::Error;

/// Top-level error for ip-tools diagnostic operations.
///
/// Variants are grouped by protocol layer so that callers can map a failure
/// to the layer at which it occurred. `source()` reports the underlying error
/// where one exists.
#[derive(Debug, Error)]
pub enum DiagError {
    /// DNS resolution failed.
    #[error("dns lookup of {hostname} ({kind}) failed: {source}")]
    Dns {
        /// The hostname being resolved.
        hostname: String,
        /// Human-readable record type description, e.g. `A` or `AAAA`.
        kind: &'static str,
        /// Underlying resolver error.
        source: hickory_resolver::ResolveError,
    },

    /// DNS client construction failed (e.g. the system resolver config could
    /// not be read).
    #[error("failed to construct DNS client: {0}")]
    DnsClient(String),

    /// TCP connect to a destination failed.
    #[error("tcp connect to {destination} failed: {source}")]
    Tcp {
        /// Destination socket address.
        destination: SocketAddr,
        /// Underlying I/O error.
        source: std::io::Error,
    },

    /// A network operation timed out.
    #[error("{operation} to {destination} timed out after {timeout:?}")]
    Timeout {
        /// Operation that timed out (e.g. `tcp connect`).
        operation: &'static str,
        /// Destination involved.
        destination: String,
        /// Configured timeout.
        timeout: std::time::Duration,
    },

    /// Invalid target string provided on the CLI.
    #[error("invalid target {input:?}: {reason}")]
    InvalidTarget {
        /// The invalid input as written.
        input: String,
        /// Why it is invalid.
        reason: String,
    },

    /// A CLI/query configuration error (not a network failure).
    #[error("{0}")]
    Config(String),
}

pub(crate) type Result<T> = std::result::Result<T, DiagError>;
