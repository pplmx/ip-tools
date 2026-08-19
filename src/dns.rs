//! DNS diagnostics: resolve A / AAAA records via the system resolver and/or
//! explicitly configured DNS servers.
//!
//! Resolver disagreement (different addresses from different resolvers) is
//! *reported*, never automatically classified as poisoning — the diagnostic
//! engine decides and considers GeoDNS/CDN/ECS/etc. as alternatives.

use crate::model::{DnsObservation, DnsRecordType, FailureKind, ProbeError, ResolverKind};
use hickory_resolver::config::{NameServerConfigGroup, ResolverConfig, ResolverOpts};
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::TokioResolver;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

/// A set of DNS resolvers to query.
///
/// Owns one configured resolver per source (the system resolver plus any
/// custom DNS servers). Building resolvers is synchronous; only the actual
/// queries are async.
#[derive(Clone)]
pub struct DnsClient {
    /// System-configured resolver, when it could be constructed.
    system: Option<TokioResolver>,
    /// Custom resolvers keyed by their socket address.
    custom: HashMap<SocketAddr, TokioResolver>,
    /// Per-attempt timeout applied as a hard wall-clock bound.
    timeout: Duration,
}

impl DnsClient {
    /// Build a client using the system resolver plus the given custom servers.
    ///
    /// `timeout` bounds each individual lookup (including across retries).
    /// `attempts` is the per-query retry count used internally.
    pub fn new(custom_servers: &[SocketAddr], timeout: Duration, attempts: usize) -> Self {
        let apply_options = |out: &mut ResolverOpts| {
            out.timeout = timeout;
            out.attempts = attempts.max(1);
        };

        let system = TokioResolver::builder_tokio()
            .map(|mut b| {
                apply_options(b.options_mut());
                b.build()
            })
            .ok();

        let mut custom = HashMap::with_capacity(custom_servers.len());
        for &server in custom_servers {
            let group = NameServerConfigGroup::from_ips_clear(std::slice::from_ref(&server.ip()), server.port(), true);
            let config = ResolverConfig::from_parts(None, Vec::new(), group);
            let mut resolver = TokioResolver::builder_with_config(config, TokioConnectionProvider::default());
            apply_options(resolver.options_mut());
            custom.insert(server, resolver.build());
        }

        Self {
            system,
            custom,
            timeout,
        }
    }

    /// Resolve `host` for `record_type` against every configured resolver.
    ///
    /// Queries are issued concurrently (bounded by the number of resolvers)
    /// and each is bounded by the configured timeout.
    pub async fn resolve(&self, host: &str, record_type: DnsRecordType) -> Vec<DnsObservation> {
        let mut tasks = tokio::task::JoinSet::new();
        if let Some(resolver) = &self.system {
            tasks.spawn(query(
                resolver.clone(),
                self.timeout,
                ResolverKind::System,
                host.to_string(),
                record_type,
            ));
        }
        for (&server, resolver) in &self.custom {
            tasks.spawn(query(
                resolver.clone(),
                self.timeout,
                ResolverKind::Custom(server),
                host.to_string(),
                record_type,
            ));
        }

        let mut results = Vec::with_capacity(tasks.len());
        while let Some(res) = tasks.join_next().await {
            if let Ok(obs) = res {
                results.push(obs);
            }
        }
        results
    }
}

/// Perform a single bounded DNS query and build its observation.
async fn query(
    resolver: TokioResolver,
    timeout: Duration,
    kind: ResolverKind,
    host: String,
    record_type: DnsRecordType,
) -> DnsObservation {
    let start = Instant::now();
    let outcome = tokio::time::timeout(timeout, resolver_ip_lookup(&resolver, &host, record_type)).await;

    let (latency_ms, records, error) = match outcome {
        Ok(Ok(records)) => (Some(start.elapsed().as_millis() as u64), records, None),
        Ok(Err(e)) => (
            None,
            Vec::new(),
            Some(ProbeError {
                kind: FailureKind::Dns,
                message: e.to_string(),
            }),
        ),
        Err(_elapsed) => (
            None,
            Vec::new(),
            Some(ProbeError {
                kind: FailureKind::Timeout,
                message: format!("dns lookup of {} ({}) timed out after {:?}", host, record_type, timeout),
            }),
        ),
    };

    DnsObservation {
        hostname: host,
        resolver: kind,
        record_type,
        latency_ms,
        records,
        error,
    }
}

/// Perform the record-type-specific hickory IP lookup, yielding the resolved
/// addresses (independent of record type).
async fn resolver_ip_lookup(
    resolver: &TokioResolver,
    host: &str,
    record_type: DnsRecordType,
) -> Result<Vec<IpAddr>, hickory_resolver::ResolveError> {
    match record_type {
        DnsRecordType::A => resolver
            .ipv4_lookup(host)
            .await
            .map(|l| l.into_iter().map(|a| IpAddr::from(a.0)).collect()),
        DnsRecordType::Aaaa => resolver
            .ipv6_lookup(host)
            .await
            .map(|l| l.into_iter().map(|a| IpAddr::from(a.0)).collect()),
    }
}
