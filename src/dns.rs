//! DNS diagnostics: resolve A / AAAA records via the system resolver and/or
//! explicitly configured DNS servers.
//!
//! Resolver disagreement (different addresses from different resolvers) is
//! *reported*, never automatically classified as poisoning — the diagnostic
//! engine decides and considers GeoDNS/CDN/ECS/etc. as alternatives.

use crate::model::{DnsObservation, DnsRecordType, FailureKind, ProbeError, ResolverKind};
use hickory_resolver::config::{ConnectionConfig, NameServerConfig, ProtocolConfig, ResolverConfig, ResolverOpts};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::proto::rr::RData;
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
    #[must_use]
    pub fn new(custom_servers: &[SocketAddr], timeout: Duration, attempts: usize) -> Self {
        let apply_options = |out: &mut ResolverOpts| {
            out.timeout = timeout;
            out.attempts = attempts.max(1);
        };

        // hickory 0.26 surfaces failures while building resolvers (e.g. the
        // system config is unreadable) as `Result`s; a resolver that cannot be
        // built is skipped rather than turning every query into an error.
        let system = TokioResolver::builder_tokio().ok().and_then(|mut b| {
            apply_options(b.options_mut());
            b.build().ok()
        });

        let mut custom = HashMap::with_capacity(custom_servers.len());
        for &server in custom_servers {
            let config = ResolverConfig::from_parts(None, Vec::new(), vec![name_server_config(server)]);
            let mut resolver = TokioResolver::builder_with_config(config, TokioRuntimeProvider::default());
            apply_options(resolver.options_mut());
            if let Ok(resolver) = resolver.build() {
                custom.insert(server, resolver);
            }
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

/// Build a [`NameServerConfig`] for `server` speaking UDP and TCP.
///
/// hickory 0.26 keeps `ConnectionConfig::port` public but declares the struct
/// `#[non_exhaustive]`, so a non-default port cannot be expressed with a struct
/// literal: the provided constructors all fix the protocol's default port (53).
/// For other ports the config is therefore round-tripped through the crate's
/// own serde schema (the port field is patchable there).
fn name_server_config(server: SocketAddr) -> NameServerConfig {
    let ip = server.ip();
    let port = server.port();
    let connection = |protocol: ProtocolConfig| -> ConnectionConfig {
        if port == 53 {
            ConnectionConfig::new(protocol)
        } else {
            let mut cfg =
                serde_json::to_value(ConnectionConfig::new(protocol)).expect("predefined DNS config serializes");
            cfg["port"] = serde_json::json!(port);
            serde_json::from_value(cfg).expect("predefined DNS config deserializes")
        }
    };
    NameServerConfig::new(
        ip,
        true,
        vec![connection(ProtocolConfig::Udp), connection(ProtocolConfig::Tcp)],
    )
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
                message: format!("dns lookup of {host} ({record_type}) timed out after {timeout:?}"),
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
) -> Result<Vec<IpAddr>, hickory_resolver::net::NetError> {
    let lookup = match record_type {
        DnsRecordType::A => resolver.ipv4_lookup(host).await?,
        DnsRecordType::Aaaa => resolver.ipv6_lookup(host).await?,
    };
    Ok(lookup
        .answers()
        .iter()
        .filter_map(|rec| match rec.data {
            RData::A(ip) => Some(IpAddr::from(*ip)),
            RData::AAAA(ip) => Some(IpAddr::from(*ip)),
            _ => None,
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::UdpSocket;
    use std::sync::Arc;

    /// A minimal in-process DNS server that answers A / AAAA queries from the
    /// given address sets. Deterministic: no external network involved.
    struct FakeDns {
        addr: SocketAddr,
    }

    impl FakeDns {
        fn start(ipv4: &[&str], ipv6: &[&str]) -> Self {
            let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").expect("bind fake dns server"));
            let addr = sock.local_addr().expect("fake dns local addr");
            let ipv4: Vec<IpAddr> = ipv4.iter().map(|a| a.parse().unwrap()).collect();
            let ipv6: Vec<IpAddr> = ipv6.iter().map(|a| a.parse().unwrap()).collect();
            std::thread::spawn(move || {
                let mut buf = [0u8; 512];
                while let Ok((n, peer)) = sock.recv_from(&mut buf) {
                    if let Some(resp) = fake_dns_response(&buf[..n], &ipv4, &ipv6) {
                        let _ = sock.send_to(&resp, peer);
                    }
                }
            });
            Self { addr }
        }

        fn addr(&self) -> SocketAddr {
            self.addr
        }
    }

    /// Build a standard DNS response for one query, returning addresses of the
    /// query's own record type (A or AAAA); anything else gets no answers.
    fn fake_dns_response(query: &[u8], ipv4: &[IpAddr], ipv6: &[IpAddr]) -> Option<Vec<u8>> {
        if query.len() < 12 {
            return None;
        }
        let id = [query[0], query[1]];
        let qdcount = u16::from_be_bytes([query[4], query[5]]);
        if qdcount == 0 {
            return None;
        }
        // Parse the question: variable-length name, then fixed 4 bytes
        // (qtype + qclass). The whole question is echoed verbatim.
        let mut pos = 12;
        loop {
            let len = *query.get(pos)? as usize;
            pos += 1;
            if len == 0 {
                break;
            }
            if len > 63 {
                return None; // no compression in the query
            }
            pos += len;
        }
        let question = &query[12..pos + 4];
        let qtype = u16::from_be_bytes([query[pos], query[pos + 1]]);

        let answers: Vec<IpAddr> = match qtype {
            1 => ipv4.to_vec(),  // A
            28 => ipv6.to_vec(), // AAAA
            _ => Vec::new(),
        };

        let mut out = Vec::with_capacity(512);
        out.extend_from_slice(&id);
        out.extend_from_slice(&0x8180u16.to_be_bytes()); // QR|RD|RA, NOERROR
        out.extend_from_slice(&qdcount.to_be_bytes());
        out.extend_from_slice(&(answers.len() as u16).to_be_bytes()); // ANCOUNT
        out.extend_from_slice(&[0, 0, 0, 0]); // NSCOUNT, ARCOUNT
        out.extend_from_slice(question);
        for ip in &answers {
            out.extend_from_slice(&[0xC0, 0x0C]); // name pointer -> question name
            let type_code: u16 = if ip.is_ipv4() { 1 } else { 28 };
            let rdlen: u16 = if ip.is_ipv4() { 4 } else { 16 };
            out.extend_from_slice(&type_code.to_be_bytes());
            out.extend_from_slice(&[0, 1]); // class IN
            out.extend_from_slice(&60u32.to_be_bytes()); // TTL
            out.extend_from_slice(&rdlen.to_be_bytes());
            match ip {
                IpAddr::V4(v4) => out.extend_from_slice(&v4.octets()),
                IpAddr::V6(v6) => out.extend_from_slice(&v6.octets()),
            }
        }
        Some(out)
    }

    fn custom(servers: &[SocketAddr], timeout: Duration) -> DnsClient {
        DnsClient::new(servers, timeout, 1)
    }

    #[tokio::test]
    async fn resolves_a_records_from_custom_server() {
        let fake = FakeDns::start(&["192.0.2.1", "192.0.2.2"], &[]);
        let client = custom(&[fake.addr()], Duration::from_secs(2));
        let obs = client.resolve("host.example", DnsRecordType::A).await;
        let o = obs
            .iter()
            .find(|o| o.resolver == ResolverKind::Custom(fake.addr()))
            .expect("custom resolver observation");
        assert!(o.error.is_none(), "unexpected error: {:?}", o.error);
        let expected: Vec<IpAddr> = vec!["192.0.2.1".parse().unwrap(), "192.0.2.2".parse().unwrap()];
        assert_eq!(o.records, expected);
        assert!(o.latency_ms.is_some());
        assert_eq!(o.record_type, DnsRecordType::A);
    }

    #[tokio::test]
    async fn resolves_aaaa_records_from_custom_server() {
        let fake = FakeDns::start(&[], &["2001:db8::1"]);
        let client = custom(&[fake.addr()], Duration::from_secs(2));
        let obs = client.resolve("host.example", DnsRecordType::Aaaa).await;
        let o = obs
            .iter()
            .find(|o| o.resolver == ResolverKind::Custom(fake.addr()))
            .expect("custom resolver observation");
        assert!(o.error.is_none(), "unexpected error: {:?}", o.error);
        assert_eq!(o.records, vec!["2001:db8::1".parse::<IpAddr>().unwrap()]);
        assert_eq!(o.record_type, DnsRecordType::Aaaa);
    }

    #[tokio::test]
    async fn unreachable_custom_server_yields_timeout_observation() {
        // Reserve an ephemeral port, then drop the socket so nothing listens.
        let port = {
            let s = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind probe port");
            s.local_addr().expect("probe local addr").port()
        };
        let addr = SocketAddr::from(([127, 0, 0, 1], port));
        let client = custom(&[addr], Duration::from_millis(300));
        let obs = client.resolve("host.example", DnsRecordType::A).await;
        let o = obs
            .iter()
            .find(|o| o.resolver == ResolverKind::Custom(addr))
            .expect("custom resolver observation");
        assert!(o.records.is_empty());
        // The observation must be a failure; the exact kind is hickory's (a
        // Timeout on Linux, a Dns "no connections available" error on Windows
        // where the UDP connect fails immediately).
        let err = o.error.as_ref().expect("expected a failure observation");
        assert!(
            matches!(err.kind, FailureKind::Timeout | FailureKind::Dns),
            "got unexpected failure kind: {err:?}"
        );
        assert!(o.latency_ms.is_none());
    }
}
