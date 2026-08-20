//! DNS diagnostics: resolve A / AAAA records via the system resolver and/or
//! explicitly configured DNS servers, and optionally DNS-over-HTTPS
//! (RFC 8484) endpoints.
//!
//! Resolver disagreement (different addresses from different resolvers) is
//! *reported*, never automatically classified as poisoning — the diagnostic
//! engine decides and considers GeoDNS/CDN/ECS/etc. as alternatives.

use crate::model::{DnsObservation, DnsRecordType, FailureKind, ProbeError, ResolverKind};
use hickory_resolver::config::{ConnectionConfig, NameServerConfig, ProtocolConfig, ResolverConfig, ResolverOpts};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::proto::rr::RData;
use hickory_resolver::TokioResolver;
use http_body_util::{BodyExt, Empty, Limited};
use hyper_util::rt::TokioIo;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
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

// --- DNS-over-HTTPS (RFC 8484) ------------------------------------------------

/// Maximum response body a `DoH` endpoint is allowed to return.
const DOH_MAX_BODY: usize = 64 * 1024;

/// Query a `DNS`-over-HTTPS endpoint for `host`/`record_type` over a
/// `TLS`-wrapped `HTTP/1.1` request and build a [`DnsObservation`].
///
/// `endpoint` is an `https://` URL like `https://cloudflare-dns.com/dns-query`;
/// `insecure` skips certificate validation (needed for `IP`-literal endpoints
/// whose cert is issued to the hostname, e.g. `https://1.1.1.1/dns-query`).
#[must_use]
// Sequential probe pipeline (TLS -> HTTP -> body -> parse) is clearer inline.
#[allow(clippy::too_many_lines)]
pub async fn doh_query(
    endpoint: &str,
    host: &str,
    record_type: DnsRecordType,
    timeout: Duration,
    insecure: bool,
) -> DnsObservation {
    let start = Instant::now();
    let step = |kind: FailureKind, message: String| ProbeError { kind, message };
    let base = DnsObservation {
        hostname: host.to_string(),
        resolver: ResolverKind::Doh(endpoint.to_string()),
        record_type,
        records: Vec::new(),
        latency_ms: None,
        error: None,
    };
    let fail = |kind, message| DnsObservation {
        error: Some(step(kind, message)),
        ..base.clone()
    };

    let (ehost, eport, path) = match parse_doh_url(endpoint) {
        Ok(p) => p,
        Err(msg) => return fail(FailureKind::Other, msg),
    };
    let ip = match resolve_doh_host(&ehost, timeout).await {
        Ok(ip) => ip,
        Err(msg) => return fail(FailureKind::Dns, msg),
    };
    let query = match build_query(host, record_type) {
        Ok(q) => q,
        Err(msg) => return fail(FailureKind::Protocol, msg),
    };

    // TLS handshake to the endpoint (its hostname as SNI), then one HTTP/1.1
    // GET whose body is the DNS wire-format response.
    let roots = crate::tls::roots();
    let mode = if insecure {
        crate::tls::TlsMode::Insecure
    } else {
        crate::tls::TlsMode::Roots(&roots)
    };
    let conn = match crate::tls::connect_to(
        SocketAddr::new(ip, eport),
        &ehost,
        crate::tls::ALPN_HTTP1,
        timeout,
        mode,
    )
    .await
    {
        Ok(c) => c,
        Err(f) => return DnsObservation { error: Some(f), ..base },
    };

    let handshake = hyper::client::conn::http1::handshake(TokioIo::new(conn.stream));
    let (mut sender, connection) = match tokio::time::timeout(timeout, handshake).await {
        Ok(Ok(pair)) => pair,
        Ok(Err(e)) => {
            return fail(
                FailureKind::Dns,
                format!("http/1.1 handshake with DoH endpoint failed: {e}"),
            )
        }
        Err(_) => {
            return fail(
                FailureKind::Timeout,
                format!("DoH handshake to {endpoint} timed out after {timeout:?}"),
            )
        }
    };
    tokio::spawn(async move {
        let _ = connection.await;
    });

    let uri = format!("{path}?dns={}", base64url(&query));
    let request = match hyper::Request::builder()
        .method("GET")
        .uri(uri)
        .header("host", &ehost)
        .header("accept", "application/dns-message")
        .header("user-agent", "ip-tools")
        .body(Empty::<hyper::body::Bytes>::new())
    {
        Ok(r) => r,
        Err(e) => return fail(FailureKind::Protocol, format!("could not build DoH request: {e}")),
    };

    let response = match tokio::time::timeout(timeout, sender.send_request(request)).await {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => return fail(FailureKind::Dns, format!("DoH request failed: {e}")),
        Err(_) => {
            return fail(
                FailureKind::Timeout,
                format!("DoH request to {endpoint} timed out after {timeout:?}"),
            )
        }
    };

    let status = response.status().as_u16();
    let body = response.into_body();
    let limited = Limited::new(body, DOH_MAX_BODY);
    let bytes = match tokio::time::timeout(timeout, limited.collect()).await {
        Ok(Ok(collected)) => collected.to_bytes(),
        Ok(Err(e)) => return fail(FailureKind::Dns, format!("DoH body read failed: {e}")),
        Err(_) => {
            return fail(
                FailureKind::Timeout,
                format!("DoH body from {endpoint} timed out after {timeout:?}"),
            )
        }
    };
    if status != 200 {
        return fail(
            FailureKind::Dns,
            format!("DoH endpoint {endpoint} responded HTTP {status}"),
        );
    }
    let parsed = match parse_dns_response(&bytes, record_type) {
        Ok(p) => p,
        Err(msg) => {
            return fail(
                FailureKind::Dns,
                format!("DoH endpoint {endpoint} returned an invalid response: {msg}"),
            )
        }
    };
    // A non-NOERROR response code means the resolution itself failed (e.g.
    // SERVFAIL, NXDOMAIN), even though the endpoint answered HTTP 200.
    if parsed.rcode != 0 {
        return DnsObservation {
            records: Vec::new(),
            latency_ms: None,
            error: Some(step(
                FailureKind::Dns,
                format!("DoH endpoint {endpoint} answered {}", rcode_name(parsed.rcode)),
            )),
            ..base
        };
    }

    DnsObservation {
        records: parsed.records,
        latency_ms: Some(start.elapsed().as_millis() as u64),
        ..base
    }
}

/// Human-readable name for a common DNS response code (RFC 1035 §4.1.1).
#[must_use]
const fn rcode_name(rcode: u8) -> &'static str {
    match rcode {
        0 => "NoError",
        1 => "FormErr",
        2 => "ServFail",
        3 => "NXDomain",
        4 => "NotImp",
        5 => "Refused",
        9 => "NotAuth",
        _ => "UnknownError",
    }
}

/// Split an `https://host[:port]/path` endpoint URL into its components
/// (port defaults to 443, path to `/dns-query`).
fn parse_doh_url(url: &str) -> Result<(String, u16, String), String> {
    let rest = url
        .strip_prefix("https://")
        .ok_or_else(|| format!("DoH endpoint {url:?} must be an https:// URL"))?;
    let (authority, path) = match rest.split_once('/') {
        Some((authority, path)) => (authority, format!("/{path}")),
        None => (rest, "/dns-query".to_string()),
    };
    if authority.is_empty() {
        return Err(format!("DoH endpoint {url:?} has an empty authority"));
    }
    // `[::1]:443`, `[::1]`, `host:8080`, `host`, `1.1.1.1`
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let (addr, port) = match rest.split_once(']') {
            Some((addr, "")) => (addr, 443u16),
            Some((addr, port)) => {
                let port = port
                    .strip_prefix(':')
                    .ok_or_else(|| format!("DoH endpoint {url:?} has a malformed bracket authority"))?
                    .parse::<u16>()
                    .map_err(|_| format!("DoH endpoint {url:?} has a non-numeric port"))?;
                (addr, port)
            }
            None => return Err(format!("DoH endpoint {url:?} has an unterminated '['")),
        };
        (addr.to_string(), port)
    } else if let Some((host, port)) = authority.rsplit_once(':') {
        let port = port
            .parse::<u16>()
            .map_err(|_| format!("DoH endpoint {url:?} has a non-numeric port"))?;
        (host.to_string(), port)
    } else {
        (authority.to_string(), 443)
    };
    if host.is_empty() {
        return Err(format!("DoH endpoint {url:?} has an empty host"));
    }
    Ok((host, port, path))
}

/// Resolve the `DoH` endpoint's hostname to one connectable address
/// (`IPv4` first), using the system resolver. `IP` literals pass through
/// unchanged.
async fn resolve_doh_host(host: &str, timeout: Duration) -> Result<IpAddr, String> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(ip);
    }
    let resolver = TokioResolver::builder_tokio()
        .map_err(|e| format!("could not build resolver for DoH endpoint host: {e}"))?
        .build()
        .map_err(|e| format!("could not build resolver for DoH endpoint host: {e}"))?;
    let wanted = |rec: &hickory_resolver::proto::rr::Record| match rec.data {
        RData::A(ip) => Some(IpAddr::from(*ip)),
        RData::AAAA(ip) => Some(IpAddr::from(*ip)),
        _ => None,
    };
    if let Ok(Ok(lookup)) = tokio::time::timeout(timeout, resolver.ipv4_lookup(host)).await {
        if let Some(ip) = lookup.answers().iter().find_map(wanted) {
            return Ok(ip);
        }
    }
    if let Ok(Ok(lookup)) = tokio::time::timeout(timeout, resolver.ipv6_lookup(host)).await {
        if let Some(ip) = lookup.answers().iter().find_map(wanted) {
            return Ok(ip);
        }
    }
    Err(format!(
        "could not resolve DoH endpoint host {host:?} via the system resolver"
    ))
}

/// Build a single-question DNS query message (RFC 1035 §4.1) with recursion
/// requested and an arbitrary id.
fn build_query(host: &str, record_type: DnsRecordType) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(host.len() + 32);
    out.extend_from_slice(&0u16.to_be_bytes()); // id
    out.extend_from_slice(&0x0100u16.to_be_bytes()); // flags: RD
    out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    out.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // AN/NS/ARCOUNT
    for label in host.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(format!("hostname {host:?} has an invalid DNS label"));
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0); // root label
    let qtype: u16 = match record_type {
        DnsRecordType::A => 1,
        DnsRecordType::Aaaa => 28,
    };
    out.extend_from_slice(&qtype.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // CLASS IN
    Ok(out)
}

/// A parsed DNS response: the response code (RCODE, low nibble of the header
/// flags) plus the requested record type's addresses from the answer section.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedDnsResponse {
    /// `0` means `NOERROR`; 1-5 are `FORMERR`..`REFUSED`; anything else is an
    /// extension code.
    rcode: u8,
    /// Addresses of the wanted record type found in the answers.
    records: Vec<IpAddr>,
}

/// Parse a DNS response message (RFC 1035 §4.1.3, with name compression
/// support), returning the response code and the wanted record type's
/// addresses from the answer section.
fn parse_dns_response(bytes: &[u8], want: DnsRecordType) -> Result<ParsedDnsResponse, String> {
    if bytes.len() < 12 {
        return Err("message shorter than the 12-byte header".to_string());
    }
    let rcode = bytes[3] & 0x0F;
    let qdcount = u16::from_be_bytes([bytes[4], bytes[5]]) as usize;
    let ancount = u16::from_be_bytes([bytes[6], bytes[7]]) as usize;
    let mut pos = 12;
    for _ in 0..qdcount {
        pos = skip_name(bytes, pos)?; // question name
        pos += 4; // qtype + qclass
    }
    let mut addrs = Vec::new();
    for _ in 0..ancount {
        pos = skip_name(bytes, pos)?; // answer name (possibly a pointer)
        if pos + 10 > bytes.len() {
            return Err("truncated answer header".to_string());
        }
        let rtype = u16::from_be_bytes([bytes[pos], bytes[pos + 1]]);
        // skip class (2) + ttl (4)
        let rdlen = u16::from_be_bytes([bytes[pos + 8], bytes[pos + 9]]) as usize;
        pos += 10;
        let end = pos + rdlen;
        if end > bytes.len() {
            return Err("truncated rdata".to_string());
        }
        let rdata = &bytes[pos..end];
        pos = end;
        match (rtype, want) {
            (1, DnsRecordType::A) if rdlen == 4 => {
                addrs.push(IpAddr::V4(Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3])));
            }
            (28, DnsRecordType::Aaaa) if rdlen == 16 => {
                addrs.push(IpAddr::V6(Ipv6Addr::from(
                    <[u8; 16]>::try_from(rdata).expect("rdlen checked above"),
                )));
            }
            _ => {} // other record types are ignored
        }
    }
    Ok(ParsedDnsResponse { rcode, records: addrs })
}

/// Return the byte position just past the name at `start`. Handles plain
/// label sequences and a trailing compression pointer (which is validated by
/// a bounded walk of its target).
fn skip_name(bytes: &[u8], start: usize) -> Result<usize, String> {
    let mut pos = start;
    loop {
        let b = *bytes
            .get(pos)
            .ok_or_else(|| format!("name overruns message at {pos}"))?;
        if b == 0 {
            return Ok(pos + 1);
        }
        if b & 0xC0 == 0xC0 {
            let target = (u16::from(b & 0x3F) << 8) | u16::from(*bytes.get(pos + 1).ok_or("truncated pointer")?);
            let target = usize::from(target);
            if target >= bytes.len() {
                return Err("compression pointer out of range".to_string());
            }
            validate_name(bytes, target, 0)?;
            return Ok(pos + 2);
        }
        let len = usize::from(b);
        if len == 0 || len > 63 {
            return Err("bad label length".to_string());
        }
        pos += 1 + len;
        if pos > bytes.len() {
            return Err("name overruns message".to_string());
        }
    }
}

/// Validate the label chain at `start`, capping compression hops to bound
/// pointer loops.
fn validate_name(bytes: &[u8], start: usize, depth: usize) -> Result<(), String> {
    if depth > 8 {
        return Err("too many compression-pointer hops".to_string());
    }
    let mut pos = start;
    loop {
        let b = *bytes
            .get(pos)
            .ok_or_else(|| format!("name overruns message at {pos}"))?;
        if b == 0 {
            return Ok(());
        }
        if b & 0xC0 == 0xC0 {
            let target = (u16::from(b & 0x3F) << 8) | u16::from(*bytes.get(pos + 1).ok_or("truncated pointer")?);
            let target = usize::from(target);
            if target >= bytes.len() {
                return Err("compression pointer out of range".to_string());
            }
            return validate_name(bytes, target, depth + 1);
        }
        let len = usize::from(b);
        if len == 0 || len > 63 {
            return Err("bad label length".to_string());
        }
        pos += 1 + len;
        if pos > bytes.len() {
            return Err("name overruns message".to_string());
        }
    }
}

/// RFC 4648 §5 base64url encoding without padding (as required by RFC 8484).
fn base64url(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        out.push(ALPHABET[usize::from(b0 >> 2)] as char);
        out.push(ALPHABET[usize::from(((b0 & 0x03) << 4) | (b1 >> 4))] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[usize::from(((b1 & 0x0F) << 2) | (b2 >> 6))] as char);
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[usize::from(b2 & 0x3F)] as char);
        }
    }
    out
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

    #[test]
    fn base64url_encodes_without_padding() {
        assert_eq!(base64url(b""), "");
        assert_eq!(base64url(b"f"), "Zg");
        assert_eq!(base64url(b"fo"), "Zm8");
        assert_eq!(base64url(b"foobar"), "Zm9vYmFy");
        // URL-safe alphabet: 0xFB 0xEF 0xFF -> 111110 111110 111111 111111
        assert_eq!(base64url(&[0xFB, 0xEF, 0xFF]), "--__");
    }

    #[test]
    fn doh_url_is_parsed_into_host_port_path() {
        assert_eq!(
            parse_doh_url("https://1.1.1.1/dns-query").unwrap(),
            ("1.1.1.1".to_string(), 443, "/dns-query".to_string())
        );
        assert_eq!(
            parse_doh_url("https://cloudflare-dns.com").unwrap(),
            ("cloudflare-dns.com".to_string(), 443, "/dns-query".to_string())
        );
        assert_eq!(
            parse_doh_url("https://dns.google:443/resolve").unwrap(),
            ("dns.google".to_string(), 443, "/resolve".to_string())
        );
        assert_eq!(
            parse_doh_url("https://[::1]:8853/dns-query").unwrap(),
            ("::1".to_string(), 8853, "/dns-query".to_string())
        );
        assert!(parse_doh_url("http://1.1.1.1/dns-query").is_err());
        assert!(parse_doh_url("https://").is_err());
        assert!(parse_doh_url("").is_err());
    }

    #[test]
    fn query_builds_a_standard_message() {
        let q = build_query("host.example", DnsRecordType::A).unwrap();
        // 12-byte header: id 0, flags RD, QDCOUNT 1, then NS/AR counts of 0
        assert_eq!(&q[0..4], &[0, 0, 0x01, 0x00]);
        assert_eq!(&q[4..6], &[0x00, 0x01]); // QDCOUNT
        assert_eq!(&q[6..12], &[0, 0, 0, 0, 0, 0]); // AN/NS/AR
                                                    // question at 12: 4 host 7 example 0 root, qtype A, qclass IN
        assert_eq!(
            &q[12..],
            &[4, b'h', b'o', b's', b't', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0, 0, 1, 0, 1]
        );
        // AAAA uses qtype 28
        let q6 = build_query("host.example", DnsRecordType::Aaaa).unwrap();
        assert_eq!(&q6[q6.len() - 4..], &[0, 28, 0, 1]);
        assert!(build_query("foo..example", DnsRecordType::A).is_err()); // empty label
        assert!(build_query(&"a".repeat(64), DnsRecordType::A).is_err()); // label > 63 bytes
        assert!(build_query("", DnsRecordType::A).is_err());
    }

    #[test]
    fn parses_answers_with_compression_pointers() {
        // A response like the fixture's: one echoed question, two answers via
        // a compression pointer (0xC00C) to the question name.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&[0x12, 0x34, 0x81, 0x80, 0, 1, 0, 2, 0, 0, 0, 0]); // header
        bytes.extend_from_slice(&[
            4, b'h', b'o', b's', b't', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0,
        ]); // name
        bytes.extend_from_slice(&[0, 1, 0, 1]); // qtype A, qclass IN
        bytes.extend_from_slice(&[0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4]); // ptr -> A
        bytes.extend_from_slice(&[192, 0, 2, 77]);
        bytes.extend_from_slice(&[0xC0, 0x0C, 0, 28, 0, 1, 0, 0, 0, 60, 0, 16]); // ptr -> AAAA
        bytes.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x77]);

        let a = parse_dns_response(&bytes, DnsRecordType::A).unwrap();
        assert_eq!(a.rcode, 0, "NOERROR expected");
        assert_eq!(a.records, vec!["192.0.2.77".parse::<IpAddr>().unwrap()]);
        let aaaa = parse_dns_response(&bytes, DnsRecordType::Aaaa).unwrap();
        assert_eq!(aaaa.rcode, 0);
        assert_eq!(aaaa.records, vec!["2001:db8::77".parse::<IpAddr>().unwrap()]);

        // A response code (e.g. NXDOMAIN=3) is surfaced, not read as success.
        let mut nxdomain = bytes.clone();
        nxdomain[3] = 0x80 | 0x03; // flags 0x8183, rcode NXDomain
        nxdomain[7] = 0; // ANCOUNT 0: NXDOMAIN carries no answers
        let nx = parse_dns_response(&nxdomain, DnsRecordType::A).unwrap();
        assert_eq!(nx.rcode, 3);
        assert!(nx.records.is_empty());

        // malformed messages are rejected, not misread
        assert!(parse_dns_response(&bytes[..6], DnsRecordType::A).is_err());
        let mut bad = bytes.clone();
        bad[7] = 200; // ANCOUNT claims 200 answers: truncated -> rejected
        assert!(parse_dns_response(&bad, DnsRecordType::A).is_err());
        // a pointer loop is detected rather than hanging
        let looped = vec![0x12, 0x34, 0x81, 0x80, 0, 0, 0, 1, 0, 0, 0, 0, 0xC0, 0x0E, 0xC0, 0x0C];
        assert!(parse_dns_response(&looped, DnsRecordType::A).is_err());
    }

    #[test]
    fn rcode_names_cover_common_codes() {
        assert_eq!(rcode_name(0), "NoError");
        assert_eq!(rcode_name(2), "ServFail");
        assert_eq!(rcode_name(3), "NXDomain");
        assert_eq!(rcode_name(5), "Refused");
        assert_eq!(rcode_name(77), "UnknownError");
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
