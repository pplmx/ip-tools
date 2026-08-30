//! DNS diagnostics: resolve A / AAAA records via the system resolver and/or
//! explicitly configured DNS servers, and optionally DNS-over-HTTPS
//! (RFC 8484) endpoints.
//!
//! Resolver disagreement (different addresses from different resolvers) is
//! *reported*, never automatically classified as poisoning — the diagnostic
//! engine decides and considers GeoDNS/CDN/ECS/etc. as alternatives.

use crate::model::{DnsObservation, DnsRecord, DnsRecordType, DnsRepeatResult, FailureKind, ProbeError, ResolverKind};
use hickory_resolver::config::{ConnectionConfig, NameServerConfig, ProtocolConfig, ResolverConfig, ResolverOpts};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::proto::rr::{RData, RecordType};
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

    /// Repeatedly resolve `host`/`record_type` `attempts` times and aggregate
    /// per-resolver success/failure rates and latency statistics — the DNS
    /// analogue of [`crate::probe::tcp_repeat`], for a single hostname's
    /// resolution rather than a socket address.
    ///
    /// Attempts run sequentially so the latency distribution reflects genuine
    /// per-query timing (a resolver's flakiness and jitter), not concurrent
    /// skew. Each attempt queries every configured resolver; results are
    /// grouped by resolver + record type.
    pub async fn resolve_repeat(
        &self,
        host: &str,
        record_type: DnsRecordType,
        attempts: usize,
    ) -> Vec<DnsRepeatResult> {
        // Collect attempts first: a resolver may transiently produce an
        // unanswered/failed observation, and the aggregation below must see
        // every attempt's outcome for that resolver.
        let mut per_resolver: Vec<(ResolverKind, Vec<DnsObservation>)> = Vec::new();
        for _ in 0..attempts {
            let obs = self.resolve(host, record_type).await;
            for o in obs {
                let key = o.resolver.clone();
                match per_resolver.iter_mut().find(|(r, _)| *r == key) {
                    Some((_, bucket)) => bucket.push(o),
                    None => per_resolver.push((key, vec![o])),
                }
            }
        }

        let mut out = Vec::with_capacity(per_resolver.len());
        for (_resolver, bucket) in per_resolver {
            out.push(aggregate_repeat(&bucket, record_type, attempts));
        }
        out
    }
}

/// Aggregate one resolver's repeated DNS observations into a
/// [`DnsRepeatResult`]: successes feed latency, failures are bucketed by kind.
#[must_use]
pub fn aggregate_repeat(bucket: &[DnsObservation], record_type: DnsRecordType, attempts: usize) -> DnsRepeatResult {
    let mut latency = crate::model::LatencyStats::default();
    let mut failures: HashMap<FailureKind, usize> = HashMap::new();
    let mut successes = 0usize;
    let mut min_ttl: Option<u32> = None;
    for obs in bucket {
        if let Some(t) = obs.ttl {
            min_ttl = Some(min_ttl.map_or(t, |m| m.min(t)));
        }
        if let Some(ms) = obs.latency_ms {
            successes += 1;
            latency.push(ms);
        } else if let Some(err) = &obs.error {
            *failures.entry(err.kind).or_default() += 1;
        }
    }
    let failure_counts: Vec<crate::model::FailureCount> = failures
        .into_iter()
        .map(|(kind, count)| crate::model::FailureCount { kind, count })
        .collect();
    DnsRepeatResult {
        // Every observation in one bucket came from the same resolver.
        resolver: bucket.first().map_or(ResolverKind::System, |o| o.resolver.clone()),
        record_type,
        attempts,
        successes,
        failures: attempts.saturating_sub(successes),
        success_rate: if attempts == 0 {
            0.0
        } else {
            successes as f64 / attempts as f64
        },
        latency: latency.summarize(),
        failure_counts,
        ttl: min_ttl,
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
    let outcome = tokio::time::timeout(timeout, resolver_lookup(&resolver, &host, record_type)).await;

    let (latency_ms, records, ttl, error) = match outcome {
        Ok(Ok((records, ttl))) => (Some(start.elapsed().as_millis() as u64), records, ttl, None),
        Ok(Err(e)) => (
            None,
            Vec::new(),
            None,
            Some(ProbeError {
                kind: FailureKind::Dns,
                message: lookup_error_message(&host, record_type, &e),
            }),
        ),
        Err(_elapsed) => (
            None,
            Vec::new(),
            None,
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
        ttl,
        records,
        error,
    }
}

/// A human-readable reason for a failed lookup. Hickory's own Display of a
/// `NoRecordsFound` error prints the internal `Query { name: Name(...), .. }`
/// Debug struct straight at the operator (`no records found for Query { ... }`),
/// so the two common empty-answer cases are translated into plain text: a
/// name that simply has none of the requested record type (`no AAAA records
/// found for baidu.com`), and a name that does not exist at all (NXDOMAIN).
/// Anything else keeps hickory's message as the fallback.
fn lookup_error_message(host: &str, record_type: DnsRecordType, err: &hickory_resolver::net::NetError) -> String {
    if err.is_nx_domain() {
        format!("{host} does not exist (NXDOMAIN)")
    } else if err.is_no_records_found() {
        format!("no {record_type} records found for {host}")
    } else {
        err.to_string()
    }
}

/// Perform the record-type-specific hickory lookup, yielding the requested
/// record type's entries (addresses for A/AAAA, names/strings for the rest).
async fn resolver_lookup(
    resolver: &TokioResolver,
    host: &str,
    record_type: DnsRecordType,
) -> Result<(Vec<DnsRecord>, Option<u32>), hickory_resolver::net::NetError> {
    let rt = match record_type {
        DnsRecordType::A => RecordType::A,
        DnsRecordType::Aaaa => RecordType::AAAA,
        DnsRecordType::Cname => RecordType::CNAME,
        DnsRecordType::Mx => RecordType::MX,
        DnsRecordType::Txt => RecordType::TXT,
        DnsRecordType::Ns => RecordType::NS,
        DnsRecordType::Soa => RecordType::SOA,
        DnsRecordType::Caa => RecordType::CAA,
        DnsRecordType::Srv => RecordType::SRV,
        DnsRecordType::Ptr => RecordType::PTR,
    };
    let lookup = resolver.lookup(host, rt).await?;
    let mut records = Vec::new();
    let mut ttl = None;
    for rec in lookup.answers() {
        if let Some(record) = record_from_rdata(record_type, &rec.data) {
            if ttl.is_none() {
                ttl = Some(rec.ttl);
            }
            records.push(record);
        }
    }
    Ok((records, ttl))
}

/// Convert a raw hickory `RData` answer into the requested record type's
/// [`DnsRecord`]; entries of other types (e.g. an A answer in a CNAME-chain
/// lookup) are ignored to keep each observation type-consistent.
fn record_from_rdata(record_type: DnsRecordType, rdata: &RData) -> Option<DnsRecord> {
    match (record_type, rdata) {
        (DnsRecordType::A, RData::A(ip)) => Some(DnsRecord::A(**ip)),
        (DnsRecordType::Aaaa, RData::AAAA(ip)) => Some(DnsRecord::Aaaa(**ip)),
        (DnsRecordType::Cname, RData::CNAME(name)) => Some(DnsRecord::Cname(name.to_string())),
        (DnsRecordType::Mx, RData::MX(mx)) => Some(DnsRecord::Mx {
            preference: mx.preference,
            exchange: mx.exchange.to_string(),
        }),
        (DnsRecordType::Txt, RData::TXT(txt)) => {
            let joined = txt
                .txt_data
                .iter()
                .map(|b| String::from_utf8_lossy(b).into_owned())
                .collect::<String>();
            Some(DnsRecord::Txt(joined))
        }
        (DnsRecordType::Ns, RData::NS(name)) => Some(DnsRecord::Ns(name.to_string())),
        (DnsRecordType::Soa, RData::SOA(soa)) => Some(DnsRecord::Soa(format!(
            "{} {} serial {} refresh {} retry {} expire {} minimum {}",
            soa.mname, soa.rname, soa.serial, soa.refresh, soa.retry, soa.expire, soa.minimum
        ))),
        (DnsRecordType::Caa, RData::CAA(caa)) => {
            let flags = (u8::from(caa.issuer_critical) << 7) | caa.reserved_flags;
            Some(DnsRecord::Caa {
                flags,
                tag: caa.tag.clone(),
                value: String::from_utf8_lossy(&caa.value).into_owned(),
            })
        }
        (DnsRecordType::Ptr, RData::PTR(name)) => Some(DnsRecord::Ptr(name.to_string())),
        (DnsRecordType::Srv, RData::SRV(srv)) => Some(DnsRecord::Srv {
            priority: srv.priority,
            weight: srv.weight,
            port: srv.port,
            target: srv.target.to_string(),
        }),
        _ => None,
    }
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
///
/// # Examples
///
/// ```no_run
/// use ip_tools::dns;
/// use ip_tools::model::DnsRecordType;
/// use std::time::Duration;
///
/// # tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap().block_on(async {
/// let obs = dns::doh_query(
///     "https://cloudflare-dns.com/dns-query",
///     "example.com",
///     DnsRecordType::A,
///     Duration::from_secs(3),
///     false,
/// )
/// .await;
/// println!("addresses: {:?}", obs.records);
/// # });
/// ```
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
        ttl: None,
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
    let ip = match resolve_endpoint_host(&ehost, timeout).await {
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
        crate::tls::TlsProtocol::Auto,
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
        // The endpoint's `host` header carries the port when it is not 443
        // (RFC 7230 §5.4): a DoH endpoint on a non-default port is otherwise
        // mistargeted by host-and-port vhosting on the far side.
        .header("host", crate::http_common::wire_authority(&ehost, eport, true))
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
        Ok(Err(e)) => {
            // http-body-util's `Limited` reports an overrun as a "length limit
            // exceeded" io error; name the cap so an oversized (but well-formed
            // on the wire) answer isn't misread as a transport failure.
            let why = if e.to_string().contains("length limit exceeded") {
                format!(
                    "the DoH response exceeded the {} KiB wire-response cap ({DOH_MAX_BODY} bytes)",
                    DOH_MAX_BODY / 1024
                )
            } else {
                format!("DoH body read failed: {e}")
            };
            return fail(FailureKind::Dns, why);
        }
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
    // A NOERROR answer with no wanted-type records is NODATA — the name
    // exists but has none of this record type. The resolver-backed path
    // reports the identical condition as a `no {type} records found for
    // {host}` failure (hickory's NoRecordsFound), so the wire paths must not
    // silently succeed with zero records: on a mixed `--doh` run the same
    // host would otherwise show SYSTEM=failure next to DOH=success, and
    // `--strict` / repeat aggregation would disagree by resolver.
    if parsed.rcode == 0 && parsed.records.is_empty() {
        return fail(FailureKind::Dns, format!("no {record_type} records found for {host}"));
    }
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
        ttl: parsed.ttl,
        ..base
    }
}

// --- DNS-over-TLS (RFC 7858) -------------------------------------------------

/// Query a `DNS`-over-TLS endpoint for `host`/`record_type` over a raw
/// `TLS` connection (RFC 7858: a 2-byte length prefix wraps each DNS message),
/// and build a [`DnsObservation`].
///
/// `endpoint` is a `host[:port]` like `1.1.1.1` (port defaults to 853);
/// `insecure` skips certificate validation.
#[must_use]
#[allow(clippy::too_many_lines)]
///
/// # Examples
///
/// ```no_run
/// use ip_tools::dns;
/// use ip_tools::model::DnsRecordType;
/// use std::time::Duration;
///
/// # tokio::runtime::Builder::new_multi_thread().enable_all().build().unwrap().block_on(async {
/// let obs = dns::dot_query(
///     "1.1.1.1",
///     "example.com",
///     DnsRecordType::A,
///     Duration::from_secs(3),
///     false,
/// )
/// .await;
/// println!("addresses: {:?}", obs.records);
/// # });
/// ```
pub async fn dot_query(
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
        resolver: ResolverKind::Dot(endpoint.to_string()),
        record_type,
        records: Vec::new(),
        ttl: None,
        latency_ms: None,
        error: None,
    };
    let fail = |kind, message| DnsObservation {
        error: Some(step(kind, message)),
        ..base.clone()
    };

    let (ehost, eport) = match parse_dot_endpoint(endpoint) {
        Ok(p) => p,
        Err(msg) => return fail(FailureKind::Other, msg),
    };
    let ip = match resolve_endpoint_host(&ehost, timeout).await {
        Ok(ip) => ip,
        Err(msg) => return fail(FailureKind::Dns, msg),
    };
    let query = match build_query(host, record_type) {
        Ok(q) => q,
        Err(msg) => return fail(FailureKind::Protocol, msg),
    };

    // DoT carries raw DNS over TLS (no ALPN, no HTTP): TCP connect, then a
    // rustls handshake to the endpoint hostname, then length-prefixed framing.
    let roots = crate::tls::roots();
    let mode = if insecure {
        crate::tls::TlsMode::Insecure
    } else {
        crate::tls::TlsMode::Roots(&roots)
    };
    let conn = match crate::tls::connect_to(
        SocketAddr::new(ip, eport),
        &ehost,
        &[],
        timeout,
        mode,
        crate::tls::TlsProtocol::Auto,
    )
    .await
    {
        Ok(c) => c,
        Err(f) => return DnsObservation { error: Some(f), ..base },
    };
    let mut stream = conn.stream;

    // RFC 7858 §3.2: each DNS message is prefixed by a 2-byte length.
    // The query id is fixed (0) by `build_query`; DoT responses must echo a
    // matching id, but we validate structural correctness, not the id.
    let Ok(frame_len) = u16::try_from(query.len()) else {
        return fail(
            FailureKind::Protocol,
            format!(
                "DoT query is too large ({} bytes) for a 2-byte length prefix",
                query.len()
            ),
        );
    };
    let mut wire = Vec::with_capacity(2 + query.len());
    wire.extend_from_slice(&frame_len.to_be_bytes());
    wire.extend_from_slice(&query);
    let write = tokio::time::timeout(timeout, tokio::io::AsyncWriteExt::write_all(&mut stream, &wire)).await;
    match write {
        Ok(Ok(())) => {}
        Ok(Err(e)) => return fail(FailureKind::Dns, format!("DoT write to {endpoint} failed: {e}")),
        Err(_elapsed) => {
            return fail(
                FailureKind::Timeout,
                format!("DoT write to {endpoint} timed out after {timeout:?}"),
            )
        }
    }

    // Read the 2-byte length prefix, then the response body.
    let mut header = [0u8; 2];
    let read = tokio::time::timeout(timeout, tokio::io::AsyncReadExt::read_exact(&mut stream, &mut header)).await;
    match read {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => return fail(FailureKind::Dns, format!("DoT read from {endpoint} failed: {e}")),
        Err(_elapsed) => {
            return fail(
                FailureKind::Timeout,
                format!("DoT read from {endpoint} timed out after {timeout:?}"),
            )
        }
    }
    // A DoT message is wrapped by a 2-byte length prefix, so `resp_len` is at
    // most 65535 by construction — the RFC 7858 framing itself bounds a single
    // message, and the allocation below is therefore inherently bounded (an
    // explicit `resp_len > 64 KiB` guard was provably dead: the u16 can never
    // exceed it).
    let resp_len = u16::from_be_bytes(header) as usize;
    let mut body = vec![0u8; resp_len];
    let read = tokio::time::timeout(timeout, tokio::io::AsyncReadExt::read_exact(&mut stream, &mut body)).await;
    match read {
        Ok(Ok(_)) => {}
        Ok(Err(e)) => {
            return fail(
                FailureKind::Dns,
                format!("DoT response read from {endpoint} failed: {e}"),
            )
        }
        Err(_elapsed) => {
            return fail(
                FailureKind::Timeout,
                format!("DoT response from {endpoint} timed out after {timeout:?}"),
            )
        }
    }

    let parsed = match parse_dns_response(&body, record_type) {
        Ok(p) => p,
        Err(msg) => {
            return fail(
                FailureKind::Dns,
                format!("DoT endpoint {endpoint} returned an invalid response: {msg}"),
            )
        }
    };
    // NODATA (NOERROR, zero wanted records) is reported as a `no {type}
    // records found for {host}` failure, exactly as the resolver-backed path
    // surfaces hickory's NoRecordsFound — see `doh_query` for the rationale.
    if parsed.rcode == 0 && parsed.records.is_empty() {
        return fail(FailureKind::Dns, format!("no {record_type} records found for {host}"));
    }
    if parsed.rcode != 0 {
        return DnsObservation {
            records: Vec::new(),
            latency_ms: None,
            error: Some(step(
                FailureKind::Dns,
                format!("DoT endpoint {endpoint} answered {}", rcode_name(parsed.rcode)),
            )),
            ..base
        };
    }

    DnsObservation {
        records: parsed.records,
        latency_ms: Some(start.elapsed().as_millis() as u64),
        ttl: parsed.ttl,
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
    // The probe appends `?dns=<base64url>` to `path` (RFC 8484), so an
    // endpoint whose configured path already carries a query string or
    // fragment (`https://dns.example/resolve?key=abc`, a corporate DNS
    // gateway) must not keep it: a second `?` in the request target is
    // malformed (`/resolve?key=abc?dns=...`) and the `dns` parameter would
    // never be parsed as its own query param. Strip query+fragment, keeping
    // the base path RFC 8484 places the parameter on.
    let path = match path.split_once(['?', '#']) {
        Some((base, _)) => base.to_string(),
        None => path,
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
    } else if authority.matches(':').count() > 1 {
        // A bare IPv6 literal is not a valid URI authority: RFC 3986 §3.2.2
        // requires brackets. Guarding this here turns `https://::1/dns-query`
        // into a clear error instead of misreading `::1` as host + port and
        // failing later with a vague "could not resolve" message.
        return Err(format!(
            "DoH endpoint {url:?} has an unbracketed IPv6 authority (use [addr]:port)"
        ));
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

/// Resolve an encrypted-DNS endpoint's hostname to one connectable address
/// (`IPv4` first), using the system resolver. `IP` literals pass through
/// unchanged.
async fn resolve_endpoint_host(host: &str, timeout: Duration) -> Result<IpAddr, String> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(ip);
    }
    let resolver = TokioResolver::builder_tokio()
        .map_err(|e| format!("could not build resolver for DNS endpoint host: {e}"))?
        .build()
        .map_err(|e| format!("could not build resolver for DNS endpoint host: {e}"))?;
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
        "could not resolve DNS endpoint host {host:?} via the system resolver"
    ))
}

/// Split a `host[:port]` `DoT` endpoint into (host, port), defaulting the port
/// to 853 (RFC 7858). Bracketed IPv6 and host:port forms are accepted.
fn parse_dot_endpoint(endpoint: &str) -> Result<(String, u16), String> {
    if endpoint.is_empty() {
        return Err("DoT endpoint must not be empty".to_string());
    }
    let (host, port) = if let Some(rest) = endpoint.strip_prefix('[') {
        match rest.split_once(']') {
            Some((addr, "")) => (addr.to_string(), 853),
            Some((addr, port)) => {
                let port = port
                    .strip_prefix(':')
                    .ok_or_else(|| format!("DoT endpoint {endpoint:?} has a malformed bracket authority"))?
                    .parse::<u16>()
                    .map_err(|_| format!("DoT endpoint {endpoint:?} has a non-numeric port"))?;
                (addr.to_string(), port)
            }
            None => return Err(format!("DoT endpoint {endpoint:?} has an unterminated '['")),
        }
    } else if let Some((host, port)) = endpoint.rsplit_once(':') {
        // Careful with bare IPv6 literals without brackets; those are not a
        // valid endpoint here, so reject to avoid misparsing as host:port.
        if host.contains(':') {
            return Err(format!(
                "DoT endpoint {endpoint:?} has an unbracketed IPv6 authority (use [addr]:port)"
            ));
        }
        let port = port
            .parse::<u16>()
            .map_err(|_| format!("DoT endpoint {endpoint:?} has a non-numeric port"))?;
        (host.to_string(), port)
    } else {
        (endpoint.to_string(), 853)
    };
    if host.is_empty() {
        return Err(format!("DoT endpoint {endpoint:?} has an empty host"));
    }
    Ok((host, port))
}

/// Build a single-question DNS query message (RFC 1035 §4.1) with recursion
/// requested and an arbitrary id.
fn build_query(host: &str, record_type: DnsRecordType) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(host.len() + 32);
    out.extend_from_slice(&0u16.to_be_bytes()); // id
    out.extend_from_slice(&0x0100u16.to_be_bytes()); // flags: RD
    out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    out.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // AN/NS/ARCOUNT
                                                // A single trailing root dot (`example.com.`) is a legal fully-qualified
                                                // form that the system-resolver path accepts; strip one so the DoH/DoT
                                                // wire path resolves it identically instead of rejecting it as an invalid
                                                // empty label. A double dot (`example.com..`) stays invalid below.
    let name = host.strip_suffix('.').unwrap_or(host);
    for label in name.split('.') {
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
        DnsRecordType::Cname => 5,
        DnsRecordType::Mx => 15,
        DnsRecordType::Txt => 16,
        DnsRecordType::Ns => 2,
        DnsRecordType::Soa => 6,
        DnsRecordType::Caa => 257,
        DnsRecordType::Srv => 33,
        DnsRecordType::Ptr => 12,
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
    /// TTL (seconds) of the first answer record, when any answer is present.
    ttl: Option<u32>,
    /// Records of the wanted record type found in the answers.
    records: Vec<DnsRecord>,
}

/// Parse a DNS response message (RFC 1035 §4.1.3, with name compression
/// support), returning the response code and the wanted record type's
/// addresses from the answer section.
#[allow(clippy::too_many_lines)] // one record-type decode per answer reads clearer inline
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
    let mut recs = Vec::new();
    let mut first_ttl: Option<u32> = None;
    for _ in 0..ancount {
        pos = skip_name(bytes, pos)?; // answer name (possibly a pointer)
        if pos + 10 > bytes.len() {
            return Err("truncated answer header".to_string());
        }
        let rtype = u16::from_be_bytes([bytes[pos], bytes[pos + 1]]);
        // Capture the first answer's TTL (class(2) + ttl(4) precede rdlength),
        // but only from a record of the *wanted* type: an answer section often
        // leads with a CNAME (aliasing) whose TTL is not the address record's
        // caching bound, and the hickory-backed resolver path captures its TTL
        // from type-matching records alone — the wire path must agree.
        let is_wanted = match want {
            DnsRecordType::A => rtype == 1,
            DnsRecordType::Aaaa => rtype == 28,
            DnsRecordType::Cname => rtype == 5,
            DnsRecordType::Ns => rtype == 2,
            DnsRecordType::Ptr => rtype == 12,
            DnsRecordType::Mx => rtype == 15,
            DnsRecordType::Txt => rtype == 16,
            DnsRecordType::Soa => rtype == 6,
            DnsRecordType::Caa => rtype == 257,
            DnsRecordType::Srv => rtype == 33,
        };
        if is_wanted && first_ttl.is_none() {
            first_ttl = Some(u32::from_be_bytes([
                bytes[pos + 4],
                bytes[pos + 5],
                bytes[pos + 6],
                bytes[pos + 7],
            ]));
        }
        let rdlen = u16::from_be_bytes([bytes[pos + 8], bytes[pos + 9]]) as usize;
        pos += 10;
        let rdata_start = pos;
        let end = pos + rdlen;
        if end > bytes.len() {
            return Err("truncated rdata".to_string());
        }
        let rdata = &bytes[pos..end];
        pos = end;
        let rec = match rtype {
            1 if want == DnsRecordType::A && rdlen == 4 => {
                Some(DnsRecord::A(Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3])))
            }
            28 if want == DnsRecordType::Aaaa && rdlen == 16 => Some(DnsRecord::Aaaa(Ipv6Addr::from(
                <[u8; 16]>::try_from(rdata).expect("rdlen checked above"),
            ))),
            5 if want == DnsRecordType::Cname => Some(DnsRecord::Cname(read_name(bytes, rdata_start)?.0)),
            2 if want == DnsRecordType::Ns => Some(DnsRecord::Ns(read_name(bytes, rdata_start)?.0)),
            12 if want == DnsRecordType::Ptr => Some(DnsRecord::Ptr(read_name(bytes, rdata_start)?.0)),
            15 if want == DnsRecordType::Mx && rdlen >= 3 => {
                let preference = u16::from_be_bytes([rdata[0], rdata[1]]);
                let (exchange, _) = read_name(bytes, rdata_start + 2)?;
                Some(DnsRecord::Mx { preference, exchange })
            }
            16 if want == DnsRecordType::Txt => Some(DnsRecord::Txt(read_txt(rdata)?)),
            6 if want == DnsRecordType::Soa => {
                let (mname, p1) = read_name(bytes, rdata_start)?;
                let (rname, p2) = read_name(bytes, p1)?;
                if p2 + 20 > bytes.len() {
                    return Err("truncated soa rdata".to_string());
                }
                let field = |i: usize| {
                    u32::from_be_bytes(bytes[p2 + i * 4..p2 + i * 4 + 4].try_into().expect("bounds checked"))
                };
                Some(DnsRecord::Soa(format!(
                    "{mname} {rname} serial {} refresh {} retry {} expire {} minimum {}",
                    field(0),
                    field(1),
                    field(2),
                    field(3),
                    field(4)
                )))
            }
            257 if want == DnsRecordType::Caa && rdlen >= 2 => {
                let flags = rdata[0];
                let tag_len = usize::from(rdata[1]);
                let tag_end = 2 + tag_len;
                if tag_end > rdata.len() {
                    return Err("truncated caa rdata".to_string());
                }
                let tag = String::from_utf8_lossy(&rdata[2..tag_end]).into_owned();
                let value = String::from_utf8_lossy(&rdata[tag_end..]).into_owned();
                Some(DnsRecord::Caa { flags, tag, value })
            }
            33 if want == DnsRecordType::Srv && rdlen >= 6 => {
                let priority = u16::from_be_bytes([rdata[0], rdata[1]]);
                let weight = u16::from_be_bytes([rdata[2], rdata[3]]);
                let port = u16::from_be_bytes([rdata[4], rdata[5]]);
                let (target, _) = read_name(bytes, rdata_start + 6)?;
                Some(DnsRecord::Srv {
                    priority,
                    weight,
                    port,
                    target,
                })
            }
            _ => None, // other record types / mismatched queries are ignored
        };
        if let Some(rec) = rec {
            recs.push(rec);
        }
    }
    Ok(ParsedDnsResponse {
        rcode,
        ttl: first_ttl,
        records: recs,
    })
}

/// Decode a TXT rdata blob: a sequence of length-prefixed character-strings
/// (RFC 1035 §3.3.14), joined.
fn read_txt(rdata: &[u8]) -> Result<String, String> {
    let mut out = String::new();
    let mut off = 0;
    while off < rdata.len() {
        let len = usize::from(rdata[off]);
        off += 1;
        if off + len > rdata.len() {
            return Err("truncated txt rdata".to_string());
        }
        out.push_str(&String::from_utf8_lossy(&rdata[off..off + len]));
        off += len;
    }
    Ok(out)
}

/// Decode a domain name at `start` (RFC 1035 §4.1.4: plain labels with an
/// optional trailing compression pointer), returning the dotted name and the
/// position just past the name in the wire stream (after the pointer, not the
/// pointed-to location).
fn read_name(bytes: &[u8], start: usize) -> Result<(String, usize), String> {
    let mut labels: Vec<String> = Vec::new();
    let mut pos = start;
    let mut end = None;
    let mut hops = 0;
    loop {
        if hops > 8 {
            return Err("too many compression-pointer hops".to_string());
        }
        let b = *bytes
            .get(pos)
            .ok_or_else(|| format!("name overruns message at {pos}"))?;
        if b == 0 {
            if end.is_none() {
                end = Some(pos + 1);
            }
            break;
        }
        if b & 0xC0 == 0xC0 {
            let target = (u16::from(b & 0x3F) << 8) | u16::from(*bytes.get(pos + 1).ok_or("truncated pointer")?);
            let target = usize::from(target);
            if target >= bytes.len() {
                return Err("compression pointer out of range".to_string());
            }
            if end.is_none() {
                end = Some(pos + 2);
            }
            pos = target;
            hops += 1;
            continue;
        }
        let len = usize::from(b);
        if len == 0 || len > 63 {
            return Err("bad label length".to_string());
        }
        let label_end = pos + 1 + len;
        if label_end > bytes.len() {
            return Err("name overruns message".to_string());
        }
        labels.push(String::from_utf8_lossy(&bytes[pos + 1..label_end]).into_owned());
        pos = label_end;
    }
    let name = if labels.is_empty() {
        ".".to_string()
    } else {
        labels.join(".")
    };
    Ok((name, end.unwrap_or(pos)))
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

    #[test]
    fn build_query_accepts_a_single_trailing_root_dot() {
        // `example.com.` is a legal fully-qualified form (RFC 1034); the wire
        // query must equal the bare-name query (the loop-back suffix `A`
        // records the same question). A double dot stays an invalid label.
        let bare = build_query("example.com", DnsRecordType::A).unwrap();
        let trailing = build_query("example.com.", DnsRecordType::A).unwrap();
        assert_eq!(bare, trailing, "a trailing root dot must not change the question");
        assert!(build_query("example.com..", DnsRecordType::A).is_err());
        assert!(build_query(".", DnsRecordType::A).is_err());
        // The question name on the wire for both forms is the same
        // (after the 12-byte header): 7example3com then the root terminator.
        let mut expected = vec![7];
        expected.extend_from_slice(b"example");
        expected.push(3);
        expected.extend_from_slice(b"com");
        expected.push(0);
        assert!(trailing[12..].starts_with(&expected));
    }

    /// Wrap an IP string as an address record (A/AAAA).
    fn addr_rec(ip: &str) -> DnsRecord {
        match ip.parse::<IpAddr>().unwrap() {
            IpAddr::V4(v) => DnsRecord::A(v),
            IpAddr::V6(v) => DnsRecord::Aaaa(v),
        }
    }

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
        let expected: Vec<DnsRecord> = vec![addr_rec("192.0.2.1"), addr_rec("192.0.2.2")];
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
        assert_eq!(o.records, vec![addr_rec("2001:db8::1")]);
        assert_eq!(o.record_type, DnsRecordType::Aaaa);
    }

    #[tokio::test]
    async fn resolve_repeat_aggregates_per_resolver_successes_and_latency() {
        let fake = FakeDns::start(&["192.0.2.1"], &[]);
        let client = custom(&[fake.addr()], Duration::from_secs(2));
        let results = client.resolve_repeat("host.example", DnsRecordType::A, 5).await;
        let r = results
            .iter()
            .find(|r| r.resolver == ResolverKind::Custom(fake.addr()))
            .expect("custom resolver repeat row");
        assert_eq!(r.record_type, DnsRecordType::A);
        assert_eq!(r.attempts, 5);
        assert_eq!(r.successes, 5, "all five queries should succeed: {r:?}");
        assert_eq!(r.failures, 0, "no failures expected: {r:?}");
        assert!(r.failure_counts.is_empty(), "no failure kinds: {r:?}");
        assert_eq!(r.latency.count, 5, "five latency samples: {r:?}");
        assert!(r.latency.min.is_some() && r.latency.max.is_some());

        // The system resolver is also probed when it exists; when it does not
        // (as here on a bare sandbox), only the custom row appears.
        assert!(
            results.iter().any(|r| r.resolver == ResolverKind::Custom(fake.addr())),
            "custom row must be present: {results:?}"
        );
    }

    #[test]
    fn aggregate_repeat_buckets_failures_and_keeps_resolver_identity() {
        use crate::model::ProbeError;
        let addr: SocketAddr = "192.0.2.53:53".parse().expect("static addr");
        let bucket = vec![
            DnsObservation {
                hostname: "host.example".into(),
                resolver: ResolverKind::Custom(addr),
                record_type: DnsRecordType::A,
                records: vec![addr_rec("192.0.2.1")],
                ttl: Some(60),
                latency_ms: Some(3),
                error: None,
            },
            DnsObservation {
                hostname: "host.example".into(),
                resolver: ResolverKind::Custom(addr),
                record_type: DnsRecordType::A,
                records: vec![addr_rec("192.0.2.2")],
                ttl: Some(30),
                latency_ms: Some(3),
                error: None,
            },
            DnsObservation {
                hostname: "host.example".into(),
                resolver: ResolverKind::Custom(addr),
                record_type: DnsRecordType::A,
                records: Vec::new(),
                ttl: None,
                latency_ms: None,
                error: Some(ProbeError {
                    kind: crate::model::FailureKind::Dns,
                    message: "SERVFAIL".into(),
                }),
            },
            DnsObservation {
                hostname: "host.example".into(),
                resolver: ResolverKind::Custom(addr),
                record_type: DnsRecordType::A,
                records: Vec::new(),
                ttl: None,
                latency_ms: None,
                error: Some(ProbeError {
                    kind: crate::model::FailureKind::Timeout,
                    message: "timed out".into(),
                }),
            },
        ];
        let r = aggregate_repeat(&bucket, DnsRecordType::A, 3);
        assert_eq!(r.resolver, ResolverKind::Custom(addr));
        assert_eq!(r.attempts, 3);
        assert_eq!(r.successes, 2);
        assert_eq!(r.failures, 1);
        assert_eq!(r.latency.count, 2);
        assert_eq!(r.latency.min, Some(3));
        // The minimum TTL across the successful answers is the caching bound.
        assert_eq!(r.ttl, Some(30));
        // Failure distribution: one Dns (SERVFAIL) + one Timeout.
        let kinds: Vec<crate::model::FailureKind> = r.failure_counts.iter().map(|f| f.kind).collect();
        assert!(kinds.contains(&crate::model::FailureKind::Dns));
        assert!(kinds.contains(&crate::model::FailureKind::Timeout));
        assert!(r.failure_counts.iter().all(|f| f.count == 1));
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
    fn doh_url_strips_query_and_fragment_from_the_path() {
        // The probe appends `?dns=<base64url>` (RFC 8484) to the path, so a
        // configured path with its own query string or fragment must be
        // reduced to the base path — otherwise the request target carries a
        // malformed double `?` and the `dns` parameter is never its own key.
        assert_eq!(
            parse_doh_url("https://1.1.1.1/resolve?key=abc").unwrap(),
            ("1.1.1.1".to_string(), 443, "/resolve".to_string())
        );
        assert_eq!(
            parse_doh_url("https://1.1.1.1/resolve#frag").unwrap(),
            ("1.1.1.1".to_string(), 443, "/resolve".to_string())
        );
        assert_eq!(
            parse_doh_url("https://1.1.1.1/resolve?key=abc#frag").unwrap(),
            ("1.1.1.1".to_string(), 443, "/resolve".to_string())
        );
    }

    #[test]
    fn doh_url_rejects_malformed_authorities() {
        // Unterminated bracket: the closing ']' is missing.
        assert!(parse_doh_url("https://[::1/dns-query").is_err());
        assert!(parse_doh_url("https://1.1.1.1").is_ok());
        // Non-numeric port (bracketed or plain form) is rejected.
        assert!(parse_doh_url("https://[::1]:dns/dns-query").is_err());
        assert!(parse_doh_url("https://example.com:port/dns-query").is_err());
        // Empty host is rejected.
        assert!(parse_doh_url("https://:443/dns-query").is_err());
        // A bare IPv6 literal is not a valid URI authority (RFC 3986 §3.2.2):
        // it must be bracketed. Without a guard, `https://::1/dns-query` is
        // misread as host `::` + non-deterministic port and only fails later
        // with a confusing "could not resolve" error.
        assert!(
            parse_doh_url("https://::1/dns-query").is_err(),
            "unbracketed IPv6 authority must be rejected up front"
        );
        assert!(parse_doh_url("https://a:b:c/dns-query").is_err());
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
        // PTR uses qtype 12
        let qptr = build_query("77.2.0.192.in-addr.arpa", DnsRecordType::Ptr).unwrap();
        assert_eq!(&qptr[qptr.len() - 4..], &[0, 12, 0, 1]);
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
        assert_eq!(a.records, vec![addr_rec("192.0.2.77")]);
        let aaaa = parse_dns_response(&bytes, DnsRecordType::Aaaa).unwrap();
        assert_eq!(aaaa.rcode, 0);
        assert_eq!(aaaa.records, vec![addr_rec("2001:db8::77")]);

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

    /// Build a one-question DNS message for `host.example` with the given
    /// answer (rtype, rdata) pairs.
    fn response_with(answers: &[(u16, Vec<u8>)]) -> Vec<u8> {
        response_with_ttls(&answers.iter().map(|(t, d)| (*t, d.clone(), 60u32)).collect::<Vec<_>>())
    }

    fn response_with_ttls(answers: &[(u16, Vec<u8>, u32)]) -> Vec<u8> {
        let mut bytes = Vec::new();
        let ancount = answers.len() as u16;
        bytes.extend_from_slice(&[
            0x12,
            0x34,
            0x81,
            0x80,
            0,
            1,
            (ancount >> 8) as u8,
            (ancount as u8),
            0,
            0,
            0,
            0,
        ]);
        bytes.extend_from_slice(&[
            4, b'h', b'o', b's', b't', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0,
        ]);
        bytes.extend_from_slice(&[0, 1, 0, 1]); // qtype A, qclass IN
        for (rtype, rdata, ttl) in answers {
            bytes.extend_from_slice(&[0xC0, 0x0C]); // owner name ptr -> question
            bytes.extend_from_slice(&rtype.to_be_bytes());
            bytes.extend_from_slice(&[0, 1]); // class IN
            bytes.extend_from_slice(&ttl.to_be_bytes());
            bytes.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
            bytes.extend_from_slice(rdata);
        }
        bytes
    }

    #[test]
    fn parse_dns_response_decodes_wider_record_types() {
        let name_ptr = vec![0xC0, 0x0C]; // compression pointer to "host.example"

        // CNAME and NS carry a single (possibly compressed) name.
        let parsed = parse_dns_response(&response_with(&[(5, name_ptr.clone())]), DnsRecordType::Cname).unwrap();
        assert_eq!(parsed.records, vec![DnsRecord::Cname("host.example".into())]);
        let parsed = parse_dns_response(&response_with(&[(2, name_ptr.clone())]), DnsRecordType::Ns).unwrap();
        assert_eq!(parsed.records, vec![DnsRecord::Ns("host.example".into())]);

        // PTR (12) also carries a single (possibly compressed) name.
        let parsed = parse_dns_response(&response_with(&[(12, name_ptr)]), DnsRecordType::Ptr).unwrap();
        assert_eq!(parsed.records, vec![DnsRecord::Ptr("host.example".into())]);

        // MX is a 2-byte preference followed by a name.
        let mx = vec![0, 10, 0xC0, 0x0C];
        let parsed = parse_dns_response(&response_with(&[(15, mx)]), DnsRecordType::Mx).unwrap();
        assert_eq!(
            parsed.records,
            vec![DnsRecord::Mx {
                preference: 10,
                exchange: "host.example".into()
            }]
        );

        // TXT is a sequence of length-prefixed character-strings.
        let txt = vec![6, b'v', b'=', b's', b'p', b'f', b'1'];
        let parsed = parse_dns_response(&response_with(&[(16, txt)]), DnsRecordType::Txt).unwrap();
        assert_eq!(parsed.records, vec![DnsRecord::Txt("v=spf1".into())]);

        // SOA is two names plus five 32-bit fields.
        let mut soa = vec![0xC0, 0x0C, 0xC0, 0x0C];
        soa.extend_from_slice(&2u32.to_be_bytes());
        soa.extend_from_slice(&3u32.to_be_bytes());
        soa.extend_from_slice(&4u32.to_be_bytes());
        soa.extend_from_slice(&5u32.to_be_bytes());
        soa.extend_from_slice(&6u32.to_be_bytes());
        let parsed = parse_dns_response(&response_with(&[(6, soa)]), DnsRecordType::Soa).unwrap();
        assert_eq!(
            parsed.records,
            vec![DnsRecord::Soa(
                "host.example host.example serial 2 refresh 3 retry 4 expire 5 minimum 6".into()
            )]
        );
    }

    #[test]
    fn parse_dns_response_captures_ttl() {
        // The response_with helper stamps TTL 60 on every answer; the parser
        // captures it from the first answer.
        let parsed = parse_dns_response(&response_with(&[(1, vec![192, 0, 2, 1])]), DnsRecordType::A).unwrap();
        assert_eq!(parsed.ttl, Some(60));
        assert_eq!(parsed.records, vec![DnsRecord::A(Ipv4Addr::new(192, 0, 2, 1))]);
    }

    #[test]
    fn parse_dns_response_ttl_comes_from_the_wanted_record_type() {
        // An A query whose answer section leads with a CNAME (aliasing) must
        // report the A record's TTL, not the CNAME's — the latter is not the
        // address record's caching bound.
        let name_ptr = vec![0xC0, 0x0C]; // compression pointer to "host.example"
        let bytes = response_with_ttls(&[(5, name_ptr, 3600), (1, vec![192, 0, 2, 1], 300)]);
        let parsed = parse_dns_response(&bytes, DnsRecordType::A).unwrap();
        assert_eq!(parsed.records, vec![DnsRecord::A(Ipv4Addr::new(192, 0, 2, 1))]);
        assert_eq!(
            parsed.ttl,
            Some(300),
            "the TTL must be the A record's, not the leading CNAME's"
        );
    }

    #[test]
    fn parse_dns_response_decodes_caa_and_srv() {
        // CAA (257): flags + tag-length + tag + value.
        let mut caa = vec![0u8, 5];
        caa.extend_from_slice(b"issue");
        caa.extend_from_slice(b"letsencrypt.org");
        let parsed = parse_dns_response(&response_with(&[(257, caa)]), DnsRecordType::Caa).unwrap();
        assert_eq!(
            parsed.records,
            vec![DnsRecord::Caa {
                flags: 0,
                tag: "issue".into(),
                value: "letsencrypt.org".into()
            }]
        );

        // SRV (33): priority + weight + port + target name.
        let srv = vec![0, 1, 0, 2, 0x1F, 0x90, 0xC0, 0x0C];
        let parsed = parse_dns_response(&response_with(&[(33, srv)]), DnsRecordType::Srv).unwrap();
        assert_eq!(
            parsed.records,
            vec![DnsRecord::Srv {
                priority: 1,
                weight: 2,
                port: 8080,
                target: "host.example".into()
            }]
        );
    }

    #[test]
    fn record_from_rdata_maps_txt_and_addresses_and_filters_mismatches() {
        use hickory_resolver::proto::rr::rdata::{A, TXT};
        let a = RData::A(A(Ipv4Addr::new(192, 0, 2, 1)));
        assert_eq!(
            record_from_rdata(DnsRecordType::A, &a),
            Some(DnsRecord::A(Ipv4Addr::new(192, 0, 2, 1)))
        );
        // A non-address type is decoded from a TXT answer.
        let txt = RData::TXT(TXT::new(vec!["v=spf1".to_string()]));
        assert_eq!(
            record_from_rdata(DnsRecordType::Txt, &txt),
            Some(DnsRecord::Txt("v=spf1".into()))
        );
        // A type mismatch (asking for MX but getting TXT) is ignored.
        assert_eq!(record_from_rdata(DnsRecordType::Mx, &txt), None);
    }

    #[test]
    fn dot_endpoint_is_parsed_into_host_port() {
        assert_eq!(parse_dot_endpoint("1.1.1.1").unwrap(), ("1.1.1.1".to_string(), 853));
        assert_eq!(
            parse_dot_endpoint("8.8.8.8:8853").unwrap(),
            ("8.8.8.8".to_string(), 8853)
        );
        assert_eq!(
            parse_dot_endpoint("dns.google").unwrap(),
            ("dns.google".to_string(), 853)
        );
        assert_eq!(parse_dot_endpoint("[::1]:8853").unwrap(), ("::1".to_string(), 8853));
        assert!(parse_dot_endpoint("").is_err());
        assert!(parse_dot_endpoint("::1").is_err(), "bare IPv6 needs brackets");
        assert!(parse_dot_endpoint("[::1").is_err(), "unterminated bracket");
        assert!(parse_dot_endpoint("host:notaport").is_err());
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
