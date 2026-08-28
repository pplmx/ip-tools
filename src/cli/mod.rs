//! Command-line interface.
//!
//! This module is intentionally thin: it owns the clap argument tree, the
//! top-level dispatch, and a few shared helpers. Each subcommand's handler
//! lives in its own file under [`crate::cli`] (e.g. [`crate::cli::dns`]).

mod diagnose;
mod dns;
mod http;
mod http2;
mod http3;
mod probe;
mod progress;
mod route;
mod tcp;
mod tls;

use clap::{command, crate_authors, Arg, ArgAction, ArgMatches, Command};
use ip_tools::dns::DnsClient;
use ip_tools::model::{DnsRecord, DnsRecordType};
use ip_tools::report::to_json;
use ip_tools::style::Style;
use ip_tools::target::Target;
use ip_tools::{get_local_ip, list_net_ifs};
use progress::Progress;
use serde::Serialize;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::process::ExitCode;
use std::time::Duration;

/// Default timeout for single network operations, in milliseconds.
const DEFAULT_TIMEOUT_MS: u64 = 5000;
/// Hard upper bound on concurrency to avoid resource exhaustion.
const MAX_CONCURRENCY: usize = 256;
/// Default port for `tcp` (and later TLS/HTTP) probes when none is given.
const DEFAULT_PORT: u16 = 443;

pub fn ip_tools_cli() -> ExitCode {
    let matches = parser();
    handler(&matches)
}

#[allow(clippy::too_many_lines)] // clap subcommand declarations
fn parser() -> ArgMatches {
    command!()
        .arg_required_else_help(true)
        .author(crate_authors!("\n"))
        .arg(
            Arg::new("json")
                .long("json")
                .global(true)
                .action(ArgAction::SetTrue)
                .help("output in JSON format"),
        )
        .arg(
            Arg::new("no-color")
                .long("no-color")
                .global(true)
                .action(ArgAction::SetTrue)
                .help("disable colored human output (color is on only for a TTY unless NO_COLOR is set)"),
        )
        .subcommand(Command::new("get").about("get the local IP address"))
        .subcommand(Command::new("list").about("list all network interfaces"))
        .subcommand(
            Command::new("dns")
                .about("resolve a hostname and inspect DNS results")
                .arg(positional_target("hostname to resolve (repeatable for a DNS sweep)").num_args(1..))
                .arg(server_arg())
                .arg(doh_arg())
                .arg(dot_arg())
                .arg(insecure_arg())
                .arg(dns_ipv4_arg())
                .arg(dns_ipv6_arg())
                .arg(dns_record_type_arg())
                .arg(dns_count_arg())
                .arg(strict_arg())
                .arg(timeout_arg("5000"))
                .arg(dns_concurrency_arg())
                .arg(csv_arg()),
        )
        .subcommand(probe_command(
            "tcp",
            "test TCP connectivity to a host:port across its addresses",
            &[strict_arg(), ipv4_arg(), ipv6_arg(), csv_arg()],
        ))
        .subcommand(probe_command(
            "tls",
            "perform TLS handshake to a host:port across its addresses",
            &[
                insecure_arg(),
                strict_arg(),
                sni_arg(),
                ipv4_arg(),
                ipv6_arg(),
                csv_arg(),
                tls_version_arg(),
            ],
        ))
        .subcommand(probe_command(
            "http",
            "perform an HTTPS/HTTP1.1 request to a host:port across its addresses",
            &[
                method_arg(),
                plain_arg(),
                insecure_arg(),
                strict_arg(),
                sni_arg(),
                path_arg(),
                header_arg(),
                body_arg(),
                output_body_arg(),
                max_body_bytes_arg(),
                expect_status_arg(),
                expect_contains_arg(),
                ipv4_arg(),
                ipv6_arg(),
                csv_arg(),
                tls_version_arg(),
            ],
        ))
        .subcommand(probe_command(
            "probe",
            "repeatedly probe connectivity and report latency statistics",
            &[
                count_arg(),
                strict_arg(),
                protocol_arg(),
                method_arg(),
                plain_arg(),
                insecure_arg(),
                sni_arg(),
                path_arg(),
                header_arg(),
                body_arg(),
                csv_arg(),
                expect_status_repeat_arg(),
                expect_rate_arg(),
                ipv4_arg(),
                ipv6_arg(),
                tls_version_arg(),
            ],
        ))
        .subcommand(probe_command(
            "http2",
            "perform an HTTPS/HTTP2 request to a host:port across its addresses",
            &[
                method_arg(),
                insecure_arg(),
                strict_arg(),
                sni_arg(),
                path_arg(),
                header_arg(),
                body_arg(),
                output_body_arg(),
                max_body_bytes_arg(),
                expect_status_arg(),
                expect_contains_arg(),
                ipv4_arg(),
                ipv6_arg(),
                csv_arg(),
                tls_version_arg(),
            ],
        ))
        .subcommand(probe_command(
            "http3",
            "perform an HTTPS/HTTP3 (QUIC) request to a host:port across its addresses",
            &[
                method_arg(),
                insecure_arg(),
                strict_arg(),
                sni_arg(),
                path_arg(),
                header_arg(),
                body_arg(),
                output_body_arg(),
                max_body_bytes_arg(),
                expect_status_arg(),
                expect_contains_arg(),
                ipv4_arg(),
                ipv6_arg(),
                csv_arg(),
            ],
        ))
        .subcommand(
            Command::new("route")
                .about("trace the network path (hops) to a host (Linux, requires root)")
                .arg(positional_target("host to trace"))
                .arg(
                    Arg::new("max-hops")
                        .long("max-hops")
                        .value_name("N")
                        .value_parser(clap::value_parser!(u8))
                        .default_value("30")
                        .help("maximum number of hops"),
                )
                .arg(
                    Arg::new("probes-per-hop")
                        .long("probes-per-hop")
                        .value_name("N")
                        .value_parser(clap::value_parser!(u8))
                        .default_value("3")
                        .help("probes per hop"),
                )
                .arg(strict_arg())
                // Per-probe ICMP wait for traceroute: the generic 5 s default
                // (fine for connect probes) turns a lost hop into a 15 s stall
                // (3 probes x timeout); the library default is 1 s and a
                // responsive trace is the whole point.
                .arg(timeout_arg("1000"))
                .arg(csv_arg())
                .arg(route_count_arg()),
        )
        .subcommand(probe_command(
            "diagnose",
            "run the full probe pipeline and produce evidence-based diagnoses",
            &[
                insecure_arg(),
                strict_arg(),
                sni_arg(),
                method_arg(),
                path_arg(),
                header_arg(),
                body_arg(),
                diagnose_count_arg(),
                csv_arg(),
                ipv4_arg(),
                ipv6_arg(),
                tls_version_arg(),
                max_body_bytes_arg(),
                reverse_arg(),
                plain_arg(),
            ],
        ))
        .get_matches()
}

/// Common repeatable `--server` DNS-server argument.
fn server_arg() -> Arg {
    Arg::new("server")
        .long("server")
        .value_name("IP[:PORT]")
        .action(ArgAction::Append)
        .help("additional DNS server to query (repeatable); port defaults to 53")
}

/// `--doh` DNS-over-HTTPS endpoint argument (repeatable).
fn doh_arg() -> Arg {
    Arg::new("doh")
        .long("doh")
        .value_name("URL")
        .action(ArgAction::Append)
        .help("DNS-over-HTTPS endpoint to query (repeatable), e.g. https://1.1.1.1/dns-query (use --insecure for IP-literal endpoints)")
}

/// `--dot` DNS-over-TLS endpoint argument (repeatable).
fn dot_arg() -> Arg {
    Arg::new("dot")
        .long("dot")
        .value_name("HOST[:PORT]")
        .action(ArgAction::Append)
        .help("DNS-over-TLS endpoint to query (repeatable), e.g. 1.1.1.1 (port defaults to 853; use --insecure for IP-literal endpoints)")
}

/// Build a per-address probe subcommand: positional target plus the shared
/// `--timeout`/`--concurrency` flags, and subcommand-specific flags (e.g.
/// `--method`, `--insecure`) inserted after the target.
fn probe_command(name: &'static str, about: &'static str, extras: &[Arg]) -> Command {
    // Every per-address probe subcommand accepts many targets (a fleet/health
    // sweep): `run_probe_flow` resolves and probes each in turn.
    let positional = positional_target("host[:port] to probe (repeatable for a sweep)").num_args(1..);
    let mut cmd = Command::new(name).about(about).arg(positional);
    for extra in extras {
        cmd = cmd.arg(extra.clone());
    }
    // Every probe subcommand can resolve the target through explicit DNS
    // servers (`--server`) or encrypted resolvers (`--doh`/`--dot`, as in
    // `dns` and `diagnose`) — useful when the system resolver may be steered
    // or unhealthy; encrypted endpoints make steering detection tamper-proof.
    cmd.arg(server_arg())
        .arg(doh_arg())
        .arg(dot_arg())
        .arg(timeout_arg("5000"))
        .arg(concurrency_arg())
}

/// Common `--timeout` argument (milliseconds).
fn timeout_arg(default_ms: &'static str) -> Arg {
    Arg::new("timeout")
        .long("timeout")
        .value_name("MILLIS")
        .value_parser(clap::value_parser!(u64))
        .default_value(default_ms)
        .help("per-operation timeout in milliseconds")
}

/// Common `--concurrency` argument.
fn concurrency_arg() -> Arg {
    Arg::new("concurrency")
        .long("concurrency")
        .value_name("N")
        .value_parser(clap::value_parser!(usize))
        .default_value("32")
        .help("maximum number of parallel probes")
}

/// `--concurrency` for the `dns` health sweep: parallelize resolving many
/// targets. Defaults to 1 (sequential) to preserve the original single-target
/// ordering and DNS semantics; raising it parallelizes a multi-target sweep.
fn dns_concurrency_arg() -> Arg {
    Arg::new("concurrency")
        .long("concurrency")
        .value_name("N")
        .value_parser(clap::value_parser!(usize))
        .default_value("1")
        .help("maximum number of target hosts to resolve in parallel; 1 runs a sweep sequentially (default)")
}

/// `--ipv4` argument: probe only the IPv4 addresses of each target.
fn ipv4_arg() -> Arg {
    Arg::new("ipv4")
        .long("ipv4")
        .action(ArgAction::SetTrue)
        .conflicts_with("ipv6")
        .help("probe only the IPv4 addresses of each target")
}

/// `--ipv6` argument: probe only the IPv6 addresses of each target.
fn ipv6_arg() -> Arg {
    Arg::new("ipv6")
        .long("ipv6")
        .action(ArgAction::SetTrue)
        .conflicts_with("ipv4")
        .help("probe only the IPv6 addresses of each target")
}

/// `--count` argument for repeated probing.
fn count_arg() -> Arg {
    Arg::new("count")
        .long("count")
        .value_name("N")
        .value_parser(clap::value_parser!(usize))
        .default_value("10")
        .help("number of repeated attempts per address")
}

/// `--count` for the `dns` subcommand: repeat each resolution that many
/// times and aggregate latency/failure statistics (default 1 = single query).
fn dns_count_arg() -> Arg {
    Arg::new("count")
        .long("count")
        .value_name("N")
        .value_parser(clap::value_parser!(usize))
        .default_value("1")
        .help("number of repeated resolutions to aggregate")
}

/// `--count` for the `diagnose` subcommand: how many repeated attempts the
/// stability phase makes per address (both the TCP transport repeat and the
/// HTTP status repeat). Default 3 keeps the flapping / latency-instability /
/// intermittent rules tuned to the sample they were validated with; a larger
/// count gives a longer observation window for subtler instability.
fn diagnose_count_arg() -> Arg {
    Arg::new("count")
        .long("count")
        .value_name("N")
        .value_parser(clap::value_parser!(usize))
        .default_value("3")
        .help("number of repeated attempts per address in the stability phase")
}

/// `--count` for the `route` subcommand: repeat the traceroute that many
/// times and aggregate per-hop latency + router addresses (default 1 = the
/// single current trace, unchanged).
fn route_count_arg() -> Arg {
    Arg::new("count")
        .long("count")
        .value_name("N")
        .value_parser(clap::value_parser!(usize))
        .default_value("1")
        .help("number of traceroute runs to aggregate (1 = single trace)")
}

/// `--protocol` argument selecting which transport/protocol to repeat-probe.
fn protocol_arg() -> Arg {
    Arg::new("protocol")
        .long("protocol")
        .value_name("TCP|TLS|HTTP|HTTP2|HTTP3")
        .value_parser(["tcp", "tls", "http", "http2", "http3"])
        .default_value("tcp")
        .help("protocol to repeatedly probe (tcp, tls, http, http2 or http3)")
}

/// Shared `--method` argument.
fn method_arg() -> Arg {
    Arg::new("method")
        .long("method")
        .value_name("METHOD")
        .default_value("GET")
        .help("HTTP method to use (GET or HEAD)")
}

/// `--sni` argument: present a chosen hostname as SNI (and HTTP `Host`
/// header) instead of the target host, while still connecting to the target's
/// resolved addresses.
///
/// This is the "connect to this IP as if it were that hostname" pattern — for
/// example, probing a specific CDN edge or `--server` result with the real
/// hostname, so the certificate for the hostname validates even though the
/// destination is an IP literal.
fn sni_arg() -> Arg {
    Arg::new("sni")
        .long("sni")
        .value_name("NAME")
        .help("present this hostname as SNI (and HTTP Host) instead of the target host")
}

/// `--tls-version` argument for `tls`: offer only the given protocol version.
fn tls_version_arg() -> Arg {
    Arg::new("tls-version")
        .long("tls-version")
        .value_name("1.2|1.3|auto")
        .value_parser(["auto", "1.2", "1.3"])
        .default_value("auto")
        .help("offer only this TLS protocol version (auto = rustls defaults)")
}

/// Map the `--tls-version` CLI value to a [`ip_tools::tls::TlsProtocol`].
pub fn parse_tls_protocol(sub_m: &ArgMatches) -> ip_tools::tls::TlsProtocol {
    match sub_m.get_one::<String>("tls-version").map(String::as_str) {
        Some("1.2") => ip_tools::tls::TlsProtocol::Tls12,
        Some("1.3") => ip_tools::tls::TlsProtocol::Tls13,
        _ => ip_tools::tls::TlsProtocol::Auto,
    }
}

/// `--path` argument: the HTTP request path to probe (e.g. `/`, `/healthz`).
fn path_arg() -> Arg {
    Arg::new("path")
        .long("path")
        .value_name("PATH")
        .default_value("/")
        .help("HTTP request path to probe")
}

/// `--header` argument: an extra HTTP request header (repeatable).
fn header_arg() -> Arg {
    Arg::new("header")
        .long("header")
        .value_name("NAME:VALUE|@FILE|-")
        .action(ArgAction::Append)
        .help("extra HTTP request header; '--header @file' reads NAME:VALUE lines from a file, '--header -' reads them from stdin (repeatable)")
}

/// `--body` argument: an HTTP request body to send (e.g. for POST/PUT/API
/// endpoints that require one). Content-type is not set automatically; add a
/// `--header 'content-type: ...'` when needed.
fn body_arg() -> Arg {
    Arg::new("body")
        .long("body")
        .value_name("TEXT|@FILE|-")
        .action(ArgAction::Set)
        .help("HTTP request body to send verbatim; '--body @file' reads a file, '--body -' reads stdin")
}

/// `--output-body` argument: write the bounded response body verbatim to a
/// file, so the actual bytes of a WAF block page, JS challenge, captive-portal
/// prompt or API error are inspectable without a re-run in curl.
fn output_body_arg() -> Arg {
    Arg::new("output-body")
        .long("output-body")
        .value_name("FILE")
        .action(ArgAction::Set)
        .help("write the bounded response body verbatim to FILE")
}

/// `--max-body-bytes` argument: bound the HTTP response-body read (and the
/// `--output-body` write). Defaults to the crate's 1 MiB cap.
fn max_body_bytes_arg() -> Arg {
    Arg::new("max-body-bytes")
        .long("max-body-bytes")
        .value_name("BYTES")
        .value_parser(clap::value_parser!(u64))
        .default_value("1048576")
        .help("bound the HTTP response-body read (default 1048576) and any --output-body write")
}

/// `--csv` argument for `diagnose`: emit per-diagnosis rows in CSV.
fn csv_arg() -> Arg {
    Arg::new("csv")
        .long("csv")
        .action(ArgAction::SetTrue)
        .help("output the results as CSV rows instead of human text")
}

/// `--reverse` argument for `diagnose`: include reverse-DNS (PTR) evidence
/// for an IP-literal target in the DNS stack, so the hostname rDNS maps to it
/// surfaces alongside the forward records.
fn reverse_arg() -> Arg {
    Arg::new("reverse")
        .long("reverse")
        .action(ArgAction::SetTrue)
        .help("add reverse-DNS (PTR) evidence for an IP-literal target")
}

/// Shared `--insecure` argument (skip TLS/QUIC certificate validation).
fn insecure_arg() -> Arg {
    Arg::new("insecure")
        .long("insecure")
        .action(ArgAction::SetTrue)
        .help("skip TLS/QUIC certificate validation (e.g. for self-signed or private-PKI endpoints)")
}

/// `--plain`: probe cleartext HTTP (no TLS handshake). Mutually exclusive
/// with `--insecure` and `--tls-version`, which only make sense over TLS.
fn plain_arg() -> Arg {
    Arg::new("plain")
        .long("plain")
        .action(ArgAction::SetTrue)
        .conflicts_with("insecure")
        .conflicts_with("tls-version")
        .help("probe cleartext HTTP (no TLS handshake)")
}

/// `--strict` argument (exit non-zero when the run found failures).
///
/// Per subcommand's meaning: a failed address probe, a failed DNS lookup,
/// a lost route hop, or any non-`Healthy` diagnosis. Observations are still
/// rendered in full; only the exit status becomes non-zero.
fn strict_arg() -> Arg {
    Arg::new("strict")
        .long("strict")
        .action(ArgAction::SetTrue)
        .help("exit non-zero when the run found failures (probes, lookups, lost hops, diagnoses); for scripting/CI")
}

/// `--expect-status SPEC` argument: assert the response status of every
/// probed address (an exact code like `200` or a class like `2xx`).
fn expect_status_arg() -> Arg {
    Arg::new("expect-status")
        .long("expect-status")
        .value_name("SPEC")
        .help("assert that every probed response has this status (e.g. 200) or status class (e.g. 2xx); the run exits non-zero when any response violates it")
}

/// `--expect-contains NEEDLE` argument: assert a substring of every probed
/// response body (checked against the bounded snippet).
fn expect_contains_arg() -> Arg {
    Arg::new("expect-contains")
        .long("expect-contains")
        .value_name("NEEDLE")
        .help("assert that every probed response body contains this text (checked against the bounded snippet); the run exits non-zero when any response violates it")
}

/// `--expect-status SPEC` argument on the repeated probe: assert that every
/// observed HTTP status across the `--count` attempts is within the accepted
/// set (an exact code like `200` or a class like `2xx`). Unlike the
/// single-shot variant, this gates the aggregate status *distribution* — the
/// repeat probes surface status flapping (`200` on most attempts, `503`
/// occasionally), which a single response could never reveal.
fn expect_status_repeat_arg() -> Arg {
    Arg::new("expect-status")
        .long("expect-status")
        .value_name("SPEC")
        .help("assert that every observed HTTP status across the repeated attempts is in this set (e.g. 200) or class (e.g. 2xx); the run exits non-zero when any address violates it (--protocol http/http2/http3)")
}

/// `--expect-rate RATE` argument (repeated probe only): assert the minimum
/// aggregate success rate over the `--count` attempts. Accepts a fraction
/// (`0.97`, `1`) or a percent (`97%`); a zero threshold is rejected as a
/// caller mistake that would make every run pass vacuously.
fn expect_rate_arg() -> Arg {
    Arg::new("expect-rate")
        .long("expect-rate")
        .value_name("RATE")
        .help("assert that the aggregate success rate over the repeated attempts meets this threshold (e.g. 0.97, 1, or 97%); the run exits non-zero when any address falls below it")
}

/// `--ipv4` argument for `dns`: query A records only (the AAAA-side twin of
/// `--ipv6`, mirroring the address-family pair every probe command offers).
fn dns_ipv4_arg() -> Arg {
    Arg::new("ipv4")
        .long("ipv4")
        .action(ArgAction::SetTrue)
        .conflicts_with("ipv6")
        .help("query A records only (default: both A and AAAA)")
}

/// `--ipv6` argument for `dns`: query AAAA records only (default: both A and AAAA).
fn dns_ipv6_arg() -> Arg {
    Arg::new("ipv6")
        .long("ipv6")
        .action(ArgAction::SetTrue)
        .conflicts_with("ipv4")
        .help("query AAAA records only (default: both A and AAAA)")
}

/// `--record-type` argument for `dns`: query a single specific record type.
fn dns_record_type_arg() -> Arg {
    Arg::new("record-type")
        .long("record-type")
        .value_name("TYPE")
        .conflicts_with("ipv4")
        .conflicts_with("ipv6")
        .help("query a single record type (A, AAAA, CNAME, MX, TXT, NS, SOA, CAA, SRV, PTR); default both A and AAAA")
}

fn positional_target(help: &'static str) -> Arg {
    Arg::new("target").required(true).value_name("TARGET").help(help)
}

/// A per-observation expectation checker: returns the violation reason, or
/// `None` when the observation satisfies the asserted `--expect-*` shape
/// (bytes are used only after the concurrent sweep has finished, so it just
/// needs to tolerate being held across the await points).
type ExpectCheck<O> = Box<dyn Fn(&O) -> Option<String> + Send + Sync>;

/// A parsed `--expect-status` spec: either an exact HTTP status code (`200`)
/// or a status class (`2xx`) that every status in that class matches.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum StatusSpec {
    /// An exact status code, e.g. `200`.
    Exact(u16),
    /// A status class, e.g. `2xx` — the hundreds digit (100..=599 / 100).
    Class(u16),
}

impl StatusSpec {
    const fn matches(self, status: u16) -> bool {
        match self {
            Self::Exact(code) => code == status,
            Self::Class(hundred) => status / 100 == hundred,
        }
    }

    /// The spec as the user wrote it, for violation messages (`200` / `2xx`).
    fn describes(self) -> String {
        match self {
            Self::Exact(code) => code.to_string(),
            Self::Class(hundred) => format!("{hundred}xx"),
        }
    }
}

/// The user-asserted response expectations of a run (`--expect-status` /
/// `--expect-contains`), parsed from the subcommand.
#[derive(Clone, Debug, Default)]
struct Expectation {
    status: Option<StatusSpec>,
    contains: Option<String>,
}

impl Expectation {
    /// The reason this observation violates the asserted expectations, or
    /// `None` when it satisfies them all. A probe that failed to complete
    /// carries no response to assert on, so it can never satisfy a
    /// `--expect-*` — that is itself the violation.
    fn violation(
        &self,
        destination: &std::net::SocketAddr,
        status: Option<u16>,
        body: Option<&str>,
        failed: bool,
    ) -> Option<String> {
        if failed {
            return Some(format!(
                "{destination}: probe failed to complete (no response to assert on)"
            ));
        }
        let mut reasons = Vec::new();
        if let Some(spec) = &self.status {
            match status {
                Some(code) if spec.matches(code) => {}
                Some(code) => reasons.push(format!("status {code} (expected {})", spec.describes())),
                None => reasons.push(format!("no status observed (expected {})", spec.describes())),
            }
        }
        if let Some(needle) = &self.contains {
            let found = body.is_some_and(|b| b.contains(needle.as_str()));
            if !found {
                reasons.push(format!("body missing {needle:?} (snippet {})", body.unwrap_or("none")));
            }
        }
        if reasons.is_empty() {
            None
        } else {
            Some(format!("{destination}: {}", reasons.join(", ")))
        }
    }
}

/// Parse the `--expect-status` / `--expect-contains` args of an HTTP-family
/// subcommand into an [`Expectation`]. Returns `Ok(None)` when neither flag is
/// present (a no-op run), and a clear error for malformed specs so an
/// operator catches a typo at the CLI instead of a silently vacuously-passing
/// or always-failing check.
fn parse_expectation(sub_m: &ArgMatches) -> Result<Option<Expectation>, String> {
    let status = match sub_m.try_get_one::<String>("expect-status").ok().flatten() {
        Some(spec) => Some(parse_status_spec(spec)?),
        None => None,
    };
    let contains = match sub_m.try_get_one::<String>("expect-contains").ok().flatten() {
        Some(needle) if needle.is_empty() => {
            return Err("--expect-contains cannot be an empty string (an empty needle matches every body)".into());
        }
        Some(needle) => Some(needle.clone()),
        None => None,
    };
    if status.is_none() && contains.is_none() {
        Ok(None)
    } else {
        Ok(Some(Expectation { status, contains }))
    }
}

/// Parse a single `--expect-status` spec: `200` (exact) or `2xx` (class).
fn parse_status_spec(spec: &str) -> Result<StatusSpec, String> {
    let s = spec.trim();
    if let Some(class) = s.strip_suffix("xx") {
        let hundred: u16 = class.parse().map_err(|_| {
            format!("invalid --expect-status '{spec}': expected an exact code like 200 or a class like 2xx")
        })?;
        if !(1..=5).contains(&hundred) {
            return Err(format!("invalid --expect-status '{spec}': status classes run 1xx..5xx"));
        }
        return Ok(StatusSpec::Class(hundred));
    }
    let code: u16 = s.parse().map_err(|_| {
        format!("invalid --expect-status '{spec}': expected an exact code like 200 or a class like 2xx")
    })?;
    if !(100..=599).contains(&code) {
        return Err(format!("invalid --expect-status '{spec}': status codes run 100..599"));
    }
    Ok(StatusSpec::Exact(code))
}

fn handler(app_m: &ArgMatches) -> ExitCode {
    // Decide once whether the human output is colored: only when stdout is a
    // terminal, with `NO_COLOR` unset and without the `--no-color` flag (see
    // [`Style::auto`]). `get`/`list` print bare values and stay uncolored.
    let style = Style::auto(app_m.get_flag("no-color"));
    match app_m.subcommand() {
        Some(("get", sub_m)) => handle_get(sub_m),
        Some(("list", sub_m)) => handle_list(sub_m),
        Some((name @ ("dns" | "tcp" | "tls" | "http" | "http2" | "http3" | "probe" | "route" | "diagnose"), sub_m)) => {
            run_tokio(name, sub_m, style)
        }
        _ => {
            eprintln!("Error: unknown subcommand");
            ExitCode::FAILURE
        }
    }
}

/// Build a Tokio runtime and run the given async subcommand handler.
fn run_tokio(name: &str, sub_m: &ArgMatches, style: Style) -> ExitCode {
    let rt = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("Error: failed to start async runtime: {e}");
            return ExitCode::FAILURE;
        }
    };
    match name {
        "dns" => rt.block_on(dns::run_dns(sub_m, style)),
        "tcp" => rt.block_on(tcp::run_tcp(sub_m, style)),
        "tls" => rt.block_on(tls::run_tls(sub_m, style)),
        "http" => rt.block_on(http::run_http(sub_m, style)),
        "http2" => rt.block_on(http2::run_http2(sub_m, style)),
        "http3" => rt.block_on(http3::run_http3(sub_m, style)),
        "probe" => rt.block_on(probe::run_probe(sub_m, style)),
        "route" => rt.block_on(route::run_route(sub_m, style)),
        "diagnose" => rt.block_on(diagnose::run_diagnose(sub_m, style)),
        _ => unreachable!(),
    }
}

/// Shared pipeline for the per-address probe subcommands (`tcp`, `tls`,
/// `http`, `http2`, `http3`, `probe`): parse the target, resolve its
/// addresses, probe each in parallel (bounded by `--concurrency`), then emit
/// sorted human or JSON output.
///
/// `probe` is invoked once per destination with `(host, destination,
/// timeout)`; subcommand-specific state (e.g. `--method`, `--count`) is
/// captured by the caller's closure.
/// A whole-sweep CSV renderer (host + per-destination results); only `probe`
/// supplies one.
type CsvRenderer<O> = fn(&[(String, Vec<O>)]) -> String;

#[allow(clippy::too_many_lines)]
#[allow(clippy::too_many_arguments)] // one small per-concern callback (render/sort/failed/csv/expect/probe)
pub async fn run_probe_flow<O, Fut>(
    sub_m: &ArgMatches,
    style: Style,
    render: fn(&Style, &[O]) -> String,
    sort_key: fn(&O) -> SocketAddr,
    failed: fn(&O) -> bool,
    csv_render: Option<CsvRenderer<O>>,
    expect: Option<ExpectCheck<O>>,
    probe: impl Fn(String, SocketAddr, Duration) -> Fut + Send + Sync + Clone + 'static,
) -> ExitCode
where
    O: Sized + serde::Serialize + Send + 'static,
    Fut: Future<Output = O> + Send + 'static,
{
    // Per-target sweep result tagged with its input index so a concurrent
    // sweep can be re-sorted back to the caller's target order.
    type IndexedTarget<O> = (usize, Option<(String, Vec<O>)>);
    // Per-target resolution result (phase 1 of the two-phase sweep): the
    // destination index plus the probe addresses, or `None` when the target
    // produced no address (unresolvable, or emptied by the family scope).
    type ResolvedTarget = (usize, Option<(String, Vec<SocketAddr>)>);

    let json = sub_m.get_flag("json");
    // Not every subcommand routes through here defines `--csv` (the transport
    // and HTTP probes do; `diagnose` renders its own CSV rows below), so read
    // it defensively — try_get_one returns Err when the arg isn't defined.
    let csv = sub_m
        .try_get_one::<bool>("csv")
        .ok()
        .flatten()
        .copied()
        .unwrap_or_default();
    let strict = sub_m.get_flag("strict");
    let timeout_ms = *sub_m.get_one::<u64>("timeout").expect("timeout has default");
    let concurrency = *sub_m.get_one::<usize>("concurrency").expect("concurrency has default");
    let timeout = Duration::from_millis(timeout_ms);
    // `--ipv4`/`--ipv6` restrict a sweep to one address family; with neither,
    // every resolved address is probed (the default).
    let ipv4_only = sub_m.get_flag("ipv4");
    let ipv6_only = sub_m.get_flag("ipv6");

    let servers = match parse_custom_servers(sub_m) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Error: {e}");
            return ExitCode::FAILURE;
        }
    };
    // `--doh`/`--dot` endpoints resolve the target through an encrypted
    // resolver (parity with `dns`/`diagnose`); the per-address probe commands
    // that have `--insecure` pass it through so IP-literal endpoints validate.
    let doh_endpoints: Vec<String> = sub_m
        .get_many::<String>("doh")
        .map(|vals| vals.cloned().collect())
        .unwrap_or_default();
    let dot_eps: Vec<String> = sub_m
        .get_many::<String>("dot")
        .map(|vals| vals.cloned().collect())
        .unwrap_or_default();
    let insecure = sub_m
        .try_get_one::<bool>("insecure")
        .ok()
        .flatten()
        .copied()
        .unwrap_or_default();

    // A `--sni` override presents a chosen hostname as SNI (and HTTP `Host`)
    // instead of each target's host, applied to every target in a sweep.
    let sni = sub_m.try_get_one::<String>("sni").ok().flatten().cloned();

    let targets = match parse_targets(sub_m) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("Error: {e}");
            return ExitCode::FAILURE;
        }
    };
    let single = targets.len() == 1;

    // Probe targets concurrently (bounded by `--concurrency`; 1 keeps the
    // per-host sequential behavior), re-sorting back to the given target order
    // so the human/JSON/CSV output stays deterministic across a fleet sweep.
    // A TTY-gated per-host progress counter is shown on stderr while the
    // sweep runs (silent when piped, quieted, or a single target).
    //
    // `--concurrency` is a true bound on concurrent probes. The sweep is two
    // flat phases — resolve every target, then probe every (target, address)
    // pair — drawing from ONE shared semaphore, so a fleet of multi-address
    // targets cannot fan out to concurrency × (addresses per target)
    // simultaneous sockets (a nested-map design would, and could deadlock when
    // the outer task holds a permit waiting on an inner map's fresh one).
    let limit = std::sync::Arc::new(tokio::sync::Semaphore::new(concurrency.clamp(1, MAX_CONCURRENCY)));
    let target_count = targets.len();
    let progress = std::sync::Arc::new(Progress::new(target_count, sub_m.get_flag("no-color")));
    let progress_for_tasks = progress.clone();
    let targets_with_index: Vec<(usize, Target)> = targets.into_iter().enumerate().collect();
    // Phase 1: resolve each target to its (family-filtered) destinations.
    let mut resolved: Vec<ResolvedTarget> =
        parallel_map_with_limit(targets_with_index, limit.clone(), move |(idx, target)| {
            let servers = servers.clone();
            let doh_endpoints = doh_endpoints.clone();
            let dot_eps = dot_eps.clone();
            let progress = progress_for_tasks.clone();
            async move {
                let result =
                    resolve_for_tcp_servers(&target.host, &servers, &doh_endpoints, &dot_eps, insecure, timeout).await;
                let output = match result {
                    Ok(addrs) => {
                        let destinations: Vec<SocketAddr> = addrs
                            .into_iter()
                            .filter(|ip| match (ipv4_only, ipv6_only) {
                                (true, _) => ip.is_ipv4(),
                                (_, true) => ip.is_ipv6(),
                                _ => true,
                            })
                            .map(|ip| SocketAddr::new(ip, target.port))
                            .collect();
                        // The target resolved, but the --ipv4/--ipv6 scope
                        // emptied its address pool (e.g. `--ipv6` on an
                        // IPv4-only host). Reporting an empty success would
                        // silently exit 0 with zero probes; say so and treat
                        // the target as unresolved instead.
                        if destinations.is_empty() && (ipv4_only || ipv6_only) {
                            let fam = if ipv4_only { "IPv4" } else { "IPv6" };
                            eprintln!(
                                "Error: target {} resolves, but the --ipv4/--ipv6 scope leaves no {fam} addresses to probe",
                                target.host
                            );
                            None
                        } else {
                            Some((target.host.clone(), destinations))
                        }
                    }
                    Err(err) => {
                        eprintln!("Error: {err}");
                        None
                    }
                };
                progress.step(&target.host);
                (idx, output)
            }
        })
        .await;
    resolved.sort_by_key(|(idx, _)| *idx);
    // Phase 2: probe every (host, destination) pair, bounded by the same limit.
    let probe_items: Vec<(usize, String, SocketAddr)> = resolved
        .iter()
        .flat_map(|(idx, output)| {
            output
                .as_ref()
                .map(|(host, dests)| dests.iter().map(move |d| (*idx, host.clone(), *d)))
                .into_iter()
                .flatten()
                .collect::<Vec<_>>()
        })
        .collect();
    let probe_tasks = probe_items.len();
    let probed: Vec<(usize, String, SocketAddr, O)> =
        parallel_map_with_limit(probe_items, limit.clone(), move |(idx, host, dest)| {
            let probe = probe.clone();
            let sni = sni.clone();
            let presented = sni.unwrap_or_else(|| host.clone());
            async move { (idx, host, dest, probe(presented, dest, timeout).await) }
        })
        .await;
    // Group per-target results back into the deterministic target order, each
    // destination list sorted as before.
    let mut per_target: Vec<Option<Vec<O>>> = (0..target_count).map(|_| None).collect();
    for (idx, _host, _dest, result) in probed {
        per_target[idx].get_or_insert_with(Vec::new).push(result);
    }
    let mut indexed: Vec<IndexedTarget<O>> = Vec::with_capacity(probe_tasks);
    for (idx, output) in resolved {
        match output {
            Some((target_host, _)) => {
                let mut results = per_target[idx].take().unwrap_or_default();
                results.sort_by_key(sort_key);
                indexed.push((idx, Some((target_host, results))));
            }
            None => indexed.push((idx, None)),
        }
    }
    indexed.sort_by_key(|(idx, _)| *idx);
    progress.finish();
    let mut per_target: Vec<(String, Vec<O>)> = Vec::with_capacity(indexed.len());
    let mut unresolved = 0usize;
    for (_, result) in indexed {
        match result {
            Some(rt) => per_target.push(rt),
            None => unresolved += 1,
        }
    }

    if csv {
        if let Some(renderer) = csv_render {
            print!("{}", renderer(&per_target));
        } else {
            eprintln!("Error: --csv is not supported for this subcommand");
            return ExitCode::FAILURE;
        }
    } else if json {
        if single {
            if let Some((_, results)) = per_target.first() {
                println!("{}", to_json(results));
            }
        } else {
            let items: Vec<serde_json::Value> = per_target
                .iter()
                .map(|(host, results)| serde_json::json!({ "target": host, "results": results }))
                .collect();
            println!("{}", to_json(&items));
        }
    } else {
        let mut text = String::new();
        for (host, results) in &per_target {
            // In a sweep, label each target block so per-host results are
            // unambiguous (the observations themselves only name destinations).
            if !single {
                use std::fmt::Write as _;
                let _ = writeln!(text, "{host}:");
            }
            text.push_str(&render(&style, results));
        }
        print!("{text}");
    }

    if unresolved > 0 {
        eprintln!("Error: {unresolved} target(s) produced no address to probe (unresolvable, or emptied by the --ipv4/--ipv6 scope)");
        return ExitCode::FAILURE;
    }
    // `--expect-status`/`--expect-contains`: an asserted response shape is a
    // verdict on the whole run, independent of `--strict` (which only gates
    // probes that failed to complete). Each violating observation is named on
    // stderr; the full report above stays on stdout untouched.
    if let Some(check) = &expect {
        let mut violated = false;
        for (_, results) in &per_target {
            for o in results {
                if let Some(reason) = check(o) {
                    eprintln!("expectation violated: {reason}");
                    violated = true;
                }
            }
        }
        if violated {
            return ExitCode::FAILURE;
        }
    }
    // `--strict`: a failed probe is an observation, not an error, but for
    // scripting/CI a caller often wants a non-zero exit when any address
    // could not be reached. Output above is still rendered in full either way.
    if strict {
        let failed_count: usize = per_target
            .iter()
            .flat_map(|(_, results)| results.iter().filter(|o| failed(o)))
            .count();
        if failed_count > 0 {
            eprintln!("Error: {failed_count} probe(s) failed to complete (--strict)");
            return ExitCode::FAILURE;
        }
    }
    ExitCode::SUCCESS
}

fn handle_get(sub_m: &ArgMatches) -> ExitCode {
    let json = sub_m.get_flag("json");
    match get_local_ip() {
        Ok(ip) => {
            if json {
                println!("{}", to_json(&IpOutput { ip }));
            } else {
                println!("{ip}");
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("Error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn handle_list(sub_m: &ArgMatches) -> ExitCode {
    let json = sub_m.get_flag("json");
    match list_net_ifs() {
        Ok(net_ifs) => {
            if json {
                let interfaces: Vec<InterfaceOutput> = net_ifs
                    .iter()
                    .map(|(name, ip)| InterfaceOutput {
                        name: name.clone(),
                        ip: *ip,
                    })
                    .collect();
                println!("{}", to_json(&interfaces));
            } else {
                for (name, ip) in &net_ifs {
                    println!("{name}: {ip}");
                }
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("Error: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Apply `f` to `items` concurrently, bounded by `concurrency` (capped at
/// [`MAX_CONCURRENCY`]).
///
/// A task that panics is reported on stderr and dropped: for a diagnostics
/// tool, silently missing an address would make the report look complete when
/// it is not. Well-behaved probe closures capture failures into observations,
/// so this only fires on programming errors.
pub async fn parallel_map<I, T, F, Fut>(items: Vec<I>, concurrency: usize, f: F) -> Vec<T>
where
    I: Send + 'static,
    T: Send + 'static,
    F: Fn(I) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = T> + Send + 'static,
{
    parallel_map_with_limit(items, shared_semaphore(concurrency), f).await
}

/// A [`Semaphore`] permitting `concurrency` concurrent jobs, clamped to
/// `1..=MAX_CONCURRENCY` like [`parallel_map`]. Callers that run probe work
/// from several `parallel_map` sites over the same sweep share **one** such
/// semaphore through [`parallel_map_with_limit`], so `--concurrency N` is a
/// true bound on concurrent probes rather than a per-site level (which would
/// let a fleet sweep fan out to `N × sites` simultaneous sockets).
#[must_use]
pub fn shared_semaphore(concurrency: usize) -> std::sync::Arc<tokio::sync::Semaphore> {
    std::sync::Arc::new(tokio::sync::Semaphore::new(concurrency.clamp(1, MAX_CONCURRENCY)))
}

/// Apply `f` to `items` concurrently, bounded by a caller-provided [`Semaphore`]
/// instead of a fresh one. This is the concurrency primitive the probe sweep
/// and the `diagnose` pipeline share across their two levels: the outer
/// `parallel_map` bounds how many *targets* run at once, and every inner
/// per-address `parallel_map` draws from this *same* limit — so
/// `--concurrency N` is a true bound on concurrent probes, not a per-nesting
/// level bound that would let a fleet sweep fan out to N × (addresses per
/// target) simultaneous sockets.
pub async fn parallel_map_with_limit<I, T, F, Fut>(
    items: Vec<I>,
    limit: std::sync::Arc<tokio::sync::Semaphore>,
    f: F,
) -> Vec<T>
where
    I: Send + 'static,
    T: Send + 'static,
    F: Fn(I) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = T> + Send + 'static,
{
    let f = std::sync::Arc::new(f);
    let mut tasks = tokio::task::JoinSet::new();
    for item in items {
        let permit = limit.clone().acquire_owned().await.expect("semaphore not closed");
        let f = std::sync::Arc::clone(&f);
        tasks.spawn(async move {
            let result = f(item).await;
            drop(permit);
            result
        });
    }
    let mut out = Vec::with_capacity(tasks.len());
    while let Some(res) = tasks.join_next().await {
        match res {
            Ok(value) => out.push(value),
            Err(err) => eprintln!("Error: a parallel probe task failed and its result was dropped: {err}"),
        }
    }
    out
}

/// Resolve a hostname to its addresses via the system resolver only.
///
/// If `host` is already an IP literal, it is used directly.
pub async fn resolve_for_tcp(host: &str) -> Result<Vec<IpAddr>, String> {
    resolve_for_tcp_servers(host, &[], &[], &[], false, Duration::from_millis(DEFAULT_TIMEOUT_MS)).await
}

/// Resolve a hostname to its addresses via the system resolver plus any
/// explicit `--server` and `--doh`/`--dot` resolvers (A + AAAA,
/// de-duplicated, order-preserving). `insecure` is passed through to the
/// encrypted (`--doh`/`--dot`) resolvers so IP-literal endpoints validate.
///
/// If `host` is already an IP literal, it is used directly. `timeout` bounds
/// each individual lookup so a slow resolver cannot outlive the probe.
pub async fn resolve_for_tcp_servers(
    host: &str,
    servers: &[SocketAddr],
    doh_endpoints: &[String],
    dot_eps: &[String],
    insecure: bool,
    timeout: Duration,
) -> Result<Vec<IpAddr>, String> {
    // Bracket-form IPv6 literals (`[::1]`, as parsed from `[::1]:443`) must be
    // recognized as literals here, not sent to a resolver.
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(vec![ip]);
    }
    let client = DnsClient::new(servers, timeout, 1);
    let mut addrs = Vec::new();
    for rt in [DnsRecordType::A, DnsRecordType::Aaaa] {
        for obs in client.resolve(host, rt).await {
            if obs.error.is_none() {
                addrs.extend(obs.records.iter().filter_map(DnsRecord::address));
            }
        }
        for endpoint in doh_endpoints {
            let obs = ip_tools::dns::doh_query(endpoint, host, rt, timeout, insecure).await;
            if obs.error.is_none() {
                addrs.extend(obs.records.iter().filter_map(DnsRecord::address));
            }
        }
        for endpoint in dot_eps {
            let obs = ip_tools::dns::dot_query(endpoint, host, rt, timeout, insecure).await;
            if obs.error.is_none() {
                addrs.extend(obs.records.iter().filter_map(DnsRecord::address));
            }
        }
    }
    if addrs.is_empty() {
        return Err(format!(
            "hostname {host} did not resolve to any address via the configured resolvers"
        ));
    }
    // De-duplicate while preserving order.
    let mut seen = std::collections::HashSet::new();
    addrs.retain(|a| seen.insert(*a));
    Ok(addrs)
}

/// Parse repeatable `--server` values as DNS server socket addresses.
pub fn parse_custom_servers(sub_m: &ArgMatches) -> Result<Vec<SocketAddr>, String> {
    let mut servers = Vec::new();
    if let Some(values) = sub_m.get_many::<String>("server") {
        for raw in values {
            let parsed = if let Ok(addr) = raw.parse::<SocketAddr>() {
                addr
            } else if let Ok(ip) = raw.parse::<IpAddr>() {
                SocketAddr::new(ip, 53)
            } else {
                return Err(format!("invalid DNS server {raw:?}; expected IP or IP:port"));
            };
            servers.push(parsed);
        }
    }
    Ok(servers)
}

/// Quote a value for a CSV field per RFC 4180: quote when it contains a
/// comma, quote, CR or LF, doubling embedded quotes. The CR case matters
/// because Excel and Python's csv (unlike a naive line-splitter) treat a bare
/// `\r` as a record terminator even when the field is not quoted — a
/// server-controlled body snippet carrying a bare CR would otherwise split the
/// row into two records.
pub fn csv_field(value: &str) -> String {
    if value.contains(',') || value.contains('"') || value.contains('\r') || value.contains('\n') {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}

/// Whether `name` is a valid HTTP header name (RFC 7230 `token`).
fn valid_header_name(name: &str) -> bool {
    !name.is_empty()
        && name.bytes().all(|b| {
            b.is_ascii_alphanumeric()
                || matches!(
                    b,
                    b'!' | b'#'
                        | b'$'
                        | b'%'
                        | b'&'
                        | b'\''
                        | b'*'
                        | b'+'
                        | b'-'
                        | b'.'
                        | b'^'
                        | b'_'
                        | b'`'
                        | b'|'
                        | b'~'
                )
        })
}

/// Parse one `NAME:VALUE` header line into a (name, value) pair.
///
/// A malformed header is a caller mistake and fails fast here — before any
/// probe spins up — rather than surfacing per-address as an HTTP-protocol
/// observation. A name must be a valid HTTP token (a space or a `:` makes it
/// invalid) and a value must contain no control character (which the wire
/// would reject anyway).
fn parse_header_line(line: &str) -> Result<(String, String), String> {
    let Some((name, value)) = line.split_once(':') else {
        return Err(format!(
            "invalid header {line:?}; expected NAME:VALUE, e.g. --header 'authorization: Bearer abc'"
        ));
    };
    let name = name.trim();
    let value = value.trim();
    if !valid_header_name(name) {
        return Err(format!(
            "invalid header {line:?}: the name must be a valid HTTP token (e.g. 'authorization', not 'foo bar')"
        ));
    }
    // Control characters are rejected at the boundary (HTAB is a legal field
    // vchar); the wire would refuse the same value mid-probe otherwise.
    if value.bytes().any(|b| (b < 0x20 && b != b'\t') || b == 0x7f) {
        return Err(format!(
            "invalid header {line:?}: the value contains a control character"
        ));
    }
    Ok((name.to_string(), value.to_string()))
}

/// Append every non-empty header line of `text` (from a file or stdin) to
/// `headers`, failing on a malformed line.
fn push_header_lines(headers: &mut Vec<(String, String)>, text: &str, source: &str) -> Result<(), String> {
    for line in text.lines() {
        let line = line.trim();
        if !line.is_empty() {
            headers.push(parse_header_line(line).map_err(|e| format!("{e} (from {source})"))?);
        }
    }
    Ok(())
}

/// Parse repeatable `--header` values into (name, value) pairs ready for the
/// HTTP probes. A value equal to `-` reads header lines from stdin and a value
/// prefixed with `@` reads them from a file (`NAME:VALUE` per line); anything
/// else is a single inline `NAME:VALUE` header.
pub fn parse_custom_headers(sub_m: &ArgMatches) -> Result<Vec<(String, String)>, String> {
    let mut headers = Vec::new();
    if let Some(values) = sub_m.get_many::<String>("header") {
        for raw in values {
            if raw == "-" {
                let mut text = String::new();
                std::io::Read::read_to_string(&mut std::io::stdin(), &mut text)
                    .map_err(|e| format!("could not read headers from stdin: {e}"))?;
                push_header_lines(&mut headers, &text, "stdin")?;
            } else if let Some(path) = raw.strip_prefix('@') {
                if path.is_empty() {
                    return Err("--header @<file> requires a file path after '@'".to_string());
                }
                let text =
                    std::fs::read_to_string(path).map_err(|e| format!("could not read header file {path:?}: {e}"))?;
                push_header_lines(&mut headers, &text, &format!("file {path:?}"))?;
            } else {
                headers.push(parse_header_line(raw)?);
            }
        }
    }
    Ok(headers)
}

/// Parse a sweep command's positional `target` list (each `host[:port]`),
/// expanding a leading `@path` to the file's lines and `-` to stdin lines —
/// parity with `--header`/`--body`, so a large fleet sweep can come from a
/// file instead of the shell command line. Blank lines and `#` comments in a
/// list file are skipped.
/// A stderr hint for the classic IPv6-with-port mistake: `2001:db8::1:443`
/// (no brackets) parses as the IP literal `2001:db8::1:443` on the *default*
/// port, when the user almost certainly meant `[2001:db8::1]:443`. Fires only
/// when the part before the last colon is itself a complete IPv6 literal and
/// the trailing part is all decimal digits — a genuine bare IPv6 never trips
/// it (its prefix up to the last colon is not a complete literal), so the
/// pattern is unambiguous.
fn ipv6_port_hint(input: &str) -> Option<String> {
    let (addr, port) = input.rsplit_once(':')?;
    if addr.is_empty() || port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    if addr.parse::<std::net::Ipv6Addr>().is_err() {
        return None;
    }
    Some(format!(
        "hint: IPv6 literals with a port need brackets — did you mean [{addr}]:{port}? ({input} parsed as the address {input} on the default port)"
    ))
}

pub fn parse_targets(sub_m: &ArgMatches) -> Result<Vec<Target>, String> {
    fn parse_line(raw: &str) -> Result<Option<Target>, String> {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            return Ok(None);
        }
        if let Some(hint) = ipv6_port_hint(line) {
            eprintln!("{hint}");
        }
        Target::parse(line, DEFAULT_PORT).map(Some).map_err(|e| e.to_string())
    }

    let mut targets = Vec::new();
    if let Some(values) = sub_m.get_many::<String>("target") {
        for raw in values {
            if raw == "-" {
                let mut text = String::new();
                std::io::Read::read_to_string(&mut std::io::stdin(), &mut text)
                    .map_err(|e| format!("could not read targets from stdin: {e}"))?;
                for line in text.lines() {
                    if let Some(t) = parse_line(line)? {
                        targets.push(t);
                    }
                }
            } else if let Some(path) = raw.strip_prefix('@') {
                if path.is_empty() {
                    return Err("target @<file> requires a file path after '@'".to_string());
                }
                let text =
                    std::fs::read_to_string(path).map_err(|e| format!("could not read target file {path:?}: {e}"))?;
                for line in text.lines() {
                    if let Some(t) = parse_line(line)? {
                        targets.push(t);
                    }
                }
            } else if let Some(t) = parse_line(raw)? {
                targets.push(t);
            }
        }
    }
    Ok(targets)
}

/// Resolve the `--body` value into request-body bytes: `-` reads all of
/// stdin, a leading `@` reads the named file, and anything else is the literal
/// body text.
pub fn parse_body(sub_m: &ArgMatches) -> Result<Option<Vec<u8>>, String> {
    let Some(raw) = sub_m.get_one::<String>("body") else {
        return Ok(None);
    };
    if raw == "-" {
        let mut buf = Vec::new();
        std::io::Read::read_to_end(&mut std::io::stdin(), &mut buf)
            .map_err(|e| format!("could not read request body from stdin: {e}"))?;
        return Ok(Some(buf));
    }
    if let Some(path) = raw.strip_prefix('@') {
        if path.is_empty() {
            return Err("--body @<file> requires a file path after '@'".to_string());
        }
        let bytes = std::fs::read(path).map_err(|e| format!("could not read request body file {path:?}: {e}"))?;
        return Ok(Some(bytes));
    }
    Ok(Some(raw.as_bytes().to_vec()))
}

/// Output structure for `get --json`.
#[derive(Serialize)]
struct IpOutput {
    ip: IpAddr,
}

/// Output structure for a single interface in `list --json`.
#[derive(Serialize)]
struct InterfaceOutput {
    name: String,
    ip: IpAddr,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn parallel_map_drops_panicking_tasks_without_propagating() {
        // A panicking probe future must not bubble up; its result is dropped
        // (and reported on stderr), so the caller still gets a Vec.
        let results = parallel_map(vec![1u8, 2u8], 1, |_| async move { panic!("probe task panicked") }).await;
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn parallel_map_returns_all_values_in_any_order() {
        let mut results = parallel_map(vec![1u8, 2, 3], 2, |n| async move { n * 2 }).await;
        results.sort_unstable();
        assert_eq!(results, vec![2, 4, 6]);
    }

    #[tokio::test]
    async fn resolve_recognizes_ip_literals_bracketed_or_bare() {
        // Bracket-form IPv6 (`[::1]`, as parsed from `[::1]:443`) must resolve
        // to itself rather than being sent to a DNS resolver.
        let short = Duration::from_millis(50);
        let want: Vec<IpAddr> = vec!["::1".parse().unwrap()];
        assert_eq!(
            resolve_for_tcp_servers("[::1]", &[], &[], &[], false, short)
                .await
                .unwrap(),
            want
        );
        assert_eq!(
            resolve_for_tcp_servers("::1", &[], &[], &[], false, short)
                .await
                .unwrap(),
            want
        );
        let v4: Vec<IpAddr> = vec!["127.0.0.1".parse().unwrap()];
        assert_eq!(
            resolve_for_tcp_servers("127.0.0.1", &[], &[], &[], false, short)
                .await
                .unwrap(),
            v4
        );
        assert_eq!(
            resolve_for_tcp_servers("[127.0.0.1]", &[], &[], &[], false, short)
                .await
                .unwrap(),
            v4
        );
    }

    #[test]
    fn parse_status_spec_accepts_exact_codes_and_classes() {
        assert_eq!(parse_status_spec("200").unwrap(), StatusSpec::Exact(200));
        assert_eq!(parse_status_spec(" 302 ").unwrap(), StatusSpec::Exact(302));
        assert_eq!(parse_status_spec("2xx").unwrap(), StatusSpec::Class(2));
        assert_eq!(parse_status_spec("5xx").unwrap(), StatusSpec::Class(5));
    }

    #[test]
    fn parse_status_spec_rejects_malformed_specs() {
        for bad in [
            "",
            "20",
            "20x",
            "2X",
            "999",
            "0xx",
            "6xx",
            "two-hundred",
            "-200",
            "200xx",
        ] {
            assert!(parse_status_spec(bad).is_err(), "spec {bad:?} must be rejected");
        }
    }

    #[test]
    fn status_spec_matches_exact_and_class() {
        let exact = StatusSpec::Exact(200);
        assert!(exact.matches(200));
        assert!(!exact.matches(201));
        let class = StatusSpec::Class(2);
        assert!(class.matches(200));
        assert!(class.matches(299));
        assert!(!class.matches(300));
        assert_eq!(exact.describes(), "200");
        assert_eq!(class.describes(), "2xx");
    }

    #[test]
    fn expectation_violation_is_none_when_everything_satisfied() {
        let e = Expectation {
            status: Some(StatusSpec::Class(2)),
            contains: Some("ok".into()),
        };
        let dest: SocketAddr = "192.0.2.1:443".parse().unwrap();
        assert!(e.violation(&dest, Some(200), Some("ok"), false).is_none());
    }

    #[test]
    fn expectation_violation_names_status_and_body_reasons() {
        let e = Expectation {
            status: Some(StatusSpec::Exact(200)),
            contains: Some("ready".into()),
        };
        let dest: SocketAddr = "192.0.2.1:443".parse().unwrap();
        let reason = e.violation(&dest, Some(503), Some("ok"), false).unwrap();
        assert!(
            reason.contains("status 503 (expected 200)") && reason.contains("body missing \"ready\""),
            "both reasons must be named: {reason}"
        );
        assert!(reason.starts_with("192.0.2.1:443:"));
    }

    #[test]
    fn expectation_violation_treats_failed_probe_as_violation() {
        let e = Expectation {
            status: Some(StatusSpec::Class(2)),
            contains: None,
        };
        let dest: SocketAddr = "192.0.2.1:443".parse().unwrap();
        let reason = e.violation(&dest, None, None, true).unwrap();
        assert!(reason.contains("failed to complete"), "{reason}");
    }

    #[test]
    fn expectation_violation_with_no_expected_status_only_checks_needle() {
        let e = Expectation {
            status: None,
            contains: Some("ok".into()),
        };
        let dest: SocketAddr = "192.0.2.1:443".parse().unwrap();
        // Status irrelevant (not asserted), body satisfies the needle.
        assert!(e.violation(&dest, Some(503), Some("it is ok"), false).is_none());
        // Missing needle is the only violation.
        let reason = e.violation(&dest, Some(200), Some("nope"), false).unwrap();
        assert!(reason.contains("body missing \"ok\""), "{reason}");
    }

    #[test]
    fn expectation_violation_reports_no_status_observed() {
        let e = Expectation {
            status: Some(StatusSpec::Exact(200)),
            contains: None,
        };
        let dest: SocketAddr = "192.0.2.1:443".parse().unwrap();
        let reason = e.violation(&dest, None, None, false).unwrap();
        assert!(reason.contains("no status observed (expected 200)"), "{reason}");
    }

    #[test]
    fn header_line_validation_rejects_malformed_names_and_values() {
        // Well-formed headers parse, including punctuation-heavy tokens and
        // values with spaces/tabs.
        assert_eq!(
            parse_header_line("authorization: Bearer abc").unwrap(),
            ("authorization".into(), "Bearer abc".into())
        );
        assert_eq!(
            parse_header_line("x-api-key:v").unwrap(),
            ("x-api-key".into(), "v".into())
        );
        // A name with a space/other non-token char is a caller mistake that
        // must fail here, before any probe runs.
        assert!(parse_header_line("foo bar: baz").unwrap_err().contains("HTTP token"));
        assert!(parse_header_line(": v").unwrap_err().contains("HTTP token"));
        // A control character in the value (CR/LF/NUL, DEL) is rejected.
        assert!(parse_header_line("x: a\nb").unwrap_err().contains("control character"));
        assert!(parse_header_line("x: a\x7fb")
            .unwrap_err()
            .contains("control character"));
    }

    #[test]
    fn ipv6_port_hint_fires_only_on_the_bracket_mistake() {
        // `2001:db8::1:443` (no brackets) is the classic host:port typo for an
        // IPv6 literal — the hint names the corrected bracketed form.
        let h = ipv6_port_hint("2001:db8::1:443").expect("typo should get a hint");
        assert!(h.contains("[2001:db8::1]:443"), "{h}");
        // Genuine bare IPv6 literals (with or without a trailing digit group)
        // never trip it.
        assert!(ipv6_port_hint("2001:db8::1").is_none());
        assert!(ipv6_port_hint("::1").is_none());
        assert!(ipv6_port_hint("2001:db8::443").is_none());
        // Bracketed-with-port and IPv4-with-port are untouched.
        assert!(ipv6_port_hint("[2001:db8::1]:443").is_none());
        assert!(ipv6_port_hint("1.2.3.4:443").is_none());
        assert!(ipv6_port_hint("example.com:443").is_none());
    }

    #[test]
    fn csv_field_quotes_and_doubles_embedded_quotes() {
        assert_eq!(csv_field("a,b"), "\"a,b\"");
        assert_eq!(csv_field("say \"hi\""), "\"say \"\"hi\"\"\"");
        assert_eq!(csv_field("plain"), "plain");
    }

    #[test]
    fn csv_field_quotes_a_bare_carriage_return() {
        // RFC 4180: a lone `\r` inside a field terminates the record for
        // Excel and Python's csv even unquoted, so it must be quoted. A
        // server-controlled body snippet with a bare CR used to split the row
        // into two records before this was added.
        assert_eq!(csv_field("only\rreturn"), "\"only\rreturn\"");
        assert_eq!(csv_field("line1\r\nline2"), "\"line1\r\nline2\"");
        assert_eq!(csv_field("no-cr"), "no-cr");
    }
}
