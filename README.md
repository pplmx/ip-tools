# ip-tools

[![Crates.io](https://img.shields.io/crates/v/ip-tools.svg)](https://crates.io/crates/ip-tools)
[![Docs.rs](https://docs.rs/ip-tools/badge.svg)](https://docs.rs/ip-tools)
[![CI](https://github.com/pplmx/ip-tools/workflows/CI/badge.svg)](https://github.com/pplmx/ip-tools/actions)

A network observability and diagnostics toolkit.

`ip-tools` measures *what actually happens* when you try to reach a
destination, at each protocol layer (DNS → addressing → TCP → TLS → HTTP …),
and reports evidence and confidence rather than jumping to conclusions.

**Core principle:** a failed connection is an observation, not a verdict.
`ip-tools` never claims a network failure is censorship merely because a
connection fails. It separates measurement from diagnosis, distinguishes
failure modes (`timeout != reset != refused`), treats every resolved address
independently, and always lists alternative explanations consistent with the
evidence.

## Status

Currently implements: **DNS**, **TCP**, **TLS**, **HTTPS/HTTP1.1**, **HTTP/2**,
**HTTP/3/QUIC**, **route diagnostics (Linux, traceroute)**, **repeated
probing with latency statistics**, and the **evidence-based diagnostic engine**.

- DNS: A + AAAA via the system resolver and/or explicit DNS servers, plus
  DNS-over-HTTPS (`--doh`, RFC 8484) and DNS-over-TLS (`--dot`, RFC 7858)
  endpoints, with latency.
- TCP: per-address connect probes with classified failure modes (timeout /
  refused / reset / unreachable) and latency.
- TLS: handshake with SNI, ALPN, cipher, TLS version and certificate
  subject/issuer/validity, per address.
- HTTPS/HTTP1.1: single request per address over TLS (status, redirect,
  protocol, body size and a bounded body-content snippet).
- Repeated probes: per-address success rate, min/p50/p90/p95/p99/max latency,
  jitter, and failure distribution.
- IPv4 and IPv6 are kept separate and never collapsed.
- Human and `--json` output.

## Installation

```shell
cargo install ip-tools
```

MSRV: see `rust-version` in `Cargo.toml`.

## Testing

The default test suite is fully deterministic (no external network): TCP,
TLS, HTTP/1.1, HTTP/2 and HTTP/3 probes are exercised against an **in-process
fixture** — a self-signed certificate with local hyper (HTTP/1.1 + HTTP/2)
and quinn/h3 (HTTP/3) servers, enabled by the `test-server` feature:

```shell
cargo test                        # unit + CLI + localhost TCP/probe tests
cargo test --all-features         # adds the local HTTP/2 + HTTP/3 fixture tests
```

Running the whole suite is what CI does (`cargo test --all-features`).

## Usage

### DNS diagnostics

Resolve a hostname via the system resolver and any custom servers:

```shell
ip-tools dns example.com
ip-tools dns example.com --server 1.1.1.1 --server 8.8.8.8
ip-tools dns example.com --ipv6        # AAAA only
ip-tools dns example.com --record-type MX    # mail exchange records
ip-tools dns example.com --record-type TXT   # SPF / DKIM text
ip-tools dns example.com --json        # raw observations as JSON
ip-tools dns example.com --count 30    # repeated resolution, latency stats
ip-tools dns example.com example.org another.net   # DNS health sweep (multi-target)
```

`dns` accepts **multiple targets** — a DNS health sweep — resolving each in
turn. Human output renders every host; `--json` with >1 target emits a
per-target array; `--strict` fails if any resolver on any target failed.
`--csv` emits a `host,resolver,record_type,attempts,success_rate,p50,p95,max,
failures` row per (resolver, record type) — single-shot rows are attempts=1,
and `--count` repeat rows use the aggregated latency stats — so a DNS sweep
loads into a spreadsheet.

By default `dns` queries `A` and `AAAA`. `--record-type TYPE` queries a single
specific type — `A`, `AAAA`, `CNAME`, `MX`, `TXT`, `NS`, `SOA`, `CAA` or `SRV`
— so you can inspect mail routing (`MX`), `SPF`/`DKIM` (`TXT`), aliasing
(`CNAME`), authority (`NS`/`SOA`), which CAs may issue certs (`CAA`), or
service endpoints like SIP/XMPP/LDAP (`SRV`) the same way you check addresses.
`--ipv6` is the shorthand for `--record-type AAAA`; the two conflict.

An IP-literal target is shorthand for "this is already an address": `dns
1.1.1.1` reports the literal as its own `A` record (and a clean NODATA-style
empty `AAAA`), with no resolver consulted — consistent with the probe
subcommands, and never a `--strict` failure.

`--count N` repeats each resolution N times and aggregates per-resolver /
per-record-type latency statistics (min/p50/p95/p99/max, jitter) plus the
success rate and failure distribution — the DNS analogue of `probe`'s
per-layer repeat view. Resolver flakiness and intermittent `SERVFAIL` /
`REFUSED` answers that a single lookup cannot show become visible over
repeated queries. With `--count 1` (the default) the output is the ordinary
single-shot report.

Example output:

```
DNS example.com
  system
    A   : 104.20.23.154, 172.66.147.243 (15 ms)
    AAAA: 2606:4700:10::ac42:93f3, 2606:4700:10::6814:179a (1 ms)
  1.1.1.1:53
    A   : 104.20.23.154 (71 ms)
```

#### DNS-over-HTTPS

Query a DNS-over-HTTPS (RFC 8484) endpoint directly, so the answer cannot
be seen or altered by the local resolver:

```shell
ip-tools dns example.com --doh https://cloudflare-dns.com/dns-query
ip-tools dns example.com --doh https://1.1.1.1/dns-query --insecure
ip-tools dns example.com --doh https://dns.google/dns-query --doh https://mozilla.cloudflare-dns.com/dns-query
```

Each `--doh` endpoint is queried for both A and AAAA (subject to `--ipv6`)
and reported alongside the system and `--server` results, so disagreement
between the local path and an encrypted, tamper-resistant path is visible
side by side. `--insecure` is for IP-literal endpoints whose TLS certificate
does not cover that address: certificates are usually issued to a hostname,
so `https://1.1.1.1/dns-query` typically needs it — but some providers
publish a matching IP subject-alt-name (Cloudflare's `1.1.1.1` does), in
which case the certificate validates either way.

#### DNS-over-TLS

Query a DNS-over-TLS (RFC 7858) endpoint directly, so the answer cannot be
seen or altered by the local resolver over a TLS-protected channel (raw DNS
inside TLS on port 853, no HTTP):

```shell
ip-tools dns example.com --dot 1.1.1.1
ip-tools dns example.com --dot 8.8.8.8:853 --dot dns.google
ip-tools dns example.com --dot 1.1.1.1 --count 30
```

Each `--dot` endpoint is queried for both A and AAAA (subject to `--ipv6`)
and reported alongside the system, `--server` and `--doh` results — so the
UDP/plain path can be compared with both encrypted transports side by side
(DoT's TLS-over-853 channel is a first-class alternative to DoH for detecting
steering or tampering). The port defaults to 853; `--insecure` is for an
IP-literal endpoint whose certificate does not cover that address. `--count`
loops the DoT query and aggregates latency/failure statistics like the other
resolvers.

### Custom DNS resolvers

Every subcommand that resolves a hostname — `dns`, `tcp`, `tls`, `http`,
`http2`, `http3`, `probe` and `diagnose` — accepts repeatable `--server`
arguments to query explicit DNS servers in addition to the system resolver:

```shell
ip-tools tcp host.example --server 1.1.1.1 --server 8.8.8.8
ip-tools probe host.example --server 1.1.1.1 --count 20
```

Probing through a chosen resolver is how you check whether the *system*
resolver is the thing being steered: compare the addresses returned by
`1.1.1.1` with those from the system resolver, then probe them. Addresses are
de-duplicated, and IP-literal targets skip resolution entirely.

### TCP connectivity

Probe TCP connectivity to a host, across every address it resolves to:

```shell
ip-tools tcp example.com
ip-tools tcp example.com:443
ip-tools tcp 127.0.0.1:8080 --timeout 2000 --concurrency 16
ip-tools tcp a.example b.example c.example   # fleet connectivity sweep (multi-target)
```

Every per-address probe subcommand — `tcp`, `tls`, `http`, `http2`, `http3`
and `probe` — accepts **multiple targets** (a fleet/connectivity sweep): each
is resolved and probed in turn. Human output labels each host block; `--json`
emits a per-target array for more than one host; `--strict` aggregates failed
probes across all targets.

`--csv` exports a fleet sweep to a spreadsheet: `tcp` rows carry
`host,destination,success,latency_ms,failure`; `tls` adds the handshake details
(version/cipher/ALPN/certificate subject/issuer/expiry); `http`/`http2`/`http3`
carry the response `protocol,status,location,body_bytes,ttfb_ms,latency_ms`.
`probe --csv` instead reports the aggregated `--count` latency statistics, and
`--csv`/`--json`/human output are mutually exclusive on every command.

On a dual-stack host, `--ipv4` probes only the IPv4 addresses and `--ipv6` only
the IPv6 addresses of each target (mutually exclusive). This avoids
broken-family timeouts and lets you test one family in isolation — for example
confirming whether IPv6 is actually up:

```shell
ip-tools probe example.com --count 20 --ipv6 --strict
```

Example output:

```
TCP connect
  104.20.23.154:443        PASS      198 ms
  172.66.147.243:443       PASS      179 ms
  [2606:4700:10::ac42:93f3]:443 network unreachable
```

### TLS diagnostics

Perform a TLS handshake (with the target hostname as SNI) to each address:

```shell
ip-tools tls example.com
ip-tools tls 10.0.0.5:443 --insecure   # skip certificate validation
ip-tools tls example.com --tls-version 1.3   # offer TLS 1.3 only
```

`--insecure` (also on `http`, `http2`, `http3` and `diagnose`) skips TLS/QUIC
certificate validation — useful for self-signed or private-PKI endpoints.
Signatures on the wire are still verified; only the certificate chain check is
skipped.

`--tls-version 1.2|1.3` offers only that protocol version during the handshake
(default `auto` = rustls defaults), so you can verify *which* TLS versions an
endpoint actually negotiates — e.g. confirming a server still accepts or has
dropped TLS 1.2 for compliance. The negotiated version is reported in the
`TLS:` row.

The certificate row also annotates the remaining lifetime when it is
actionable: `(expires in N days)` within 30 days, or `(expired)` once past
`notAfter` — an expiring certificate is invisible in a raw timestamp, so the
report makes it explicit.

The certificate row also lists its **Subject Alternative Names** (`; sans:
example.com, 127.0.0.1`), so you can see exactly which hostnames/IPs the
certificate is valid for — and whether the host you probed is among them
(searchable when you've a hostname that doesn't match, or a wildcard-only cert).

The TLS report also gives an explicit **`covers <name>: yes/no`** verdict —
whether the served certificate's SANs cover the hostname/SNI you presented
(RFC 6125-style: exact or single-label wildcard for hostnames, exact match for
IP literals). This surfaces a wrong-host or wildcard-mismatch certificate even
under `--insecure`, where chain validation is skipped and the mismatch is
otherwise silent.

Example output:

```
TLS handshake
  104.20.23.154:443
    SNI: example.com
    TLS: TLSv1.3
    cipher: TLS_AES_256_GCM_SHA384
    ALPN: h2
    cert : CN=example.com issued by C=US, O=SSL Corporation, CN=Cloudflare TLS Issuing ECC CA 3 (valid 2026-07-29T22:10:08..2026-10-27T22:17:21)
    latency: 447 ms
```

The report names the SNI presented per address when it differs from the
destination literal — explicit when `--sni` overrides an IP literal (below).

### SNI / Host override

Probe one address while presenting a different hostname as SNI (and, for the
HTTP protocols, the `Host` header). This is the "connect to this IP as if it
were that hostname" pattern — it lets you probe a specific CDN edge, a
`--server` result, or any IP literal as if it were a real hostname, and have
the hostname's certificate validate:

```shell
ip-tools tls 104.20.23.154:443 --sni example.com
ip-tools http 104.20.23.154:443 --sni example.com
ip-tools http2 104.20.23.154:443 --sni example.com --method HEAD
ip-tools probe 104.20.23.154:443 --protocol http --sni example.com --count 20
```

Resolution still uses the target (an IP literal is used directly); only the
name presented on the wire changes. Without `--sni`, an IP-literal target
would present the literal as SNI and the hostname's certificate would not
match (requiring `--insecure`).

`diagnose --sni <name>` scopes the entire diagnosis the same way: the full
probe pipeline (DNS → TCP → TLS → HTTP/1.1+2+3 → repeated) connects to the
target's addresses while presenting the chosen name, so a conclusion about
"why is this address failing as that hostname" is evaluated under the name
users actually connect with:

```shell
ip-tools diagnose 104.20.23.154:443 --sni example.com
ip-tools diagnose example.com --path /healthz
ip-tools diagnose example.com --method HEAD --header 'authorization: Bearer abc123'
```

`diagnose` accepts the same request-control flags as the HTTP probes —
`--method`, `--path`, `--header`, `--body` (plus `--sni` above) — so the HTTP
evidence the engine reasons over can be scoped to a specific request: a
`/healthz` behind a WAF, an authenticated endpoint, a HEAD-only route, or a
`POST`/API endpoint that requires a body. The rest of the pipeline
(DNS/TCP/TLS/repeated) is unaffected.

Issue a single request over TLS to each address (redirects not followed):

```shell
ip-tools http example.com
ip-tools http example.com --method HEAD
ip-tools http example.com --path /healthz
ip-tools http example.com --method POST --body '{"key":"value"}' --header 'content-type: application/json'
ip-tools http example.com --header 'authorization: Bearer abc123'
ip-tools http example.com --path /private --header 'cookie: session=xyz'
```

`--path` requests a specific resource instead of the default `/` (also on
`http2`, `http3` and `probe --protocol http|http2|http3`), so path-dependent
behavior — a WAF rule, a CDN cache key, a per-endpoint route — can be
observed. The report shows the path when it is not `/`.

`--header NAME:VALUE` (repeatable) sends an extra request header verbatim on
every protocol — an `authorization`, `cookie`, or any header an endpoint
requires to answer truthfully (the `user-agent`/`accept` defaults are always
sent). `--header @file` reads `NAME:VALUE` lines from a file and `--header -`
reads them from stdin, so a common set of headers can be reused without shell
escaping (`-` consumes all of stdin — don't combine with `--body -`).

`--body <TEXT>` sends a request body verbatim (also on `http2`, `http3`,
`probe --protocol http|http2|http3` and `diagnose`), so a `POST`/`PUT`/API
endpoint — a JSON payload, form data, or any health check that requires a
body — can be probed truthfully. Content is sent with an explicit
`content-length`; content-type is not set automatically, so add a
`--header 'content-type: ...'` when the endpoint needs one. `--body @file`
reads the request body from a file (for large or JSON payloads without shell
quoting), and `--body -` reads it from stdin — useful for piping a payload in.

The probes also record the **response headers** (bounded to the first 24):
the `--json` observation carries every header, and the human report shows the
diagnostic-relevant ones — server identity (`server`, `x-powered-by`,
`x-served-by`), CDN/proxy evidence (`via`, `x-cache`, `x-cache-hits`,
`cf-ray`, `cf-cache-status`, `age`, `alt-svc`), caching (`cache-control`,
`expires`, `etag`, `last-modified`), and `set-cookie`/`content-type` — so
*which* server or CDN actually answered is visible in both modes.

The probes also capture a **bounded textual snippet of the response body**
(the first 1024 bytes, lossy-UTF8, with an explicit `…` when the body
continues past that cap): the human report shows a `body content:` line and
`--json` carries the `body_snippet` field. Because the body is what makes a
status code meaningful — a WAF block page, an auth/JSON error, a rate-limit
message, a JS challenge, a captive-portal prompt — surfacing it completes the
HTTP observation (request control, headers, status, and now content).

Example output:

```
HTTPS
  104.20.23.154:443
    host: example.com
    HTTP/1.1 200
    TLS: TLSv1.3
    ALPN: http/1.1
    body: 559 bytes
    body content: <html>...
    latency: 899 ms
    ttfb:    734 ms
```

The HTTP probes also report **TTFB** (time-to-first-byte): the time from
sending the request to receiving the response headers, separate from the total
latency — so a slow server response is distinct from a slow body transfer.
`--json` carries it as `ttfb_ms`.

### HTTP/2

Perform a single request over an HTTP/2 (ALPN `h2`) connection to each address:

```shell
ip-tools http2 example.com
ip-tools http2 example.com --method HEAD
```

Example output:

```
HTTPS
  104.20.23.154:443
    host: example.com
    HTTP/2 200
    TLS: TLSv1.3
    ALPN: h2
    body: 559 bytes
    latency: 916 ms
```

Compare `http` (HTTP/1.1) and `http2` to reveal protocol-selective behavior:
`HTTP/1.1 PASS / HTTP/2 FAIL` is an observable, useful signal — not an
automatic censorship verdict.

### HTTP/3 (QUIC)

Probe the UDP/QUIC path with a single HTTP/3 request to each address:

```shell
ip-tools http3 example.com
ip-tools http3 cloudflare.com --method GET
```

Example output:

```
HTTPS
  104.16.132.229:443
    host: cloudflare.com
    HTTP/3 301
    redirect: https://www.cloudflare.com/
    TLS: TLSv1.3
    ALPN: h3
    body: 167 bytes
    latency: 251 ms
```

Comparing the TCP path (`http`/`http2`) with the QUIC path (`http3`) reveals
protocol/transport-selective behavior. A QUIC-only failure is reported as a
QUIC failure, never conflated with a TCP failure or an automatic censorship
verdict.

### Full diagnosis

Run the full probe pipeline (DNS, TCP, TLS, HTTP/1.1, HTTP/2, HTTP/3 and
repeated probes) then evaluate the evidence with the deterministic engine:

```shell
ip-tools diagnose example.com
ip-tools diagnose example.com --json
```

`diagnose` accepts **multiple targets** — a fleet/health sweep — running the
full pipeline per host sequentially:

```shell
ip-tools diagnose a.example b.example c.example
ip-tools diagnose a.example b.example --json      # one array of per-host reports
ip-tools diagnose a.example b.example --csv       # spreadsheet-friendly rows per diagnosis
```

Human output renders every host's evidence + verdicts; `--json` emits the
existing single-report object for one host and a JSON array for more than one;
`--csv` emits a `host,severity,category,confidence,summary` row per diagnosis
(a single host still gets one row per verdict); `--strict` exits non-zero if
**any** host raised an anomaly.

Example output (on a host whose IPv6 has no route — the IPv4 path works, the
IPv6 and QUIC paths fail locally):

```
DNS example.com
  system
    A   : 104.20.23.154, 172.66.147.243 (15 ms)
TCP connect
  104.20.23.154:443        PASS      203 ms
  [2606:4700:10::ac42:93f3]:443 network unreachable
Diagnosis
[LOW] AddressFamily (Medium confidence)
    IPv6 connectivity fails while the other family works
    Evidence:
      - IPv4: reachable
      - IPv6: unreachable
    Possible causes:
      - broken or missing IPv6
      - destination has no working IPv6
      - firewall / ISP IPv6 filtering
      - routing problem for one family
[LOW] Quic (Medium confidence)
    QUIC/HTTP3 fails while TCP+HTTPS succeeds for example.com
    ...
```

Because the failures above are the *local* address family being unroutable —
not the destination's addresses being partially down — the engine reports the
honest address-family and QUIC verdicts and does **not** raise a
destination-side partial-connectivity or filtering alarm. A resolver
*disagreement* diagnosis requires comparing resolvers (`--server`, `--doh`
and/or `--dot`); a single system-resolver run answers A+AAAA normally and is
not "disagreeing with itself". `diagnose --dot <endpoint>` folds a DNS-over-TLS
resolver into the same evidence and address pool as `--doh`.

The engine separates measurement from diagnosis: each diagnosis carries a
severity, a category, a confidence, the evidence that supports it, and the
mundane alternative explanations that remain consistent with the evidence.
`--json` includes the full raw observations plus the diagnoses.

### Route diagnostics

Trace the network path (Linux, requires root/`CAP_NET_RAW`):

```shell
ip-tools route example.com
ip-tools route 8.8.8.8 --max-hops 20 --probes-per-hop 3 --timeout 700
ip-tools route example.com --csv      # hop-by-hop rows for a path spreadsheet
```

Example output:

```
Traceroute
   1  *
   2  10.135.5.254                             0 ms
   3  10.135.1.1                               1 ms
   4  100.244.0.50                             46 ms
```

A missing hop (`*`) is recorded as lost but not over-interpreted: routers
frequently deprioritize or filter TTL-expired responses.

`--csv` emits a `ttl,hostname,addr,rtt_ms,lost` row per hop (lost hops keep
empty hostname/address/RTT and `lost=1`), so a traceroute path loads into a
spreadsheet for path analysis; `--csv`/`--json`/human output are mutually
exclusive.

### Repeated probes

Repeatedly probe connectivity and report latency statistics per address.
TCP is the default; `--protocol tls|http|http2|http3` repeats a TLS handshake
or an HTTP/1.1, HTTP/2 or HTTP/3 request instead (with `--method` on the HTTP
protocols and, for self-signed endpoints, `--insecure`):

```shell
ip-tools probe example.com --count 100
ip-tools probe example.com --count 100 --concurrency 16
ip-tools probe example.com --protocol tls --count 50
ip-tools probe example.com --protocol http2 --count 100 --method HEAD
ip-tools probe example.com --protocol http3 --count 30 --insecure
```

Per-address attempts run sequentially (so the latency distribution reflects
genuine per-attempt timing and jitter); addresses are probed in parallel,
bounded by `--concurrency`.

Example output:

```
Repeated probes
  104.20.23.154:443
    attempts: 8
    success:  8 (100.0%)
    failure:  0
    latency:
      min:  197 ms
      p50:  198 ms
      p95:  200 ms
      p99:  200 ms
      max:  200 ms
      jitter: 1 ms
```

`--csv` emits a `host,destination,attempts,success_rate,latency_p50_ms,
latency_p95_ms,latency_max_ms,jitter_ms,failures` row per destination across
single and multi-target sweeps — a connectivity-health sweep loads straight
into a spreadsheet (`--csv`/`--json`/human output are mutually exclusive).

### Scripting exit codes

A failed probe is an observation, not an error, so by default the CLI exits
`0` as long as the run completed. For scripting and CI, pass `--strict`
on any of `dns`, `tcp`, `tls`, `http`, `http2`, `http3`, `probe`, `route`
or `diagnose` to exit non-zero when the run found failures:

```shell
ip-tools tcp example.com --strict && echo "all addresses reachable"
ip-tools probe example.com --count 20 --strict || echo "packet loss detected"
ip-tools diagnose example.com --strict || echo "anomaly diagnosed"
ip-tools dns example.com --strict || echo "a resolver failed"
ip-tools route example.com --strict || echo "a hop was lost"
```

`--strict` is per-command: a failed/address probe (each address), any failed
attempt (repeated `probe`), any failed DNS lookup (`dns`), any non-`Healthy`
diagnosis (`diagnose`) or any lost hop (`route`). Output is still rendered in
full; only the exit code changes.

### Local IP helpers

```shell
ip-tools get      # local IP address
ip-tools list     # network interfaces
ip-tools get --json
```

## Diagnostics model

`ip-tools` separates measurement from diagnosis:

```
measurement layer  →  normalized observations  →  diagnostic engine  →  report
```

The model (`src/model/`) is typed: every probe produces an observation with
classified failure kinds, latencies, and the data needed to reason about *why*
a connection behaves as it does. The diagnostic engine is deterministic and
performs no network I/O.

## Interpreting results

- `timeout`, `connection refused`, and `connection reset` are distinct and
  imply different failure mechanisms. They are never collapsed.
- IPv4 working while IPv6 fails is reported as an address-family difference —
  usually broken IPv6 / routing / firewall, not censorship.
- Different addresses of the same hostname are tested independently (CDN,
  anycast, load balancing, partial filtering).

**`ip-tools` does not claim a network failure is censorship merely because a
connection fails.** Many mundane explanations (CDN node failure, routing
asymmetry, destination outage, local firewall, packet loss, transit
congestion) usually explain the observations.

## Library usage

Published as the `ip_tools` crate. Low-level probe functions are async
(Tokio):

```rust
use ip_tools::tcp;
use std::net::SocketAddr;
use std::time::Duration;

let addr: SocketAddr = "127.0.0.1:8080".parse()?;
let obs = tcp::probe(addr, Duration::from_secs(2)).await;
println!("success={} latency={:?}", obs.success, obs.latency_ms);
```

## License

Licensed under either of

 * Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
 * MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option.
