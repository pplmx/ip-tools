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

Currently implements: **DNS**, **TCP**, **TLS**, **HTTPS/HTTP1.1**, and
**repeated probing with latency statistics** (Phases 1–2). HTTP/2, HTTP/3/QUIC,
route diagnostics, and the diagnostic engine are planned.

- DNS: A + AAAA via the system resolver and/or explicit DNS servers, with
  latency.
- TCP: per-address connect probes with classified failure modes (timeout /
  refused / reset / unreachable) and latency.
- TLS: handshake with SNI, ALPN, cipher, TLS version and certificate
  subject/issuer/validity, per address.
- HTTPS/HTTP1.1: single request per address over TLS (status, redirect,
  protocol, body size).
- Repeated probes: per-address success rate, min/p50/p90/p95/p99/max latency,
  jitter, and failure distribution.
- IPv4 and IPv6 are kept separate and never collapsed.
- Human and `--json` output.

## Installation

```shell
cargo install ip-tools
```

MSRV: see `rust-version` in `Cargo.toml`.

## Usage

### DNS diagnostics

Resolve a hostname via the system resolver and any custom servers:

```shell
ip-tools dns example.com
ip-tools dns example.com --server 1.1.1.1 --server 8.8.8.8
ip-tools dns example.com --ipv6        # AAAA only
ip-tools dns example.com --json        # raw observations as JSON
```

Example output:

```
DNS example.com
  system
    A   : 104.20.23.154, 172.66.147.243 (15 ms)
    AAAA: 2606:4700:10::ac42:93f3, 2606:4700:10::6814:179a (1 ms)
  1.1.1.1:53
    A   : 104.20.23.154 (71 ms)
```

### TCP connectivity

Probe TCP connectivity to a host, across every address it resolves to:

```shell
ip-tools tcp example.com
ip-tools tcp example.com:443
ip-tools tcp 127.0.0.1:8080 --timeout 2000 --concurrency 16
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
```

Example output:

```
TLS handshake
  104.20.23.154:443
    TLS: TLSv1.3
    cipher: TLS_AES_256_GCM_SHA384
    ALPN: h2
    cert : CN=example.com issued by C=US, O=SSL Corporation, CN=Cloudflare TLS Issuing ECC CA 3 (valid 2026-07-29T22:10:08..2026-10-27T22:17:21)
    latency: 447 ms
```

### HTTPS / HTTP/1.1

Issue a single request over TLS to each address (redirects not followed):

```shell
ip-tools http example.com
ip-tools http example.com --method HEAD
```

Example output:

```
HTTPS
  104.20.23.154:443
    HTTP/1.1 200
    TLS: TLSv1.3
    ALPN: http/1.1
    body: 559 bytes
    latency: 899 ms
```

### Repeated probes

Repeatedly probe TCP connectivity and report latency statistics per address:

```shell
ip-tools probe example.com --count 100
ip-tools probe example.com --count 100 --concurrency 16
```

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
classified failure kinds, latencies, and (for later phases) the data needed to
reason about *why* a connection behaves as it does. The diagnostic engine is
deterministic and performs no network I/O.

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
