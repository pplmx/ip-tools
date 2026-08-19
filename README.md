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

Currently implements: **DNS** and **TCP** diagnostics (Phase 1). TLS, HTTP,
HTTP/2, HTTP/3/QUIC, route diagnostics, repeated probing, and the diagnostic
engine are planned.

- DNS: A + AAAA via the system resolver and/or explicit DNS servers, with
  latency.
- TCP: per-address connect probes with classified failure modes (timeout /
  refused / reset / unreachable) and latency.
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
