# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
|- `--sni <name>` on `tls`, `http`, `http2`, `http3` and `probe`: present a chosen hostname as SNI (and, for the HTTP protocols, the `Host` header) while still connecting to the target's resolved addresses — the "connect to this IP as if it were that hostname" pattern. This lets a user probe a specific CDN edge, `--server` result, or any IP literal *as* a real hostname, so the hostname's certificate validates even though the destination is an address. Resolution still uses the target (an IP literal is used directly); only the name presented on the wire changes. Previously an IP-literal target always presented the literal as SNI, forcing `--insecure` even for a hostname whose address it is. The human TLS/HTTP reports now also name the SNI/`host` presented per address when it differs from the destination literal, so an override is visible in the output (the JSON always carried `sni`/`host`). Pinned by three fixture-gated integration tests: the HTTP `Host` header actually routes on the wire, the TLS observation records the overridden SNI, and `probe --protocol http --sni` aggregates under the presented host
|- README accuracy: the `diagnose` example previously showed a `[LOW] Dns` "Resolvers disagree" verdict and a `[MEDIUM] PartialConnectivity (High confidence)` verdict for a plain `example.com` run — both stale after the resolver-disagreement grouping and the locality fixes (a single system-resolver run no longer disagrees with itself, and a locally-unroutable address family is no longer read as destination partial connectivity). The example now reflects the honest AddressFamily/Quic verdicts for a host with an unroutable family, and notes that a disagreement diagnosis requires comparing `--server`/`--doh` resolvers. The `--doh` `--insecure` claim is also corrected: IP-literal endpoints usually need it, but providers that publish a matching IP subject-alt-name (e.g. Cloudflare `1.1.1.1`) validate either way
|- `probe --protocol tls` (library: `probe::tls_repeat`): repeated TLS handshakes aggregated into the same latency statistics (success rate, min/p50/p90/p95/p99/max, jitter, failure distribution) as the TCP and HTTP protocols, isolating TLS-negotiation latency per address — the handshake was previously only measurable as a single `tls` probe or folded into the HTTP repeat, so TLS-specific slowness (ClientHello RTT, resumption, cert-chain size) was not separately observable
|- `--strict` now also covers `dns` (exit non-zero when any resolver/lookup returned an error), `diagnose` (exit non-zero when any non-`Healthy` diagnosis was raised) and `route` (exit non-zero when any hop is lost) — the flag previously existed only on the per-address probe commands (`tcp`/`tls`/`http`/`http2`/`http3`/`probe`), so automation could not gate on these commands' observation-level failures. Observations are still rendered in full; only the exit status becomes non-zero
|- `diagnose` and the human `http`/`diagnose` output now surface a *truncated* HTTP response: when headers arrive but the body never completes within the probe bound, the text report shows `body: incomplete (timed out)` and the diagnostic engine raises a Low "HTTP response body did not complete" clue (proxy truncation, keep-alive without content-length/chunked, packet loss mid-transfer, never-finishing streams). The underlying evidence has existed since the body-completion fix; it was previously invisible to both renderings
|- Deterministic integration tests (`test_local_http.rs`) exercising the full probe pipeline against the local fixture — TCP, TLS (TLSv1.3), HTTP/1.1 200, HTTP/2 200 (ALPN h2) and HTTP/3 200 (QUIC) — with no external network
|- `*_with_roots` probe variants on `tls`, `http`, `http2` and `http3` to verify in-process fixtures with self-signed certificates
|- Evolve ip-tools into a network observability and diagnostics toolkit (measurement separated from deterministic diagnosis)
|- Async Tokio runtime foundation with explicit per-operation timeouts and bounded concurrency
|- Strongly typed observation model (`src/model/`): DNS, TCP, latency statistics, diagnosis types, failure-kind classification
|- DNS diagnostics: A + AAAA via system resolver and custom servers (`ip-tools dns`), with latency and per-resolver results
|- TCP connectivity probes with classified failure modes — timeout / refused / reset / unreachable (`ip-tools tcp`)
|- TLS handshake diagnostics with SNI, ALPN, cipher, TLS version, and certificate subject/issuer/validity (`ip-tools tls`)
|- HTTPS / HTTP1.1 probing over per-address TLS connections, with status, redirect, protocol and body size (`ip-tools http`)
|- HTTP/2 probing over a dedicated ALPN `h2` connection (`ip-tools http2`), keeping HTTP/1.1 and HTTP/2 as first-class distinctions
|- HTTP/3 / QUIC probing over the UDP path (`ip-tools http3`), with negotiated ALPN/TLS version captured, distinct from the TCP path
|- Route diagnostics (`ip-tools route`): Linux UDP/ICMP traceroute with per-hop TTL/address/RTT and loss, reverse-resolved router names, platform-gated and privilege-aware
|- Evidence-based diagnostic engine (`ip-tools diagnose`): deterministic, pure (no I/O) rules over the observations, producing severity / category / confidence / evidence / alternatives for DNS, connectivity, address-family, TLS, HTTP, QUIC and intermittent failures, plus a conservative multi-signal possible-filtering check (never high confidence)
|- Repeated probing with per-address latency statistics — success rate, min/p50/p90/p95/p99/max, jitter, failure distribution (`ip-tools probe --count N`)
|- IPv4/IPv6 kept as separate first-class dimensions per address
|- Human and `--json` output for all new subcommands
|- Target parsing supporting host, host:port, IP literals and bracketed IPv6
|- Documentation: core principle that a failed connection is an observation, not a verdict
|- Restore runnable doc-tests (`# Examples`) for the legacy local-IP helpers (`get_local_ip`, `list_net_ifs`) so the CI `doctest` job verifies real, compiled examples again
|- `--insecure` flag on `tls`, `http`, `http2`, `http3` and `diagnose` (plus `probe_insecure` library functions) to skip TLS/QUIC certificate validation for self-signed or private-PKI endpoints; signatures are still verified on the wire
|- `--server` custom DNS resolvers on `diagnose` (matching `dns`), so the diagnostic engine can observe resolver disagreement rather than only the system resolver's answer
|- `--server` custom DNS resolvers on every per-address probe subcommand (`tcp`, `tls`, `http`, `http2`, `http3`, `probe`), so probes can be steered through a trusted resolver (e.g. to check whether the system resolver is being steered); the address lookups now also honor `--timeout` instead of a hard-coded 5 s
|- `--strict` flag on `tcp`, `tls`, `http`, `http2`, `http3` and `probe`: exit non-zero when any address probe failed to complete (failed probes remain exit-0 observations by default), for scripting/CI use
|- `diagnose` text output now renders the full evidence stack — DNS, TCP, TLS, HTTP/1.1+2+3 and repeated probe phases — before the verdicts, instead of only DNS + TCP + verdicts (the observations were collected and shown in `--json`, but invisible in human output)
|- Repeat-probing for HTTP: `probe --protocol http|http2|http3` (with `--method`/`--insecure`) aggregates latency stats over HTTP/1.1, HTTP/2 or HTTP/3 via the new `probe::http_repeat`, `probe::http2_repeat` and `probe::http3_repeat` library functions; TCP remains the default, and the shared aggregation logic is unified behind `probe::repeat_impl`
|- DNS-over-HTTPS (RFC 8484): `dns --doh <https://.../dns-query>` (repeatable, plus `--insecure`) queries an encrypted DoH endpoint and reports it alongside the system/custom resolvers, so the local answer can be compared against a tamper-resistant one; no new dependencies (hand-rolled wire-format query/builder + base64url + response parser over the existing TLS/HTTP stack)
|- `diagnose --doh <endpoint>` folds DNS-over-HTTPS answers into both the evidence stack and the probed address set, so resolver disagreement between the local path and an encrypted path shows up in the diagnoses

### Fixed
|- `diagnose` no longer double-counts an HTTP/3 probe's *QUIC-path* timeout as an HTTP-layer error: `http_layer_rules` excluded a QUIC failure only when it surfaced as the `Quic` kind, but on a silent-UDP or stalled QUIC peer the same failure reaches the wall-clock bound as `Timeout` — so a healthy TCP+HTTPS host whose HTTP/3 probes simply timed out (e.g. a certificate-mismatch host, whose h3 row shows `quic handshake ... timed out`) got a misleading `HTTP-layer errors returned by hostname` diagnosis citing an "HTTP (not TLS) protocol problem". The h3 row now counts as an HTTP-layer error only for a genuine HTTP/3-protocol failure (`Http`/`Protocol` kind or a non-2xx status); every other h3 failure remains the QUIC path's verdict (`quic_rules`). HTTP/1.1+/2-over-TLS keep the existing kind-based exclusion (a request timeout there *is* the server not answering HTTP)
|- DoH endpoint URLs with an *unbracketed* IPv6 authority (e.g. `https://::1/dns-query`) are now rejected up front with a clear error instead of being misread as a bare host + port and failing later with a vague "could not resolve" message. RFC 3986 §3.2.2 requires IPv6 literals in a URI authority to be bracketed (`[::1]`); the parser now enforces that, and malformed authorities (unterminated `[`, non-numeric port, empty host) are all covered by unit tests
|- `probe --count 0` is now rejected with a clear error instead of rendering a vacuous "0 attempts, 0.0% success" report and exiting 0: a zero attempt count is a caller mistake, and the tool should not report a misleading all-zero success rate as if it had measured anything (the probe commands' `--count` now has the same "never probe zero times" guarantee `route` already applies to its hops)
|- `dns` no longer treats an IP-literal target as a hostname to resolve: `dns 1.1.1.1` (or `dns [::1]`) previously asked the resolvers to look up the *name* `1.1.1.1.` and reported a confusing `no records found` DNS error — and made `dns <literal> --strict` fail for an input that is already an address. `dns` now short-circuits literals like every other subcommand: the literal is reported as its own record for the matching address family (`A`/`AAAA`) and as a clean empty (NODATA-style) answer for the other, with no resolver consulted and a deterministic exit 0 under `--strict`
|- `diagnose` no longer raises a destination-side `PartialConnectivity` alarm when every failing address fails with a *local* no-route verdict: if the host's own stack reports `network unreachable`/`host unreachable` (ENETUNREACH / EHOSTUNREACH) for every failing address — e.g. an address family with no global route — no packet ever left the host for those addresses, so there is no path evidence that the destination's addresses are "only partially reachable". The reachability rule now stays quiet there and the address-family rule reports the local condition instead, matching how the filtering rule already treats local unreachability (it is not a path/filtering signal). As soon as even one failing address shows a genuine path failure (timeout / refused / reset), partial connectivity still fires with its normal confidence
|- `diagnose` no longer double-counts a QUIC or TLS failure as an HTTP-layer error: `http_layer_rules` used to raise "HTTP-layer errors returned by hostname" for any HTTP-family observation whose transport failed, so a failed HTTP/3 handshake on an otherwise-healthy host produced *both* that HTTP diagnosis *and* the dedicated `Quic` diagnosis for the same cause (and a TLS handshake failure produced HTTP + TLS). The HTTP-layer rule now counts only genuine HTTP-protocol-layer failures (an `Http`-kind error or a non-2xx status) and leaves `Quic` and `TlsHandshake`/`Certificate` failures to their own rules
|- Failed HTTP probes now keep their protocol identity: `HttpObservation::protocol` was only set on success, so a failed HTTP/2 / HTTP/3 probe lost it (rendered as `HTTP/1.1` in the report). Worse, the `QUIC/HTTP3 fails while TCP+HTTPS succeeds` diagnosis and the QUIC-only filtering signal match on `protocol == "HTTP/3"` — with real probes every failed h3 observation had no protocol, so both rules were dead in production. Each probe now tags its base observation with the protocol it is attempting before any step; the human report names the protocol on failure rows too
|- All three HTTP probes now agree on body-read semantics: `body_bytes` is `Some(n)` when the response body completed (end-of-stream or the cap) and `None` when headers were received but the body stalled past the probe timeout. Previously HTTP/2 and HTTP/3 reported a stalled body as a clean partial-body success (a mid-body timeout was indistinguishable from a full reply), and HTTP/1.1 reported a mid-body *transport error* as if the body had simply hit the 1 MiB cap (`Some(MAX_BODY_BYTES)`) instead of a failed observation. Local tests against an in-process `stall.invalid` fixture (headers + one chunk, then the server holds the stream open) verify all three report `status 200`, no failure, `body_bytes: None`
|- `diagnose`'s possible-filtering analysis no longer counts a *local* no-route condition as an independent signal: a TCP failure classified `network unreachable`/`host unreachable` (ENETUNREACH / EHOSTUNREACH) is reported by the host's own stack before any packet is sent (e.g. an address family with no global route), so it is not evidence of destination-specific filtering — only failures that actually occur on the path (timeout / refused / reset) count toward the "address-specific reachability" signal. Genuine reset+path-failure combinations still fire (Low confidence)
|- `diagnose` no longer raises a DNS-disagreement / possible-filtering alarm on a healthy dual-stack host whose IPv6 has no route: (1) resolver disagreement now compares per-*resolver* combined A+AAAA address sets instead of per `(resolver, record_type)` sets, so one resolver answering both families is a normal answer rather than "disagreeing with itself"; (2) TLS, HTTP and repeat-probe failures that merely *inherit* a TCP connect failure on the same address (no handshake/request was ever attempted) no longer count as independent layer or filtering signals — only genuine intermittency (mixed successes and failures on a reachable address) and genuine layer failures (TCP connected, upper layer failed) do
|- Probe commands (and `diagnose`) could not probe bracket-form IPv6 literals: `[::1]:443` parsed the bracketed hostname and sent it to DNS (`hostname [::1] did not resolve`) instead of using it as a literal address. Resolution now strips the brackets before the literal check (TLS/HTTP SNI/Host handling already dealt with bracketed IPv6 correctly)
|- DoH queries now surface the DNS response code: a `SERVFAIL`/`NXDOMAIN`/`REFUSED` answer (HTTP 200, non-NOERROR RCODE) is reported as a failed `Dns` observation instead of an empty-record success, and a 200 body that is not a valid DNS message reports an error rather than silently succeeding

### Tested
|- Deterministic error-path coverage for the handshake timeouts: HTTP/3 against a silent UDP socket times out (not success); HTTP/3 against a closed UDP port fails; TLS and HTTP/1.1 against a TCP listener that accepts but never speaks TLS hit the wall-clock `Timeout` bound
|- Two new hung-server behaviors for HTTP/3, via the local fixture: a server that accepts the request but never sends a response (`quiesce.invalid`) and a QUIC endpoint that completes the handshake but never establishes h3 (`stalled_quic_addr`) — both must time out cleanly (never hang, never report success)

### Changed
|- Add `tokio`, `hickory-resolver`, `rustls`, `tokio-rustls`, `rustls-native-certs`, `hyper`, `hyper-util`, `h2`, `quinn`, `h3`, `h3-quinn`, `http-body-util`, `x509-parser` and `libc` dependencies
|- Raise MSRV to 1.88 (required by hickory-resolver 0.26.1, which also ships the DNS security fixes below)
|- Upgrade `hickory-resolver` to 0.26.1 and move the DNS layer onto its new API (resolver construction and lookups return `Result`; lookups are read via the `answers` record set); drop the unused direct `hickory-proto` dependency; enable hickory-resolver's `serde` feature so `--server IP:PORT` custom DNS ports (non-53) keep working via the crate's own config schema
|- Add `.cargo/config.toml` with `resolver.incompatible-rust-versions = "fallback"` so `cargo update` selects dependency versions within the declared MSRV instead of silently pulling newer incompatible ones
|- Fix the public-API baseline gate: it previously used `cargo public-api diff` (no args), which under current tooling compares against the last *published* version and can therefore never pass between releases; it now diffs the tree's public API (simplified `-sss` output) directly against the committed `api-baseline.txt`, and CI pins `cargo-public-api` 0.52.0 and the nightly rustdoc toolchain that the baseline was generated with for reproducibility
|- Raise test coverage well above the 80% CI gate (92% lines today): unit tests for every report renderer, the DNS client against an in-process fake resolver, the diagnostic rule families, and full CLI integration tests that exercise the real binary against local listeners (subprocess runs are traced by llvm-cov)
|- Reorganize the library into `dns`, `tcp`, `tls`, `http`, `probe`, `model`, `report`, `target`, `error` modules (breaking but intentional)
|- Internal module splits (no API or behavior change): CLI dispatch split from the single `cli.rs` into `cli/` per-subcommand handlers sharing a thin `mod.rs` router; the diagnostic engine split from `diagnostics.rs` into `diagnostics/` (`dns`, `connectivity`, `layer`, `filtering`); TLS-observation and HTTP-error builders moved into a shared `http_common.rs`**
|- Deduplicate the per-address probe CLI handlers (`tcp`, `tls`, `http`, `http2`, `http3`, `probe`) behind a shared `run_probe_flow` pipeline in `cli/mod.rs`, and build their clap subcommands with a shared `probe_command` argument helper (no behavior or help-text change)
|- Run DNS resolution once in the `diagnose` pipeline: probe addresses are now derived from the same DNS observations (previously the hostname was resolved a second time); IP-literal targets no longer produce a spurious DNS observation
|- Move the shared HTTP-probe pieces into `http_common.rs` and the model: the `MAX_BODY_BYTES` cap, a generic `http_error`, and a reusable `HttpObservation::base` / `with_failure` on the model, so HTTP/1.1, HTTP/2 and HTTP/3 no longer duplicate the base-observation literal

### Security
|- Fix two DNS parsing advisories in `hickory-proto` 0.25.2 by upgrading to 0.26.1: RUSTSEC-2026-0118 (NSEC3 closest-encloser proof validation can loop on cross-zone responses) and RUSTSEC-2026-0119 (CPU exhaustion from O(n²) name compression during message encoding)

### Fixed
|- Allow the `BSD-3-Clause` (neli, neli-proc-macros, subtle) and `CDLA-Permissive-2.0` (webpki-root-certs) licenses in `deny.toml` so the cargo-deny gate reflects the actual permissive licenses used by the dependency graph
|- Fix `cargo doc` breaking under the `-D warnings` gate: `diagnostics` module docs linked private submodules, and the traceroute docs contained a stray `[UDP]` intra-doc link (both broke CI's docs job)
|- Close the raw ICMP socket on error paths in the Linux traceroute (it was leaked when UDP-probe binding or TTL setting failed mid-run)
|- Remove an always-false dead branch in the partial-connectivity confidence logic (failing and passing address sets are disjoint, so the comparison could never match; effective behavior is unchanged)

## [0.2.0] - 2026-07-24

### Added
|- Add editorconfig
|- Add renovate.json
|- Add a badge for [Rust GitHub Template](https://rust-github.github.io/)
|- Add CLI integration tests covering get, list, no-subcommand, flag rejection, and help output
|- Add assert_cmd and predicates as dev dependencies
|- Add pre-publish test step to cargo publish in CD workflow
|- Add husky-rs git hooks (pre-commit, commit-msg, pre-push) for local fmt/clippy/test enforcement
|- Add unit tests for IpToolsError (Display, source, From, Send+Sync) to improve coverage
|- Add coverage enforcement step to CI (`cargo llvm-cov --fail-under-lines 80`)
|- Document coverage testing with cargo-llvm-cov in CONTRIBUTING.md
|- Add `--json` global flag for machine-readable JSON output of `get` and `list` subcommands
|- Add CLI integration tests for JSON output structure (get, list, and global flag placement)
|- Add `#![warn(clippy::pedantic, clippy::nursery)]` to crate roots to enforce code quality standards locally and in CI
|- Update CI clippy and pre-push hook to explicitly check pedantic and nursery lints
|- Update CONTRIBUTING.md clippy command to include pedantic and nursery lints
|- Add runnable doc-tests (`# Examples`) to the public API (`get_local_ip`, `list_net_ifs`, `IpToolsError`) so documented examples are compiled and verified in CI
|- Add crate-level documentation (`//!`) with a quick-start example to `src/lib.rs`, providing the docs.rs front page for the library
|- Add an inline library usage snippet to README.md so readers see the `ip_tools` API at a glance
|- Add a runnable library example (`examples/ip_info.rs`) demonstrating `get_local_ip` and `list_net_ifs`; makes the CI docs job `--examples` flag meaningful

### Changed
|- Document the library example (`cargo run --example ip_info`) and clarify that `cargo test` runs doc-tests in CONTRIBUTING.md
|- Remove redundant `.version()` and `.about()` calls (and their now-unused `crate_version`/`crate_description` imports) from the CLI parser — `command!()` already sets these from Cargo.toml; behavior unchanged (`.author(crate_authors!("\n"))` kept for its multi-author separator)
|- Improve crate `description` (was the generic "IP Tools") and add `keywords` and `categories` to Cargo.toml for better crates.io discoverability; the new description also improves the CLI `--help` about text
|- Update pre-commit hook to run clippy with `-W clippy::pedantic -W clippy::nursery`, matching pre-push and CI (previously only pre-push and CI enforced these lints, so the local commit gate was weaker than CI for targets without a crate-level `#![warn]` attribute, e.g. examples)
|- Adopt `thiserror` for `IpToolsError`, replacing manual `Display`, `Error`, and `From` implementations with derive macros (reduces ~30 lines of boilerplate while maintaining identical public API)
|- Remove cli.yml
|- Add `serde` and `serde_json` as direct dependencies (already transitive via `clap`)
|- Remove redundant dependabot.yml — Renovate handles all dependency updates
|- Update clap to v4
|- Replace clap_derive with clap_builder
|- Replace CARGO_API_KEY with CARGO_REGISTRY_TOKEN
|- Refactor `get_local_ip` and `list_net_ifs` to return `Result` instead of panicking
|- Print errors to stderr and exit with non-zero status on failure
|- Add `ExitCode` return from CLI entry point
|- Replace placeholder tests with meaningful integration tests
|- Add benchmarks for `get_local_ip` and `list_net_ifs`
|- Modernize CD workflow: replace deprecated `actions-rs/toolchain` and `actions-rs/cargo` with `dtolnay/rust-toolchain` and direct `cargo` commands
|- Modernize audit workflow: replace deprecated `actions-rs/audit-check` with `cargo install cargo-audit` and direct `cargo audit`
|- Improve README with actual usage examples for `get` and `list` subcommands
|- Update clap from `~4.5.0` to `~4.6.0` (4.5.61 -> 4.6.4)
|- Update clap_builder to 4.6.2
|- Remove redundant `--ip` flag from `get` subcommand and `--all` flag from `list` subcommand
|- Fix pedantic clippy warnings: `handler` takes `&ArgMatches` instead of by value, use `&net_ifs` in for loops
|- Simplify `list_net_ifs` by removing unnecessary `let` binding and `Ok()` wrapper
|- Use Display format instead of Debug format for IP addresses in CLI output
|- Fix list output format from tab-separated to `name: ip`
|- Fix misleading doc comments on `get_local_ip` and `list_net_ifs` to clarify they return `Result`
|- Inline format arguments (e.g., `{e}` instead of `{}`, `e`) in string formatting

### Fixed
|- Fix broken checkbox format in bug report and feature request issue templates
|- Fix clippy command in CONTRIBUTING.md to match CI (`-D warnings`)
|- Fix README example output to match actual `name: ip` format (was tab-separated)
|- Run tests before `cargo publish` to prevent untested code from being published to crates.io

## [v0.1.0] - 2022-08-02

### Added
|- initial release
|- add clap for command line arguments
