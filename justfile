# ip-tools justfile — network tool with library + binary
default:
    @just --list

# Build release binary
build:
    cargo build --release

# Run all tests
test:
    cargo test --all-features --workspace

# Format check (CI style)
fmt-check:
    cargo fmt --all --check

# Run clippy (CI style, matches project pedantic/nursery standards)
clippy:
    cargo clippy --all-targets --all-features --workspace -- -D warnings -W clippy::pedantic -W clippy::nursery

# Check documentation (CI style)
doc-check:
    RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --document-private-items --all-features --workspace --examples

# Run doctests (/// examples in src/lib.rs)
doctest:
    cargo test --doc --workspace --all-features

# Run coverage check
coverage:
    cargo llvm-cov --all-features --workspace --fail-under-lines 80

# Run benchmarks
bench:
    cargo bench --workspace

# Quick read-only checks (local loop)
quick: fmt-check clippy doc-check doctest test

# Full CI gate
ci: quick coverage msrv audit deny

# MSRV check
msrv:
    cargo +1.78 check --all-targets --all-features --workspace

# Auto-fix clippy + format
fix:
    cargo clippy --fix --allow-dirty --allow-staged --all-targets --all-features --workspace -- -D warnings -W clippy::pedantic -W clippy::nursery
    cargo fmt --all

# Security audit
audit:
    cargo audit

# Dependency policy check
deny:
    cargo deny check

# Clean build artifacts
clean:
    cargo clean
