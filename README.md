# ip-tools

[![Crates.io](https://img.shields.io/crates/v/ip-tools.svg)](https://crates.io/crates/ip-tools)
[![Docs.rs](https://docs.rs/ip-tools/badge.svg)](https://docs.rs/ip-tools)
[![CI](https://github.com/pplmx/ip-tools/workflows/CI/badge.svg)](https://github.com/pplmx/ip-tools/actions)
[![Coverage Status](https://coveralls.io/repos/github/pplmx/ip-tools/badge.svg?branch=main)](https://coveralls.io/github/pplmx/ip-tools?branch=main)
[![Rust GitHub Template](https://img.shields.io/badge/Rust%20GitHub-Template-blue)](https://rust-github.github.io/)

A small CLI tool to list network interfaces and retrieve the local IP address.

## Installation

### Cargo

* Install the rust toolchain in order to have cargo installed by following
  [this](https://www.rust-lang.org/tools/install) guide.
* run `cargo install ip-tools`

## Usage

### Get the local IP address

```shell
ip-tools get
```

Example output:

```
192.168.1.100
```

### List all network interfaces

```shell
ip-tools list
```

Example output:

```
lo:	127.0.0.1
eth0:	192.168.1.100
wlan0:	10.0.0.5
```

### Show help

```shell
ip-tools --help
```

## License

Licensed under either of

 * Apache License, Version 2.0
   ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license
   ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

See [CONTRIBUTING.md](CONTRIBUTING.md).
