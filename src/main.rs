#![warn(clippy::pedantic, clippy::nursery)]

mod cli;

fn main() -> std::process::ExitCode {
    cli::ip_tools_cli()
}
