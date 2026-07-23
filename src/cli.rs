use clap::{command, crate_authors, crate_description, crate_version, ArgMatches, Command};
use ip_tools::{get_local_ip, list_net_ifs};
use std::process::ExitCode;

pub fn ip_tools_cli() -> ExitCode {
    let matches = parser();
    handler(matches)
}

fn parser() -> ArgMatches {
    command!()
        .arg_required_else_help(true)
        .version(crate_version!())
        .author(crate_authors!("\n"))
        .about(crate_description!())
        .subcommands(vec![
            Command::new("list").about("list all network interfaces"),
            Command::new("get").about("get the local IP address"),
        ])
        .get_matches()
}

fn handler(app_m: ArgMatches) -> ExitCode {
    match app_m.subcommand() {
        Some(("list", _)) => match list_net_ifs() {
            Ok(net_ifs) => {
                for (name, ip) in net_ifs.iter() {
                    println!("{name}: {ip}");
                }
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("Error: {e}");
                ExitCode::FAILURE
            }
        },
        Some(("get", _)) => match get_local_ip() {
            Ok(ip) => {
                println!("{ip}");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("Error: {e}");
                ExitCode::FAILURE
            }
        },
        _ => {
            // Unreachable: arg_required_else_help(true) makes clap print help
            // and exit before handler is called when no subcommand is given.
            eprintln!("Error: no subcommand provided");
            ExitCode::FAILURE
        }
    }
}
