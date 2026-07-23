use clap::{command, crate_authors, Arg, ArgAction, ArgMatches, Command};
use ip_tools::{get_local_ip, list_net_ifs};
use serde::Serialize;
use std::net::IpAddr;
use std::process::ExitCode;

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

pub fn ip_tools_cli() -> ExitCode {
    let matches = parser();
    handler(&matches)
}

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
        .subcommands(vec![
            Command::new("list").about("list all network interfaces"),
            Command::new("get").about("get the local IP address"),
        ])
        .get_matches()
}

fn handler(app_m: &ArgMatches) -> ExitCode {
    match app_m.subcommand() {
        Some(("list", sub_m)) => {
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
                        println!("{}", serde_json::to_string(&interfaces).unwrap());
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
        Some(("get", sub_m)) => {
            let json = sub_m.get_flag("json");
            match get_local_ip() {
                Ok(ip) => {
                    if json {
                        println!("{}", serde_json::to_string(&IpOutput { ip }).unwrap());
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
        _ => {
            // Unreachable: arg_required_else_help(true) makes clap print help
            // and exit before handler is called when no subcommand is given.
            eprintln!("Error: no subcommand provided");
            ExitCode::FAILURE
        }
    }
}
