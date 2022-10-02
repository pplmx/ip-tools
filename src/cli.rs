use clap::{arg, command, crate_authors, crate_description, crate_version, ArgMatches, Command};

use crate::handler::{get_local_ip, list_net_ifs};

pub fn ip_tools_cli() {
    let matches = parser();
    handler(matches);
}

// This function is used to build the CLI parser.
// pub fn clap_yaml_parser() -> ArgMatches {
//     let yaml = load_yaml!("cli.yml");
//     return App::from_yaml(yaml).get_matches();
// }

fn parser() -> ArgMatches {
    command!()
        .arg_required_else_help(true)
        .version(crate_version!())
        .author(crate_authors!("\n"))
        .about(crate_description!())
        // .args(&[
        //     arg!(--config <FILE> "a required file for the configuration and no short"),
        //     arg!(-d --debug ... "turns on debugging information and allows multiples"),
        //     arg!([input] "an optional input file to use")
        // ])
        .subcommands(vec![
            Command::new("list")
                .about("list all network interfaces")
                .arg(arg!(--all "list all network interfaces"))
                .arg(arg!(--get_if_addrs "list all network interfaces")),
            Command::new("get")
                .about("get the local IP address")
                .arg(arg!(--ip "get the local IP address")),
        ])
        .get_matches()
}

fn handler(app_m: ArgMatches) {
    match app_m.subcommand() {
        Some(("list", sub_m)) => {
            if sub_m.contains_id("all") {
                list_net_ifs();
            }
        }
        Some(("get", sub_m)) => {
            if sub_m.contains_id("ip") {
                get_local_ip();
            }
        }
        Some(("commit", sub_m)) => {
            println!("Subcommand: {:?}", sub_m);
        }
        _ => {
            // If no subcommand was used, print an help message
            println!("No subcommand was used.");
        }
    }
}
