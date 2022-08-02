use clap::{arg, App, ArgMatches};

// This function is used to build the CLI parser.
// pub fn clap_yaml_parser() -> ArgMatches {
//     let yaml = load_yaml!("cli.yml");
//     return App::from_yaml(yaml).get_matches();
// }

pub fn clap_builder_parser() -> ArgMatches {
    return App::new("ip-tools")
        .version("0.1.0")
        .author("Mystic")
        .about("A command line interface for the Rust language")
        .arg(arg!(-c --config <CONFIG_FILE> "Sets a custom config file").required(false))
        .arg(arg!(-i --input <INPUT_FILE> "Sets the input file to use").required(false))
        .arg(arg!(-o --output <OUTPUT_FILE> "Sets the output file to use").required(false))
        .arg(arg!(-v --verbose "Prints verbose output").required(false))
        .get_matches();
}
