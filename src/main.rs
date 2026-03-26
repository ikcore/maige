use clap::Parser;
use maige::cli;
use maige::commands;

fn main() {
    let cli = cli::Cli::parse();

    if let Err(e) = commands::run_command(cli.command, cli.passphrase) {
        eprintln!("Error: {:#}", e);
        std::process::exit(1);
    }
}
