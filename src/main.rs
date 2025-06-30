use clap::Parser;
use cli::{Cli, Commands};

mod cli;
mod agent;
mod core;

fn main() -> anyhow::Result<()> {
    let cl = Cli::parse();

    match cl.command {
        Commands::Agent => {
            agent::run()?;
        }
        Commands::Generate { server, policy } => {
            cli::generate(&server, &policy)?;
        }
        Commands::Validate { path } => {
            cli::validate(&path)?;
        }
    }

    Ok(())
}
