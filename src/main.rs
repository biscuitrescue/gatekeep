use clap::Parser;
use cli::{Cli, Commands};

mod cli;
mod agent;
mod core;

fn main() -> anyhow::Result<()> {
    let cl = Cli::parse();

    match cl.command {
        Commands::Agent { config }=> {
            agent::run(&config);
        }
        Commands::Generate { server } => {
            let server_name: String = match server {
                Some(s) => s,
                None => {
                    let default: String = hostname::get()
                        .map_err(|e| anyhow::anyhow!("Failed to get hostname {e}"))?
                        .to_string_lossy()
                        .into_owned();
                    default
                }
            };
            cli::generate(&server_name)?;
        }
        Commands::Commit { message } => {
            cli::commit(&message)?;
        }
        Commands::Validate { path } => {
            cli::validate(&path)?;
        }
    }

    Ok(())
}
