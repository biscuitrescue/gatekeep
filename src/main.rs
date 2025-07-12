use clap::Parser;
use cli::{Cli, Commands};

mod cli;
mod agent;
mod core;

fn get_server() -> Result<String, anyhow::Error> {
    let owned = hostname::get()
        .map_err(|e| anyhow::anyhow!("Failed to get hostname {e}"))?
        .to_string_lossy()
        .into_owned();
    let default: String = owned;
    println!("Using {default} as hostname. Use --server for better accuracy");
    Ok(default)
}

fn main() -> anyhow::Result<()> {
    let cl = Cli::parse();

    match cl.command {
        Commands::Agent { config }=> {
            agent::run(&config);
        }
        Commands::Generate { server } => {
            let server_name: String = match server {
                Some(s) => s,
                None => get_server().unwrap(),
            };
            core::config::generate(&server_name)?;
        }
        Commands::Commit { message } => {
            cli::commit(&message)?;
        }
        Commands::Validate { path, server } => {
            let server_name: String = match server {
                Some(s) => s,
                None => get_server().unwrap(),
            };
            core::policy::validate(&path, &server_name)?;
        }
    }

    Ok(())
}
