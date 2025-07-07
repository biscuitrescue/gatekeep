use clap::{Parser, Subcommand};
use std::fs::read;
use dirs::home_dir;

#[derive(Parser)]
#[command(name = "gk", about = "Manually manage SSH access policies")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    Agent {
        #[arg(long, short, default_value = "gk.yaml")]
        config: String,
    },

    Generate {
        #[arg(long)]
        server: Option<String>,
    },

    Commit {
        #[arg(long)]
        message: String,
    },

    Validate {
        path: String,
    },
}

pub fn generate(_server: &str) -> anyhow::Result<()> {
    let home_path= home_dir()
        .expect("Failed to get home directory!");
    let path = home_path.join(".ssh/authorized_keys");

    if path.exists() { println!("exists"); }

    Ok(())
}

pub fn validate(path: &str) -> anyhow::Result<()> {
    println!("validating path: {path}");
    Ok(())
}

pub fn commit(message: &str) -> anyhow::Result<()> {
    println!("Committed with message: {message}");
    Ok(())
}
