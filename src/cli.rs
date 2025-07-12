use clap::{Parser, Subcommand};
use std::result::Result::Ok;

#[derive(Parser)]
#[command(name = "gk", about = "Manually manage SSH access policies")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    Agent {
        #[arg(long, short)]
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
        #[arg(long)]
        path: String,

        #[arg(long)]
        server: Option<String>,
    },
}

pub fn commit(message: &str) -> anyhow::Result<()> {
    println!("Committed with message: {message}");
    Ok(())
}
