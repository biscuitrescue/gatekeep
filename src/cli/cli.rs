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
        #[clap(subcommand)]
        subcommand: AgentSubcommand,
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
        user: String,

        #[arg(long)]
        server: Option<String>,
    },
}

#[derive(Subcommand)]
#[derive(Clone)]
pub enum AgentSubcommand {
    Init {
        #[clap(flatten)]
        source: crate::agent::agent::PolicySource,
        #[arg(long, short, default_value = "./docs/config.toml")]
        config: String,
    },

    Run {
        #[arg(long, short)]
        config: Option<String>,
    },
}



pub fn commit(message: &str) -> anyhow::Result<()> {
    println!("Committed with message: {message}");
    Ok(())
}
