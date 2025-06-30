use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "gk", about = "Manually manage SSH access policies")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    Agent,

    Generate {
        #[arg(long)]
        server: String,

        #[arg(long)]
        policy: String,
    },

    Validate {
        path: String,
    },
}

pub fn generate(server: &str, policy: &str) -> anyhow::Result<()> {
    println!("KeyGen... server: {server}, policy: {policy}");
    Ok(())
}

pub fn validate(path: &str) -> anyhow::Result<()> {
    println!("validating path: {path}");
    Ok(())
}
