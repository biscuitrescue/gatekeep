use std::{path::PathBuf, process::exit};
use clap::Args;
use anyhow::{Error, Result};
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
struct AgentConfig {
    pub policy_source: PolicySource,
    pub auth_keys: AuthKeys,
}

#[derive(Args, Serialize, Deserialize)]
#[derive(Clone)]
pub struct PolicySource {
    #[arg(long, default_value = "git")]
    pub r#type: String,

    #[arg(long)]
    pub url: String,

    #[arg(long)]
    pub branch: Option<String>,

    #[arg(long)]
    pub ssh_key: String,
}

#[derive(Serialize, Deserialize)]
struct AuthKeys {
    path: PathBuf
}

pub fn run(config: PathBuf) -> ! {
    println!("Agent running with config path specified: {}", config.to_string_lossy());

    loop {
        if !config.exists() {
            eprintln!("specified config.toml doesn't exist. Create with `gk agent init <args>`");
            exit;
        }
        std::thread::sleep(std::time::Duration::from_secs(10));
    }
} 

pub fn init(source: PolicySource, path: PathBuf) -> Result<()> {
    let config = AgentConfig {
        policy_source: source,
        auth_keys: AuthKeys { path: path }
    };

    Ok(())
}
