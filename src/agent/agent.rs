#![allow(unused)]
use std::path::PathBuf;

use clap::Args;
use anyhow::Result;
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
    path: String
}

pub fn run(config: PathBuf) -> ! {
    println!("Agent running with config path specified: {}", config.to_string_lossy());

    loop {
        std::thread::sleep(std::time::Duration::from_secs(10));
    }
}

pub fn init(source: PolicySource, path: &str) -> Result<()> {

    let config = AgentConfig {
        policy_source: source,
        auth_keys: AuthKeys { path: path.to_owned() }
    };

    Ok(())
}
