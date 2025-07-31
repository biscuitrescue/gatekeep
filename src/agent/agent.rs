use anyhow::{Error, Result};
use clap::{Subcommand, Args};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::core::globals;

#[derive(Subcommand, Clone)]
pub enum AgentSubcommand {
    Init {
        #[clap(flatten)]
        source: crate::agent::agent::PolicySource,

        #[arg(long, short, default_value = globals::CUR_DIR.join("docs/agent/config.toml").into_os_string())]
        path: PathBuf,

        #[arg(long, short)]
        auth_path: PathBuf,
    },

    Run {
        #[arg(long, short)]
        config: Option<String>,
    },
}

#[derive(Serialize, Deserialize)]
struct AgentConfig {
    pub policy_source: PolicySource,
    pub auth_keys: AuthKeys,
}

#[derive(Args, Serialize, Deserialize, Clone)]
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
    path: PathBuf,
}

pub fn run(config: PathBuf) -> Error {
    println!(
        "Agent running with config path specified: {}",
        config.to_string_lossy()
    );

    loop {
        if !config.exists() {
            return anyhow::anyhow!(
                "specified config.toml doesn't exist. Create with `gk agent init <args>`"
            );
        }
        // TODO: Read config.toml ?? globals?
        std::thread::sleep(std::time::Duration::from_secs(10));
    }
}

pub fn init(source: PolicySource, path: PathBuf, auth_path: PathBuf) -> Result<()> {
    globals::write_toml(
        path,
        &AgentConfig {
            policy_source: source,
            auth_keys: AuthKeys { path: auth_path },
        },
    )
}
