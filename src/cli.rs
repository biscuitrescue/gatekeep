use clap::{Parser, Subcommand};
use dirs::home_dir;
use std::fs::read_to_string;
use std::result::Result::Ok;
use crate::core::config;

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
        path: String,
    },
}


pub fn generate(server: &str) -> anyhow::Result<()> {

    // set path
    let home_path = home_dir().expect("Failed to get home dir");

    //  TODO: need to implement for windows also
    let path = home_path.join(".ssh/authorized_keys");

    let contents = match read_to_string(&path) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Couldn't open file {path:?}: {e}");
            String::new()
        }
    };

    // Parsing auth_keys
    for line in contents.lines().into_iter() {
        if line.trim().is_empty() || line.starts_with('#') {
            continue;
        }

        let mut remaining_str = line.split_whitespace();
        let key_type = remaining_str.next().unwrap_or("").to_owned();
        let key = remaining_str.next().unwrap_or("").to_owned();
        let user = remaining_str
            .next()
            .unwrap_or("")
            .split('@')
            .next()
            .unwrap_or("")
            .to_owned();

        let _ = config::write_to_toml(key, key_type, user, server.to_owned());
    }

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
