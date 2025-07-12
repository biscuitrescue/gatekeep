use clap::{Parser, Subcommand};
use dirs::home_dir;
use serde::Serialize;
use std::fs::read_to_string;
use std::{path::Path, result::Result::Ok};

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

#[derive(Serialize)]
struct Config {
    key: String,
    key_type: String,
}

// TODO: Move to another file
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

        let _ = write_to_toml(key, key_type, user, server.to_owned());
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

// FIX: error handling
fn write_to_toml(key: String, key_type: String, user: String, server: String) -> Result<(), std::io::Error> {
    let conf = Config {
        key: key,
        key_type: key_type,
    };

    // each user has separate file in ./policies/
    std::fs::create_dir_all(format!("./policies/{server}"))?;

    let toml_string = toml::to_string_pretty(&conf)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    let path = Path::new("./policies/").join(server).join(format!("{user}.toml"));
    std::fs::write(path, toml_string)?;

    Ok(())
}
