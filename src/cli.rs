// use anyhow::Ok;
use std::result::Result::Ok;
use clap::{Parser, Subcommand};
use std::fs::read_to_string;
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

pub fn generate(server: &str) -> anyhow::Result<()> {

    // set path
    let home_path= home_dir()
        .expect("Failed to get home directory!");
    let path = home_path.join(".ssh/authorized_keys");

    // reading
    let contents = match read_to_string(&path) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("Couldn't open file {path:?}: {e}");
            String::new()
        }
    };

    // Parsing
    for line in contents.lines().into_iter() {
        if line.trim().is_empty() || line.starts_with('#') { continue; }

        let mut remaining_str = line.split_whitespace();
        let keys = remaining_str.next().unwrap();
        println!("{keys}");
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
