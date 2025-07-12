use std::path::Path;
use std::fs::{read_to_string, create_dir_all};
use serde::{Serialize, Deserialize};
use crate::core::globals;

#[derive(Serialize, Deserialize)]
pub struct Config {
    pub key: String,
    pub key_type: String,
}

pub fn read_conf(file: &Path) -> anyhow::Result<Config> {
    let content = std::fs::read_to_string(file)
        .map_err(|e| anyhow::anyhow!("Failed to read file: {} with error: {}", file.to_str().unwrap(), e))?;
    let config = toml::from_str(&content)
        .map_err(|e| anyhow::anyhow!("Failed to convert toml to struct with err {e}"))?;
    Ok(config)
}

fn write_config(key: &str, key_type: &str, user: &str, server: &str) -> Result<(), std::io::Error> {
    let conf = Config {
        key: key.to_owned(),
        key_type: key_type.to_owned(),
    };

    // each server has diff directory
    // each user has separate file in ./configs/
    let path = globals::CUR_DIR.join(format!("config/{server}"));

    create_dir_all(path)?;

    let toml_string = toml::to_string_pretty(&conf)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    let path = Path::new("./config/").join(server).join(format!("{user}.toml"));
    std::fs::write(path, toml_string)?;

    Ok(())
}

pub fn generate(server: &str) -> anyhow::Result<()> {

    //  TODO: need to implement for windows also
    let path = globals::HOME_DIR.join(".ssh/authorized_keys");

    if !path.exists() {
        return Err(anyhow::anyhow!("no authorized keys exist"));
    }

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
        let key_type = remaining_str.next().unwrap_or("");
        let key = remaining_str.next().unwrap_or("");
        let user = remaining_str
            .next()
            .unwrap_or("")
            .split('@')
            .next()
            .unwrap_or("");

        let _ = write_config(key, key_type, user, server)?;
    }

    Ok(())
}
