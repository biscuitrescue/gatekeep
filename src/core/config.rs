use std::path::Path;
use dirs::home_dir;
use std::fs::{read_to_string, create_dir_all};
use serde::{Serialize, Deserialize};

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

fn write_config(key: String, key_type: String, user: String, server: String) -> Result<(), std::io::Error> {
    let conf = Config {
        key: key,
        key_type: key_type,
    };

    // each server has diff directory
    // each user has separate file in ./configs/
    create_dir_all(format!("./config/{server}"))?;

    let toml_string = toml::to_string_pretty(&conf)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    let path = Path::new("./config/").join(server).join(format!("{user}.toml"));
    std::fs::write(path, toml_string)?;

    Ok(())
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

        let _ = write_config(key, key_type, user, server.to_owned());
    }

    Ok(())
}
