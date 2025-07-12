use serde::{Serialize, Deserialize};
use std::fs::create_dir_all;
use std::path::Path;
use crate::core::config;

#[derive(Serialize, Deserialize)]
struct Policy {
    user: String,
    key: String,
    key_type: String,
}

fn write_policy(key: String, key_type: String, user: String, server: String) -> Result<(), anyhow::Error> {
    let policy = Policy{
        user: user,
        key: key,
        key_type: key_type,
    };

    // Each server has different policy
    create_dir_all(format!("./policy"))?;

    let toml_string = toml::to_string_pretty(&policy)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    let path = Path::new("./policy").join(format!("{server}.toml"));
    std::fs::write(path, toml_string)?;

    Ok(())
}

pub fn validate(user: &str, server: &str) -> anyhow::Result<()> {
    let conf_path = Path::new("./config").join(server).join(format!("{user}.toml"));
    // let config = config::read_conf(conf_path);
    println!("{}", conf_path.to_string_lossy());
    Ok(())
}
