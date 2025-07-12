use serde::{Serialize, Deserialize};
use std::fs::create_dir_all;
use std::path::Path;
use crate::core::{config, globals};

#[derive(Serialize, Deserialize)]
struct Policy {
    pub user: String,
    pub key: String,
    pub key_type: String,
}

fn write_policy(key: &str, key_type: &str, user: &str, server: &str) -> Result<(), anyhow::Error> {
    let policy = Policy {
        user: user.to_owned(), // TODO: use lifetimes
        key: key.to_owned(),
        key_type: key_type.to_owned(),
    };

    // Each server has different policy
    create_dir_all("./policy")?;

    let toml_string = toml::to_string_pretty(&policy)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
    let path = Path::new("./policy").join(format!("{server}.toml"));
    std::fs::write(path, toml_string)?;

    Ok(())
}

pub fn validate(user: &str, server: &str) -> anyhow::Result<()> {
    let conf_path = globals::CUR_DIR.join(format!("config/{server}/{user}.toml"));

    if !conf_path.exists() {
        return Err(anyhow::anyhow! (
            format!("config path: {} doesnt exist", conf_path.to_string_lossy()))
        );
    }

    if let Ok(conf) = config::read_conf(&conf_path) {
        write_policy(&conf.key, &conf.key_type, user, server)?;
    }

    Ok(())
}
