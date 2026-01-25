use anyhow::Result;
use dirs::home_dir;
use once_cell::sync::Lazy;
use serde::Serialize;
use std::{fs::create_dir_all, path::PathBuf};

pub static CUR_DIR: Lazy<PathBuf> = Lazy::new(|| -> PathBuf {
    std::env::current_dir().expect("Couldnt get current working directory")
});

pub static HOME_DIR: Lazy<PathBuf> =
    Lazy::new(|| -> PathBuf { home_dir().expect("Couldnt get current working directory") });

pub fn write_toml<T: Serialize>(path: PathBuf, source: &T) -> Result<()> {
    if let Some(parent) = path.parent() {
        create_dir_all(parent)?;
    }

    let toml_string = toml::to_string_pretty(&source)
        .map_err(|e| anyhow::anyhow!("Couldnt make toml string with err {}", e))?;

    match std::fs::write(&path, toml_string) {
        Ok(()) => Ok(()),
        Err(e) => Err(anyhow::anyhow!(
            "Couldnt write toml to file: {} with error: {:?}",
            path.to_string_lossy(),
            e
        )),
    }
}

pub fn read_toml<T: serde::de::DeserializeOwned>(path: &PathBuf) -> Result<T> {
    let toml_string = std::fs::read_to_string(path).map_err(|e| {
        anyhow::anyhow!(
            "Couldnt read toml from file: {} with error: {:?}",
            path.to_string_lossy(),
            e
        )
    })?;

    toml::from_str(&toml_string)
        .map_err(|e| anyhow::anyhow!("Couldnt parse toml from string with error: {:?}", e))
}
