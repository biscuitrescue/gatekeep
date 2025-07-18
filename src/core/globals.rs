use std::path::PathBuf;
use dirs::home_dir;
use once_cell::sync::Lazy;
use serde::Serialize;
use anyhow::Result;

pub static CUR_DIR: Lazy<PathBuf> = Lazy::new(|| -> PathBuf {
    std::env::current_dir()
        .expect("Couldnt get current working directory")
});

pub static HOME_DIR: Lazy<PathBuf> = Lazy::new(|| -> PathBuf {
    home_dir()
        .expect("Couldnt get current working directory")
});

pub fn write_toml<T: Serialize>(path: PathBuf, source: &T) -> Result<()> {
    let toml_string = toml::to_string_pretty(&source)
        .map_err(|e| anyhow::anyhow!("Couldnt make toml string with err {}", e))?;

    match std::fs::write(&path, toml_string) {
        Ok(()) => Ok(()),
        Err(e) => Err(anyhow::anyhow!("Couldnt write toml to file: {} with error: {:?}", path.to_string_lossy(), e))
    }
}
