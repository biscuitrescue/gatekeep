use std::path::PathBuf;
use dirs::home_dir;
use once_cell::sync::Lazy;

pub static CUR_DIR: Lazy<PathBuf> = Lazy::new(|| -> PathBuf {
    std::env::current_dir()
        .expect("Couldnt get current working directory")
});

pub static HOME_DIR: Lazy<PathBuf> = Lazy::new(|| -> PathBuf {
    home_dir()
        .expect("Couldnt get current working directory")
});
