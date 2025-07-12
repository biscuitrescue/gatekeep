use serde::Serialize;
use std::path::Path;

#[derive(Serialize)]
struct Config {
    key: String,
    key_type: String,
}
pub fn _read_conf(file: String) -> anyhow::Result<()>{
    let path = std::path::Path::new(&file);
    let content = std::fs::read_to_string(path).expect("Failed to read file");
    Ok(toml::from_str(&content)?)
}

pub fn write_to_toml(key: String, key_type: String, user: String, server: String) -> Result<(), std::io::Error> {
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
