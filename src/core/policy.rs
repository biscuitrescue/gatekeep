use serde::{Serialize, Deserialize};
use std::fs::create_dir_all;
use std::path::Path;

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

pub fn validate(path: &str, server: &str) -> anyhow::Result<()> {
    println!("validating path: {path} in server: {server}");
    Ok(())
}
