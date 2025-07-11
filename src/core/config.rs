pub fn read_conf(file: String) -> Result<(), anyhow::Error> {
    let path = std::path::Path::new(&file);
    let content = std::fs::read_to_string(path).expect("Failed to read file");
    Ok(toml::from_str(&content)?)
}
