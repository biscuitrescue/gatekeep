use anyhow::Result;
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
struct AgentConfig {
    pub policy_source: PolicySource,
    pub aut_keys: AuthKeys,
}

#[derive(Serialize, Deserialize)]
struct PolicySource {
    r#type: String,
    url: String,
    branch: Option<String>,
    ssh_key: String,
}

#[derive(Serialize, Deserialize)]
struct AuthKeys {
    path: String
}

// TODO: add logging + security
// #[derive(Serialize, Deserialize)]
// struct Logging<'a> {

// }

// #[derive(Serialize, Deserialize)]
// struct Security<'a> {
// }


pub fn run(config: &str) -> ! {
    println!("Agent running with config path specified: {config}");

    loop {
        std::thread::sleep(std::time::Duration::from_secs(10));
    }
}

pub fn init(_conf_path: &str) -> Result<()> {
    Ok(())
}
