use anyhow::Result;
use serde::{Serialize, Deserialize};
use std::borrow::Cow;

// #[derive(Serialize, Deserialize)]
// struct AgentConfig<'a> {
//     pub policysource: PolicySource<'a>,
// }

#[derive(Serialize, Deserialize)]
struct PolicySource<'a> {
    r#type: Cow<'a, str>,
    url: Cow<'a, str>,
    branch: Option<Cow<'a, str>>,
    ssh_key: Cow<'a, str>,
}

#[derive(Serialize, Deserialize)]
struct AuthKeys<'a> {
    path: &'a str,
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
