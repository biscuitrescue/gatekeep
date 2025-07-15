// use crate::core::config;
use anyhow::Result;

struct AgentConfig<'a> {
    r#type: &'a str,
    url: &'a str,

}

pub fn run(config: &str) -> ! {
    println!("Agent running with config path specified: {config}");

    loop {
        std::thread::sleep(std::time::Duration::from_secs(10));
    }
}

pub fn init(_conf_path: &str) -> Result<()> {
    Ok(())
}
