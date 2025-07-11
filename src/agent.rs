// use crate::core::config;

pub fn run(config: &str) -> ! {
    println!("Agent running with config path specified: {config}");

    loop {
        std::thread::sleep(std::time::Duration::from_secs(10));
    }
}
