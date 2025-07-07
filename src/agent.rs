use std::{thread::sleep, time::Duration};
// use crate::core::config;

pub fn run(config: &str) -> ! {
    println!("Agent running with config path specified: {config}");

    loop {
        sleep(Duration::from_secs(10));
    }
}
