use ethers::{prelude::Lazy, types::Bytes};

pub static PROJECT_NAME: &str = "gengar";

pub fn get_env(key: &str) -> String {
    std::env::var(key).unwrap_or(String::from(""))
}

#[derive(Debug, Clone)]
pub struct Env {
    pub https_url: String,
    pub wss_url: String,
    // pub private_key: String,
    // pub debug: bool,
}

impl Env {
    pub fn new() -> Self {
        Env {
            https_url: get_env("HTTPS_URL"),
            wss_url: get_env("WSS_URL"),
            // private_key: get_env("PRIVATE_KEY"),
            // debug: get_env("DEBUG").parse::<bool>().unwrap(),
        }
    }
}
