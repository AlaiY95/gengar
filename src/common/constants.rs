use ethers::{prelude::Lazy, types::Bytes};

pub static PROJECT_NAME: &str = "gengar";

pub fn get_env(key: &str) -> String {
    std::env::var(key).unwrap_or(String::from(""))
}

#[derive(Debug, Clone)]
pub struct Env {
    pub https_url: String,
    pub wss_url: String,
    pub bot_address: String,
    pub private_key: String,
    pub debug: bool,
}

impl Env {
    pub fn new() -> Self {
        Env {
            https_url: get_env("HTTPS_URL"),
            wss_url: get_env("WSS_URL"),
            bot_address: get_env("BOT_ADDRESS"),
            private_key: get_env("PRIVATE_KEY"),
            debug: get_env("DEBUG").parse::<bool>().unwrap(),
        }
    }
}

pub static COINBASE: &str = "0xDAFEA492D9c6733ae3d56b7Ed1ADB60692c98Bc5"; // Flashbots Builder

pub static WETH_ADDRESS: &str = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2";
pub static USDT_ADDRESS: &str = "0xdAC17F958D2ee523a2206206994597C13D831ec7";
pub static USDC_ADDRESS: &str = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48";

pub static WETH_BALANCE_SLOT: i32 = 3;
pub static USDT_BALANCE_SLOT: i32 = 2;
pub static USDC_BALANCE_SLOT: i32 = 9;

pub static WETH_DECIMALS: u8 = 18;
pub static USDT_DECIMALS: u8 = 6;
pub static USDC_DECIMALS: u8 = 6;

pub static UNISWAP_V2_PAIR_INIT_CODE_HASH: &str =
    "0x96e8ac4277198ff8b6f785478aa9a39f403cb768dd02cbee326c3e7da348845f";
