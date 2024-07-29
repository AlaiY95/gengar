use alloy::primitives::{Address as AlloyAddress, Bytes as rBytes, FixedBytes as rFixedBytes};
use anyhow::Result;
use ethers::types::{
    transaction::eip2930::{AccessList as eAccessList, AccessListItem},
    Bytes as eBytes, NameOrAddress, H160 as EthersH160, I256, U256,
};
use ethers_core::rand;
use ethers_core::rand::Rng;
use fern::colors::{Color, ColoredLevelConfig};
use log::LevelFilter;
use revm::primitives::{Address, SpecId, B256, U256 as rU256};
use std::env;
pub fn setup_logger() -> Result<(), fern::InitError> {
    // Configure colors for log levels
    let colors = ColoredLevelConfig {
        trace: Color::Cyan,
        debug: Color::Magenta,
        info: Color::Green,
        warn: Color::Red,
        error: Color::BrightRed,
        ..ColoredLevelConfig::new()
    };

    // Read RUST_LOG environment variable, default to "info" if not set
    let log_level = match env::var("RUST_LOG") {
        Ok(level) => level.parse::<LevelFilter>().unwrap_or(LevelFilter::Info),
        Err(_) => LevelFilter::Info,
    };

    let console_dispatch = fern::Dispatch::new()
        .format(move |out, message, record| {
            out.finish(format_args!(
                "{}[{}] {}",
                chrono::Local::now().format("[%H:%M:%S]"),
                colors.color(record.level()),
                message
            ))
        })
        .chain(std::io::stdout())
        .level(log_level)
        // Add these lines to filter out specific modules
        .level_for("ethers", LevelFilter::Warn)
        .level_for("jsonrpsee", LevelFilter::Warn);

    let file_dispatch = fern::Dispatch::new()
        .format(|out, message, record| {
            out.finish(format_args!(
                "{}[{}] {}",
                chrono::Local::now().format("[%Y-%m-%d][%H:%M:%S]"),
                record.level(),
                message
            ))
        })
        .level(log_level)
        // Add these lines here too if you want to filter file logs as well
        .level_for("ethers", LevelFilter::Warn)
        .level_for("jsonrpsee", LevelFilter::Warn)
        .chain(fern::log_file("output.log")?);

    fern::Dispatch::new()
        .chain(console_dispatch)
        .chain(file_dispatch)
        .apply()?;

    Ok(())
}

#[inline]
pub fn b160_to_h160(b: revm::primitives::Address) -> EthersH160 {
    EthersH160::from(b.0.as_ref())
}

#[inline]
pub fn ru256_to_u256(u: revm::primitives::U256) -> ethers::types::U256 {
    ethers::types::U256::from_little_endian(&u.as_le_bytes())
}

#[inline]
pub fn u256_to_f64(value: U256) -> f64 {
    let mut result = 0.0;
    let mut current = value;
    let mut digit = 0;

    while !current.is_zero() {
        let (new_current, remainder) = current.div_mod(U256::from(10u64));
        result += (remainder.low_u64() as f64) * 10f64.powi(digit);
        current = new_current;
        digit += 1;
    }

    result
}

#[inline]
pub fn eth_to_wei(eth_amount: f64) -> rU256 {
    let wei_per_eth = rU256::from(10).pow(rU256::from(18));
    let eth_amount_u256 = rU256::from((eth_amount * 1e18) as u64);
    eth_amount_u256 * wei_per_eth / rU256::from(10).pow(rU256::from(18))
}

pub fn calculate_next_block_base_fee(
    gas_used: u128,
    gas_limit: u128,
    base_fee_per_gas: u128,
) -> u128 {
    let mut target_gas_used = gas_limit / 2;
    target_gas_used = if target_gas_used == 0 {
        1
    } else {
        target_gas_used
    };

    let new_base_fee = {
        if gas_used > target_gas_used {
            base_fee_per_gas
                + ((base_fee_per_gas * (gas_used - target_gas_used)) / target_gas_used) / 8
        } else {
            base_fee_per_gas
                - ((base_fee_per_gas * (target_gas_used - gas_used)) / target_gas_used) / 8
        }
    };

    let seed = rand::thread_rng().gen_range(0..9);
    new_base_fee + seed as u128
}
