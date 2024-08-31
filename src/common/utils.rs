use alloy::primitives::{Address as AlloyAddress, Bytes as rBytes, FixedBytes as rFixedBytes};
use anyhow::Result;
use ethers::core::rand::thread_rng;
use ethers::signers::{LocalWallet, Signer};
use ethers::types::BigEndianHash;
use ethers::types::{
    transaction::eip2930::{AccessList as eAccessList, AccessListItem},
    Bytes as eBytes, NameOrAddress, H160 as EthersH160, H160, H256, I256, U256,
};
use ethers_core::rand;
use ethers_core::rand::Rng;
use fern::colors::{Color, ColoredLevelConfig};
use log::LevelFilter;
use revm::precompile::{PrecompileSpecId, Precompiles};
use revm::primitives::{Address, SpecId, B256, U256 as rU256};
use rust_decimal::Decimal;
use serde::{Deserialize, Serialize};
use std::env;
use std::str::FromStr;

use crate::common::constants::{
    USDC_ADDRESS, USDC_BALANCE_SLOT, USDC_DECIMALS, USDT_ADDRESS, USDT_BALANCE_SLOT, USDT_DECIMALS,
    WETH_ADDRESS, WETH_BALANCE_SLOT, WETH_DECIMALS,
};

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

pub fn create_new_wallet() -> (LocalWallet, EthersH160) {
    let wallet = LocalWallet::new(&mut thread_rng());
    let address = wallet.address();
    (wallet, address)
}

pub fn ethers_u256_to_alloy_uint(input: ethers::types::U256) -> alloy::primitives::Uint<256, 4> {
    let mut bytes = [0u8; 32];
    input.to_big_endian(&mut bytes);
    alloy::primitives::Uint::from_be_bytes(bytes)
}

pub fn fixed_bytes_to_h256(fixed: rFixedBytes<32>) -> H256 {
    H256::from_slice(fixed.as_slice())
}

#[inline]
pub fn h160_to_b160(h: EthersH160) -> revm::primitives::Address {
    revm::primitives::Address::from_slice(h.as_bytes())
}

pub fn alloy_uint_to_ethers_u256(input: alloy::primitives::Uint<256, 4>) -> ethers::types::U256 {
    let bytes: [u8; 32] = input.to_be_bytes();
    ethers::types::U256::from_big_endian(&bytes)
}

pub fn b256_to_h256(b: B256) -> H256 {
    H256::from_slice(b.as_slice())
}

pub fn determine_main_currency(token_in: H160, token_out: H160) -> (MainCurrency, u8, i32) {
    if let Some((main_token, _)) = return_main_and_target_currency(token_in, token_out) {
        let main_currency = MainCurrency::new(main_token);
        (
            main_currency.clone(),
            main_currency.decimals(),
            main_currency.balance_slot(),
        )
    } else {
        // If neither token is a main currency, default to treating token_in as the "main" currency
        (
            MainCurrency::Default,
            MainCurrency::Default.decimals(),
            MainCurrency::Default.balance_slot(),
        )
    }
}

pub fn is_weth(token_address: H160) -> bool {
    token_address == to_h160(WETH_ADDRESS)
}
pub fn return_main_and_target_currency(token0: H160, token1: H160) -> Option<(H160, H160)> {
    let token0_supported = is_main_currency(token0);
    let token1_supported = is_main_currency(token1);

    if !token0_supported && !token1_supported {
        return None;
    }

    if token0_supported && token1_supported {
        let mc0 = MainCurrency::new(token0);
        let mc1 = MainCurrency::new(token1);

        let token0_weight = mc0.weight();
        let token1_weight = mc1.weight();

        if token0_weight > token1_weight {
            return Some((token0, token1));
        } else {
            return Some((token1, token0));
        }
    }

    if token0_supported {
        return Some((token0, token1));
    } else {
        return Some((token1, token0));
    }
}

pub fn sub_u256_to_i256(a: U256, b: U256) -> I256 {
    if a >= b {
        let result = a - b;
        I256::try_from(result).unwrap_or(I256::MAX)
    } else {
        let result = b - a;
        let neg_result = I256::try_from(result).unwrap_or(I256::MIN);
        -neg_result
    }
}

pub fn to_h160(str_address: &'static str) -> H160 {
    H160::from_str(str_address).unwrap()
}

pub fn h256_to_b256(h: H256) -> B256 {
    B256::from_slice(h.as_bytes())
}

pub fn u128_to_u256(value: u128) -> U256 {
    U256::from(value)
}

pub fn is_main_currency(token_address: H160) -> bool {
    let main_currencies = vec![
        to_h160(WETH_ADDRESS),
        to_h160(USDT_ADDRESS),
        to_h160(USDC_ADDRESS),
    ];
    main_currencies.contains(&token_address)
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]

pub enum MainCurrency {
    WETH_ADDRESS,
    USDT_ADDRESS,
    USDC_ADDRESS,
    Default, // Pairs that aren't WETH/Stable pairs. Default to WETH for now
}

impl MainCurrency {
    pub fn new(address: H160) -> Self {
        if address == to_h160(WETH_ADDRESS) {
            MainCurrency::WETH_ADDRESS
        } else if address == to_h160(USDT_ADDRESS) {
            MainCurrency::USDT_ADDRESS
        } else if address == to_h160(USDC_ADDRESS) {
            MainCurrency::USDC_ADDRESS
        } else {
            MainCurrency::Default
        }
    }

    pub fn decimals(&self) -> u8 {
        match self {
            MainCurrency::WETH_ADDRESS => WETH_DECIMALS,
            MainCurrency::USDT_ADDRESS => USDC_DECIMALS,
            MainCurrency::USDC_ADDRESS => USDC_DECIMALS,
            MainCurrency::Default => WETH_DECIMALS,
        }
    }

    pub fn balance_slot(&self) -> i32 {
        match self {
            MainCurrency::WETH_ADDRESS => WETH_BALANCE_SLOT,
            MainCurrency::USDT_ADDRESS => USDT_BALANCE_SLOT,
            MainCurrency::USDC_ADDRESS => USDC_BALANCE_SLOT,
            MainCurrency::Default => WETH_BALANCE_SLOT,
        }
    }

    /*
    We score the currencies by importance
    WETH has the highest importance, and USDT, USDC in the following order
    */
    pub fn weight(&self) -> u8 {
        match self {
            MainCurrency::WETH_ADDRESS => 3,
            MainCurrency::USDT_ADDRESS => 2,
            MainCurrency::USDC_ADDRESS => 1,
            MainCurrency::Default => 3, // default is WETH
        }
    }
}

pub fn u256_to_eth(value: U256) -> Decimal {
    // Convert U256 to a decimal string
    let wei_value = Decimal::from_str(&value.to_string()).unwrap();

    // Convert wei to ETH (1 ETH = 10^18 wei)
    let eth_value = wei_value / Decimal::from(10u64.pow(18));

    eth_value
}

pub fn access_list_to_ethers(access_list: Vec<(Address, Vec<rU256>)>) -> eAccessList {
    eAccessList::from(
        access_list
            .into_iter()
            .map(|(address, slots)| AccessListItem {
                address: b160_to_h160(address),
                storage_keys: slots
                    .into_iter()
                    .map(|y| H256::from_uint(&ru256_to_u256(y)))
                    .collect(),
            })
            .collect::<Vec<AccessListItem>>(),
    )
}

pub fn access_list_to_revm(access_list: eAccessList) -> Vec<(Address, Vec<rU256>)> {
    access_list
        .0
        .into_iter()
        .map(|x| {
            (
                h160_to_b160(x.address),
                x.storage_keys
                    .into_iter()
                    .map(|y| u256_to_ru256(y.0.into()))
                    .collect(),
            )
        })
        .collect()
}

pub fn alloy_to_ethers_bytes(alloy_bytes: rBytes) -> eBytes {
    eBytes::from(alloy_bytes.to_vec())
}

#[inline]
pub fn u256_to_ru256(u: ethers::types::U256) -> revm::primitives::U256 {
    let mut buffer = [0u8; 32];
    u.to_little_endian(buffer.as_mut_slice());
    revm::primitives::U256::from_le_bytes(buffer)
}

pub fn ethers_to_alloy_bytes(ethers_bytes: eBytes) -> rBytes {
    rBytes::from(ethers_bytes.to_vec())
}

pub fn get_precompiles_for(spec_id: SpecId) -> impl IntoIterator<Item = Address> {
    Precompiles::new(PrecompileSpecId::LATEST)
        .addresses()
        .into_iter()
        .map(|addr| *addr)
}
