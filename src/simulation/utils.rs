use alloy::providers::Provider as AlloyProvider;
use alloy::transports::{BoxTransport, Transport};
use alloy_network::AnyNetwork;
use anyhow::Result;
use eth_encode_packed::ethabi;
use eth_encode_packed::ethabi::{ParamType, Token};
use ethers::types::{H160, U256};
use ethers::utils::hex;
use std::str::FromStr;

use crate::common::evm::EvmSimulator;

pub fn extract_and_decode_error(error_message: &str) -> Option<String> {
    // Look for "EVM REVERT: " in the error message
    if let Some(revert_data_start) = error_message.find("EVM REVERT: ") {
        let revert_data = &error_message[revert_data_start + 12..]; // Skip "EVM REVERT: "

        // Find the end of the hex data (it might be followed by other information)
        let revert_data_end = revert_data.find('/').unwrap_or(revert_data.len());
        let revert_data = &revert_data[..revert_data_end];

        // Remove any whitespace and decode the hex
        let revert_data = revert_data.trim();
        if let Ok(decoded) = hex::decode(revert_data) {
            return decode_revert_error(&decoded);
        }
    }
    None
}

fn decode_revert_error(revert_data: &[u8]) -> Option<String> {
    if revert_data.len() > 4 {
        // The first 4 bytes are the error selector, which we can ignore
        let encoded_message = &revert_data[4..];
        if let Ok(decoded) = ethabi::decode(&[ParamType::String], encoded_message) {
            if let Some(Token::String(message)) = decoded.get(0) {
                return Some(message.clone());
            }
        }
    }
    None
}

pub fn get_v2_amount_out(amount_in: U256, reserve_in: U256, reserve_out: U256) -> U256 {
    // info!("Executing common_functions.get_v2_amount_out()");

    // Calculate the amount of tokens received in a Uniswap V2 swap
    // using the constant product formula.

    // Calculate the amount of tokens in after the fee is deducted
    let amount_in_with_fee = amount_in * U256::from(997);

    // Calculate the numerator of the formula
    let numerator = amount_in_with_fee * reserve_out;

    // Calculate the denominator of the formula
    let denominator = (reserve_in * U256::from(1000)) + amount_in_with_fee;

    // Calculate the amount of tokens out using checked division
    let amount_out = numerator.checked_div(denominator);

    // Return the amount of tokens out, or the default value if division failed
    amount_out.unwrap_or_default()
}

pub fn convert_usdt_to_weth<'a, P>(
    simulator: &mut EvmSimulator<'a, P>,
    // provider: &Arc<P>,
    amount: U256,
) -> Result<U256>
where
    P: AlloyProvider<BoxTransport, AnyNetwork> + 'static + Clone,
    // P: AlloyProvider<PubSubFrontend, AnyNetwork> + 'static + Clone,
{
    // info!("Executing common_functions.convert_usdt_to_weth()");

    // Convert USDT to WETH using the Uniswap V2 USDT/WETH pair.

    // Get the address of the USDT/WETH pair
    let conversion_pair = H160::from_str("0x0d4a11d5EEaaC28EC3F61d100daF4d40471f1852").unwrap();

    // Get the reserves of the USDT/WETH pair
    let reserves = simulator.get_pair_reserves(conversion_pair)?;

    // Extract the reserves for USDT and WETH
    let (reserve_in, reserve_out) = (reserves.1, reserves.0);

    // Calculate the amount of WETH received using the get_v2_amount_out function
    let weth_out = get_v2_amount_out(amount, reserve_in, reserve_out);

    // Return the amount of WETH received
    Ok(weth_out)
}

pub fn convert_usdc_to_weth<'a, P>(
    simulator: &mut EvmSimulator<'a, P>,
    amount: U256,
) -> Result<U256>
where
    P: AlloyProvider<BoxTransport, AnyNetwork> + 'static + Clone,
    // P: AlloyProvider<PubSubFrontend, AnyNetwork> + 'static + Clone,
{
    // info!("Executing common_functions.convert_usdc_to_weth()");

    // Convert USDC to WETH using the Uniswap V2 USDC/WETH pair.

    // Get the address of the USDC/WETH pair
    let conversion_pair = H160::from_str("0xB4e16d0168e52d35CaCD2c6185b44281Ec28C9Dc").unwrap();

    // Get the reserves of the USDC/WETH pair
    let reserves = simulator.get_pair_reserves(conversion_pair)?;

    // Extract the reserves for USDC and WETH
    let (reserve_in, reserve_out) = (reserves.0, reserves.1);

    // Calculate the amount of WETH received using the get_v2_amount_out function
    let weth_out = get_v2_amount_out(amount, reserve_in, reserve_out);

    // Return the amount of WETH received
    Ok(weth_out)
}
