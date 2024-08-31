use anyhow::Error;
use anyhow::Result as AnyhowResult;

use log::{info, warn};
use std::sync::Arc;

use alloy_rpc_types_eth::Transaction as AlloyTransaction;
use ethers::core::types::{CallFrame, CallLogFrame};
use ethers::providers::{Provider, Ws};
use ethers::types::{H160, H256, U256};
use log::{debug, error};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use rust_decimal::prelude::FromPrimitive;
use rust_decimal::Decimal;
use std::sync::atomic::AtomicU64;
// use std::ops::Mul;
use std::str::FromStr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use ethers::abi::ParamType;

use crate::common::utils::{
    alloy_uint_to_ethers_u256, b160_to_h160, b256_to_h256, return_main_and_target_currency,
};
use crate::pools::DexVariant;

use crate::common::streams::{NewBlock, NewPendingTx};
use crate::pools::generic_pool::Pool;
use crate::simulation::optimizor::SwapHop;
use crate::simulation::tracing::debug_trace_call_with_retry;

// use mongodb::{options::ClientOptions, Client, Collection};
use crate::common::constants::{
    USDC_ADDRESS, USDC_BALANCE_SLOT, USDC_DECIMALS, USDT_ADDRESS, USDT_BALANCE_SLOT, USDT_DECIMALS,
    WETH_ADDRESS, WETH_BALANCE_SLOT, WETH_DECIMALS,
};
use crate::common::token_loader::Token;

use crate::simulation::types::*;

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]

pub enum SwapDirection {
    Buy,
    Sell,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct SwapInfo {
    pub tx_hash: H256,
    pub target_pair: H160,
    pub main_currency: Token,
    pub target_token: Token,
    // pub version: String,
    pub version: DexVariant,
    pub token0_is_main: bool,
    pub direction: SwapDirection,
    pub input_amount: U256,
    pub output_amount: U256,
    pub main_currency_type: String,
    pub main_currency_decimals: u8,
    pub main_currency_balance_slot: Option<u64>,
    // price_impact: Decimal,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct SwapPath {
    pub path: MatchedSwapPath,
    pub original_tx: AlloyTransaction,
}

// SwapPath
// └── MatchedSwapPath (is_multi_hop: false)
//     └── MatchedSwapHop (USDC -> ETH in USDC-ETH pool)

// SwapPath
// └── MatchedSwapPath (is_multi_hop: true)
//     ├── MatchedSwapHop (USDC -> ETH in USDC-ETH pool)
//     └── MatchedSwapHop (ETH -> WBTC in ETH-WBTC pool)
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct MatchedSwapPath {
    pub hops: Vec<MatchedSwapHop>,
    pub is_multi_hop: bool,
    pub total_input_amount: U256,
    pub total_output_amount: U256,
    pub input_token: Token,
    pub output_token: Token,
    // pub total_price_impact: Decimal,
}
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct MatchedSwapHop {
    pub hop: SwapHop,
    pub pool: Pool,
    pub swap_info: SwapInfo,
}

/*
Detected Routers
0x881d40237659c251811cec9c364ef91dc08d300c - Metamask Swap Router
0x3fc91a3afd70395cd496c647d5a6cc9d4b2b7fad - Uniswap router V2 or V3 hmmmmm
0xdef1c0ded9bec7f1a1670819833240f027b25eff
0x2ec705d306b51e486b1bc0d6ebee708e0661add1
0x3fc91a3afd70395cd496c647d5a6cc9d4b2b7fad
0x1111111254eeb25477b68fb85ed929f73a960582
0x0000000000007f150bd6f54c40a34d7c3d5e9f56
0x2ec705d306b51e486b1bc0d6ebee708e0661add1
 */

fn identify_dex(address: &H160) -> DexVariant {
    if *address == H160::from_str("0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D").unwrap() {
        DexVariant::UniswapV2
    } else if *address == H160::from_str("0xE592427A0AEce92De3Edee1F18E0157C05861564").unwrap() {
        DexVariant::UniswapV3
    } else if *address == H160::from_str("0xd9e1cE17f2641f24aE83637ab66a2cca9C378B9F").unwrap() {
        DexVariant::SushiswapV2
    } else {
        DexVariant::Unknown(format!("{:?}", address))
    }
}
pub static V2_SWAP_EVENT_ID: &str = "0xd78ad95f";
pub static V3_SWAP_EVENT_ID: &str = "0xc42079f9";
pub static SUSHISWAP_SWAP_EVENT_ID: &str = "0xd78ad95f"; // Same as Uniswap V2
pub static PANCAKESWAP_SWAP_EVENT_ID: &str = "0xd78ad95f"; // Same as Uniswap V2
                                                           // Add more as needed

pub async fn detect_swaps(
    provider: Arc<Provider<Ws>>,
    new_block: &NewBlock,
    pending_tx: &NewPendingTx,
    pools_map: &Arc<HashMap<H160, Pool>>,
    tokens_map: Arc<HashMap<H160, Token>>,
) -> AnyhowResult<Option<SwapPath>> {
    let start_time = Instant::now();
    // increment_transactions_processed();

    let router_address = pending_tx.tx.to.map(b160_to_h160).unwrap_or_default();
    // let dex = identify_dex(&router_address);

    // debug!(
    //     "Detecting swap for tx hash {:?}, DEX: {:?}",
    //     pending_tx.tx.hash, dex
    // );

    let call_frame = match debug_trace_call_with_retry(&provider, new_block, pending_tx, 3).await? {
        Some(frame) => frame,
        None => {
            debug!(
                "No call frame found for transaction {:?}",
                pending_tx.tx.hash
            );
            return Ok(None);
        }
    };

    let tx_hash_h256 = b256_to_h256(pending_tx.tx.hash);
    let mut logs = Vec::new();
    extract_logs(&call_frame, &mut logs);

    let swap_hops = extract_swap_hops(&logs, tx_hash_h256, pools_map, &tokens_map, router_address);

    if swap_hops.is_empty() {
        debug!("No swap hops identified for tx {:?}", pending_tx.tx.hash);
        return Ok(None);
    }

    let linked_paths = link_swap_hops(swap_hops);

    for path in linked_paths {
        if let Some(matched_path) =
            match_swap_with_pools(&path, pools_map, &tokens_map, tx_hash_h256)?
        {
            let swap_path = SwapPath {
                path: matched_path,
                original_tx: pending_tx.tx.clone(),
            };

            return Ok(Some(swap_path));
        }
    }

    debug!("No matched swap path found for tx {:?}", pending_tx.tx.hash);
    Ok(None)
}

fn extract_logs(call_frame: &CallFrame, logs: &mut Vec<CallLogFrame>) {
    // debug!("Running extract_logs for frame: {:?}", call_frame.to);

    if let Some(ref logs_vec) = call_frame.logs {
        // debug!("Found {} logs in current frame", logs_vec.len());
        for (i, log) in logs_vec.iter().enumerate() {
            // debug!("Log {}: {:?}", i, log);
        }
        logs.extend(logs_vec.iter().cloned());
    }

    if let Some(ref calls_vec) = call_frame.calls {
        // debug!("Processing {} nested calls", calls_vec.len());
        for (i, call) in calls_vec.iter().enumerate() {
            // debug!("Processing nested call {} to {:?}", i, call.to);
            extract_logs(call, logs);
        }
    }

    // debug!(
    //     "Finished extract_logs for frame: {:?}, total logs: {}",
    //     call_frame.to,
    //     logs.len()
    // );
}

fn extract_swap_hops(
    logs: &[CallLogFrame],
    tx_hash: H256,
    pools_map: &Arc<HashMap<H160, Pool>>,
    tokens_map: &Arc<HashMap<H160, Token>>,
    router_address: H160,
) -> Vec<SwapHop> {
    // debug!("Running extract_swap_hops on {} logs", logs.len());
    let mut swap_hops = Vec::new();
    for (i, log) in logs.iter().enumerate() {
        // debug!("Processing log {}", i);
        if let Some(swap_hop) =
            extract_single_swap(log, pools_map, tokens_map, tx_hash, router_address)
        {
            // debug!("Swap hop found in log {}: {:?}", i, swap_hop);
            swap_hops.push(swap_hop);
        }
    }
    // debug!(
    //     "Finished extract_swap_hops, found {} swap hops",
    //     swap_hops.len()
    // );
    swap_hops
}

fn link_swap_hops(swap_hops: Vec<SwapHop>) -> Vec<Vec<SwapHop>> {
    let mut linked_paths: Vec<Vec<SwapHop>> = Vec::new();
    let mut unlinked_hops: Vec<SwapHop> = swap_hops;

    while !unlinked_hops.is_empty() {
        let mut current_path: Vec<SwapHop> = vec![unlinked_hops.remove(0)];

        'outer: loop {
            let last_hop = current_path.last().unwrap();
            for i in 0..unlinked_hops.len() {
                if unlinked_hops[i].token_in == last_hop.token_out {
                    let next_hop = unlinked_hops.remove(i);
                    current_path.push(next_hop);
                    continue 'outer;
                }
            }
            break;
        }

        linked_paths.push(current_path);
    }

    linked_paths
}

fn extract_single_swap(
    log: &CallLogFrame,
    pools_map: &Arc<HashMap<H160, Pool>>,
    tokens_map: &Arc<HashMap<H160, Token>>,
    tx_hash: H256,
    router_address: H160,
) -> Option<SwapHop> {
    // info!("Extracting single swap for tx_hash {:?}", tx_hash);
    // debug!("Processing log {:?}", log);

    if let (Some(topics), Some(data), Some(address)) = (&log.topics, &log.data, log.address) {
        // debug!("Log has topics: {:?}", topics);
        if topics.len() > 1 {
            let selector = &format!("{:?}", topics[0])[0..10];
            // debug!("Selector: {}", selector);

            let is_v2_swap = selector == V2_SWAP_EVENT_ID;
            let is_v3_swap = selector == V3_SWAP_EVENT_ID;
            // debug!("Is V2 swap: {}, Is V3 swap: {}", is_v2_swap, is_v3_swap);

            if is_v2_swap || is_v3_swap {
                // debug!("Matched V2 or V3 swap event");
                if let Some(pool) = pools_map.get(&address) {
                    // debug!("Found pool for address: {:?}", address);
                    let token0 = b160_to_h160(pool.token0);
                    let token1 = b160_to_h160(pool.token1);

                    let (main_currency, target_token, token0_is_main) =
                        match return_main_and_target_currency(token0, token1) {
                            Some((main, target)) => (main, target, main == token0),
                            None => {
                                warn!(
                                    "Could not determine main and target currency for pool {:?}",
                                    address
                                );
                                return None;
                            }
                        };
                    // debug!(
                    //     "Main currency: {:?}, target_token: {:?}, token0_is_main: {:?}",
                    //     main_currency, target_token, token0_is_main
                    // );

                    if let Ok((in0, in1, out0, out1)) = decode_log_data(data) {
                        // debug!("Output of decode_log_data is in0: {:?}, in1: {:?}, out0: {:?}, out1: {:?}", in0, in1, out0, out1);

                        let zero_for_one = (in0 > U256::zero()) && (out1 > U256::zero());

                        // debug!("zero_for_one is {:?}", zero_for_one);

                        let direction = if token0_is_main {
                            if zero_for_one {
                                SwapDirection::Buy
                            } else {
                                SwapDirection::Sell
                            }
                        } else {
                            if zero_for_one {
                                SwapDirection::Sell
                            } else {
                                SwapDirection::Buy
                            }
                        };

                        let (token_in, token_out, amount_in, amount_out) = if zero_for_one {
                            (
                                tokens_map.get(&token0)?.clone(),
                                tokens_map.get(&token1)?.clone(),
                                in0,
                                out1,
                            )
                        } else {
                            (
                                tokens_map.get(&token1)?.clone(),
                                tokens_map.get(&token0)?.clone(),
                                in1,
                                out0,
                            )
                        };

                        // debug!(
                        //     "Swap details: token_in: {}, token_out: {}, main_currency: {}, direction: {:?}",
                        //     token_in.symbol, token_out.symbol, main_currency, direction
                        // );
                        // debug!("Determined swap direction: {:?}", direction);

                        let dex = identify_dex(&router_address);
                        // debug!("Identified DEX: {:?}", dex);

                        let swap_hop = SwapHop {
                            dex,
                            token_in,
                            token_out,
                            amount_in,
                            amount_out,
                            target_pair: address,
                            direction,
                            tx_hash,
                        };

                        // debug!("Created SwapHop: {:?}", swap_hop);
                        return Some(swap_hop);
                    } else {
                        // warn!("Failed to decode log data for tx hash {:?}", tx_hash);
                    }
                } else {
                    // warn!("No pool found for address: {:?}", address);
                }
            } else {
                // debug!("Not a V2 or V3 swap event for tx hash {:?}", tx_hash);
            }
        } else {
            // debug!(
            //     "Topic length is not greater than 1 for tx hash {:?}",
            //     tx_hash
            // );
        }
    } else {
        // warn!(
        //     "Log is missing topics, data, or address for tx hash {:?}",
        //     tx_hash
        // );
    }

    // debug!("No swap extracted for this log for tx hash {:?}", tx_hash);
    None
}

fn decode_log_data(data: &[u8]) -> Result<(U256, U256, U256, U256), ethers::abi::Error> {
    ethers::abi::decode(
        &[
            ParamType::Uint(256),
            ParamType::Uint(256),
            ParamType::Uint(256),
            ParamType::Uint(256),
        ],
        data,
    )
    .map(|tokens| {
        (
            tokens[0].clone().into_uint().unwrap(),
            tokens[1].clone().into_uint().unwrap(),
            tokens[2].clone().into_uint().unwrap(),
            tokens[3].clone().into_uint().unwrap(),
        )
    })
}

// Need to make an initial assessment to see the price impact and slippage indicates a failed transaction and compare it
// to the simulations to see if it did actually fail!

fn match_swap_with_pools(
    swap_path: &[SwapHop],
    pools_map: &Arc<HashMap<H160, Pool>>,
    tokens_map: &Arc<HashMap<H160, Token>>,
    tx_hash: H256,
) -> AnyhowResult<Option<MatchedSwapPath>> {
    // info!("Matching swap with pools for tx_hash {:?}", tx_hash);

    let mut matched_hops = Vec::new();
    let mut total_price_impact = Decimal::ZERO;

    // const MAX_ACCEPTABLE_IMPACT: f64 = 0.7; // 70%
    const MAX_ACCEPTABLE_IMPACT: f64 = 0.10; // 10%

    for (hop_index, hop) in swap_path.iter().enumerate() {
        // info!("Processing hop {} for tx {:?}", hop_index, tx_hash);
        // debug!("Hop details: {:?}", hop);

        if let Some(pool) = pools_map.get(&hop.target_pair) {
            // debug!("Found pool: {:?}", pool);

            let (main_currency, target_token) =
                return_main_and_target_currency(hop.token_in.address, hop.token_out.address)
                    .ok_or_else(|| {
                        let error_msg =
                            format!("No main currency found for pool in hop {}", hop_index);
                        error!("{}", error_msg);
                        Error::msg(error_msg)
                    })?;

            let token0_is_main = b160_to_h160(pool.token0) == main_currency;
            let zero_for_one = hop.token_in.address == b160_to_h160(pool.token0);

            // debug!(
            //     "Main currency: {:?}, Target token: {:?}",
            //     main_currency, target_token
            // );
            // debug!(
            //     "token0_is_main: {}, zero_for_one: {}",
            //     token0_is_main, zero_for_one
            // );

            let main_currency_info = tokens_map
                .get(&main_currency)
                .ok_or_else(|| Error::msg(format!("Token info not found for {}", main_currency)))?;

            let fee = Decimal::from_f64(pool.fee as f64 / 10000.0).unwrap_or(Decimal::ZERO);

            let (reserve_in, reserve_out) = if zero_for_one {
                (
                    alloy_uint_to_ethers_u256(pool.reserves0),
                    alloy_uint_to_ethers_u256(pool.reserves1),
                )
            } else {
                (
                    alloy_uint_to_ethers_u256(pool.reserves1),
                    alloy_uint_to_ethers_u256(pool.reserves0),
                )
            };

            // debug!(
            //     "Reserve in: {:?}, Reserve out: {:?}",
            //     reserve_in, reserve_out
            // );

            // let price_impact =
            //     calculate_price_impact(hop.amount_in, hop.amount_out, reserve_in, reserve_out, fee);

            // info!("Calculated price impact: {}", price_impact);

            // if price_impact >= Decimal::from_f64(MAX_ACCEPTABLE_IMPACT).unwrap() {
            //     warn!(
            //         "High price impact detected: {:.4}% for hop {} in tx {:?}",
            //         price_impact, hop_index, tx_hash
            //     );
            //     // continue;
            // }

            // total_price_impact += price_impact;

            let main_currency_balance_slot = get_balance_slot(main_currency);
            let main_currency_decimals = match main_currency {
                address if address == H160::from_str(WETH_ADDRESS).unwrap() => WETH_DECIMALS,
                address if address == H160::from_str(USDT_ADDRESS).unwrap() => USDT_DECIMALS,
                address if address == H160::from_str(USDC_ADDRESS).unwrap() => USDC_DECIMALS,
                _ => main_currency_info.decimals,
            };

            let output_token = tokens_map
                .get(&target_token)
                .expect("Token in not found in tokens_map");

            let swap_info = SwapInfo {
                tx_hash,
                target_pair: hop.target_pair,
                main_currency: main_currency_info.clone(),
                target_token: output_token.clone(),
                version: pool.version.clone(),
                token0_is_main,
                direction: hop.direction.clone(),
                input_amount: hop.amount_in,
                output_amount: hop.amount_out,
                main_currency_type: main_currency_info.symbol.clone(),
                main_currency_decimals,
                main_currency_balance_slot,
                // price_impact,
            };

            // debug!("Created swap_info: {:?}", swap_info);

            let matched_hop = MatchedSwapHop {
                hop: hop.clone(),
                pool: pool.clone(),
                swap_info,
            };
            matched_hops.push(matched_hop);
        } else {
            let error_msg = format!(
                "Pool not found for target pair: {:?} in hop {}",
                hop.target_pair, hop_index
            );
            warn!("{}", error_msg);
            return Ok(None);
        }
    }

    if matched_hops.is_empty() {
        warn!("No matched hops found for tx {:?}", tx_hash);
        return Ok(None);
    }

    let is_multi_hop = matched_hops.len() > 1;
    let total_input_amount = matched_hops
        .first()
        .map(|h| h.hop.amount_in)
        .unwrap_or_default();
    let total_output_amount = matched_hops
        .last()
        .map(|h| h.hop.amount_out)
        .unwrap_or_default();
    let input_token = matched_hops
        .first()
        .map(|h| h.hop.token_in.clone())
        .unwrap_or_default();
    let output_token = matched_hops
        .last()
        .map(|h| h.hop.token_out.clone())
        .unwrap_or_default();

    let matched_swap_path = MatchedSwapPath {
        hops: matched_hops,
        is_multi_hop,
        total_input_amount,
        total_output_amount,
        input_token,
        output_token,
        // total_price_impact,
    };

    // info!("Successfully matched swap path for tx {:?}", tx_hash);
    // debug!("Matched swap path: {:?}", matched_swap_path);

    Ok(Some(matched_swap_path))
}

fn u256_to_decimal(value: U256) -> Decimal {
    let (quotient, remainder) = value.div_mod(U256::from(10u64.pow(18)));
    let integer_part = Decimal::from_u128(quotient.as_u128()).unwrap_or(Decimal::MAX);
    let fractional_part = Decimal::from_u128(remainder.as_u128()).unwrap_or(Decimal::ZERO)
        / Decimal::from(10u64.pow(18));
    integer_part + fractional_part
}
fn get_balance_slot(token_address: H160) -> Option<u64> {
    match token_address {
        // USDC
        address if address == H160::from_str(USDC_ADDRESS).unwrap() => {
            Some(USDC_BALANCE_SLOT as u64)
        }
        // USDT
        address if address == H160::from_str(USDT_ADDRESS).unwrap() => {
            Some(USDT_BALANCE_SLOT as u64)
        }
        // WETH
        address if address == H160::from_str(WETH_ADDRESS).unwrap() => {
            Some(WETH_BALANCE_SLOT as u64)
        }
        // For other tokens, we return None
        _ => None,
    }
}
