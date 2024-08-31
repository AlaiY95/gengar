use alloy::primitives::{I256, U256 as rU256};
use alloy::transports::BoxTransport;
use alloy_network::AnyNetwork;
use alloy_provider::{Provider as AlloyProvider, ProviderBuilder};
use alloy_rpc_types_eth::Transaction as AlloyTransaction;

use ethers::types::{H160, H256, U256};
use ethers::utils::hex;

use anyhow::{anyhow, Result};
use log::{debug, info, warn};
use revm::primitives::B256;
use serde::{Deserialize, Serialize};
use serde_json::to_string_pretty;
use std::time::{Duration, Instant};
use std::{collections::HashMap, sync::Arc};

use crate::common::constants::Env;
use crate::common::streams::NewBlock;
use crate::common::token_loader::Token;
use crate::common::utils::{
    alloy_uint_to_ethers_u256, b160_to_h160, ethers_u256_to_alloy_uint, h160_to_b160, h256_to_b256,
    ru256_to_u256, u128_to_u256,
};
use crate::pools::generic_pool::Pool;
use crate::pools::DexVariant;
use crate::simulation::batch_sandwich::BatchSandwich;
use crate::simulation::types::{
    MiddleTx, PendingTxInfo, Sandwich, SandwichPath, SimulatedSandwich,
};
use crate::strategies::hop_extractor::{MatchedSwapPath, SwapDirection, SwapPath};

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct SwapHop {
    pub dex: DexVariant,
    pub token_in: Token,
    pub token_out: Token,
    pub amount_in: U256,
    pub amount_out: U256,
    pub target_pair: H160,
    pub direction: SwapDirection,
    pub tx_hash: H256,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OptimalSandwich {
    pub front_run_amount: U256,
    pub back_run_amount: U256,
    pub estimated_profit: I256, // Add this field
    pub path: SandwichPath,
    pub simulated_result: SimulatedSandwich,
    pub iteration_count: u32,
    pub search_completed: bool,
    hop_index: usize,
}

pub enum SandwichTarget {
    FirstHop,
    LastHop,
    AllHops,
    FirstOrLastHop(bool), // true for first hop, false for last hop
}

pub async fn generate_and_simulate_paths(
    wss_url: String,
    new_block: Arc<NewBlock>,
    tx_hash: H256,
    swap_path: SwapPath,
    pools_map: Arc<HashMap<H160, Pool>>,
    tokens_map: Arc<HashMap<H160, Token>>,
    pending_tx_info: &PendingTxInfo,
) -> Result<HashMap<B256, Vec<Sandwich>>> {
    let start_time = Instant::now();
    info!(
        "Starting generate_and_simulate_paths for tx_hash: {:?}",
        tx_hash
    );

    // Commented as we cannot pass Mutex to the simulate function which uses Send + Sync
    // So we check if confirmed before calling generate_and_simulate_paths
    // Check if pending_tx is still not confirmed
    // let b256_tx_hash = h256_to_b256(tx_hash);
    // if !pending_txs.contains_key(&b256_tx_hash) {
    //     info!(
    //         "Transaction {:?} not found in pending_txx within generate_and_simulate_paths, skipping",
    //         tx_hash
    //     );
    //     return Ok(HashMap::new());
    // }

    // Check if it's a multi-hop transaction
    if swap_path.path.is_multi_hop {
        // info!("Skipping multi-hop transaction: {:?}", tx_hash);
        return Ok(HashMap::new());
    }

    // Check if there's at least one hop
    if swap_path.path.hops.is_empty() {
        // info!("Skipping transaction with no hops: {:?}", tx_hash);
        return Ok(HashMap::new());
    }

    let middle_hop = &swap_path.path.hops[0];

    if middle_hop.hop.direction != SwapDirection::Buy {
        // info!("Skipping non-Buy direction transaction: {:?}", tx_hash);
        return Ok(HashMap::new());
    }

    let env = Env::new();
    let provider = Arc::new(
        ProviderBuilder::new()
            .network::<AnyNetwork>()
            .with_recommended_fillers()
            .on_builtin(&env.wss_url)
            .await?,
    );
    // let pending_txs = Arc::new(pending_txs.clone());

    let pending_tx_info_arc = Arc::new(pending_tx_info.clone());

    let original_tx = swap_path.original_tx.clone();

    let sandwich_paths = generate_sandwich_paths(&swap_path, &pools_map);
    // debug!(
    //     "Generated {} sandwich paths for single-hop transaction",
    //     sandwich_paths.len()
    // );

    let mut sandwiches_map: HashMap<B256, Vec<Sandwich>> = HashMap::new();

    for path in sandwich_paths {
        match binary_search_optimal_amounts(
            provider.clone(),
            new_block.clone(),
            tx_hash,
            Arc::new(path),
            pools_map.clone(),
            tokens_map.clone(),
            // pending_txs.clone(),
            pending_tx_info_arc.clone(),
            0, // Always 0 for single-hop
            &original_tx,
        )
        .await
        {
            Ok(Some((optimal, swap_path, middle_tx))) => {
                let sandwich = Sandwich {
                    amount_in: optimal.front_run_amount,
                    swap_path,
                    middle_tx,
                    optimal_sandwich: Some(optimal.clone()),
                    hop_index: 0,
                };
                sandwiches_map
                    .entry(h256_to_b256(tx_hash))
                    .or_insert_with(Vec::new)
                    .push(sandwich);
            }
            Ok(None) => info!(
                "Skipping unprofitable sandwich opportunity for transaction {:?}",
                tx_hash
            ),
            Err(e) => warn!(
                "Error in optimal sandwich calculation for transaction {:?}: {:?}",
                tx_hash, e
            ),
        }
    }

    // Sort sandwiches by estimated profit (if any)
    for sandwiches in sandwiches_map.values_mut() {
        sandwiches.sort_by(|a, b| {
            b.optimal_sandwich
                .as_ref()
                .unwrap()
                .estimated_profit
                .cmp(&a.optimal_sandwich.as_ref().unwrap().estimated_profit)
        });
    }

    info!(
        "Found {} profitable sandwiches for tx_hash: {:?}",
        sandwiches_map.len(),
        tx_hash
    );

    if !sandwiches_map.is_empty() {
        if let Some(best_sandwich) = sandwiches_map.values().next().and_then(|v| v.first()) {
            if let Some(optimal) = &best_sandwich.optimal_sandwich {
                info!(
                    "Best sandwich for tx_hash {:?}: amount_in: {:?}, estimated_profit: {:?}",
                    tx_hash, optimal.front_run_amount, optimal.estimated_profit
                );
            }
        }
    }

    let duration = start_time.elapsed();

    info!(
        "Time taken to generate sandwich map for tx_hash {:?} is {:?}",
        tx_hash, duration
    );

    Ok(sandwiches_map)
}

fn generate_sandwich_paths(
    swap_path: &SwapPath,
    pools_map: &HashMap<H160, Pool>,
) -> Vec<SandwichPath> {
    info!("Starting to generate sandwich paths");

    let middle_hop = &swap_path.path.hops[0]; // We know there's only one hop
    let middle_pool_address = middle_hop.hop.target_pair;
    let token_to_buy = middle_hop.hop.token_out.address;
    let token_to_sell = middle_hop.hop.token_in.address;

    // debug!("middle swap details:");
    // debug!("  middle pool address: {:?}", middle_pool_address);
    // debug!("  Token to buy: {:?}", token_to_buy);
    // debug!("  Token to sell: {:?}", token_to_sell);

    // Check if the middle's pool exists in our pools_map
    if let Some(middle_pool) = pools_map.get(&middle_pool_address) {
        // Create a single sandwich path using the middle's pool for front-run, middle, and back-run
        let sandwich_path = SandwichPath {
            front_run: middle_hop.clone(),
            middle_hops: vec![middle_hop.clone()],
            back_run: middle_hop.clone(),
            hop_index: 0,
        };

        // info!("Generated sandwich path:");
        // info!("  Front run: {:?}", sandwich_path.front_run);
        // info!("  middle hop: {:?}", sandwich_path.middle_hops[0]);
        // info!("  Back run: {:?}", sandwich_path.back_run);

        vec![sandwich_path]
    } else {
        // warn!(
        //     "middle's pool {:?} not found in pools_map",
        //     middle_pool_address
        // );
        Vec::new()
    }
}

const MIN_ITERATIONS: usize = 3;
const MAX_ITERATIONS: usize = 20;
const PROFIT_IMPROVEMENT_THRESHOLD: U256 = U256([5 * 10u64.pow(14), 0, 0, 0]); // 0.0005 ETH
const MIN_SEARCH_RANGE: U256 = U256([5 * 10u64.pow(14), 0, 0, 0]); // 0.0005 ETH
const CONCURRENCY_LEVEL: usize = 3;
const MAX_CONSECUTIVE_UNPROFITABLE: usize = 3;
// const SIGNIFICANT_LOSS_THRESHOLD: I256 = I256::from_raw(U256([10u64.pow(16), 0, 0, 0])); // 0.01 ETH

async fn binary_search_optimal_amounts<P>(
    provider: Arc<P>,
    new_block: Arc<NewBlock>,
    tx_hash: H256,
    path: Arc<SandwichPath>,
    pools_map: Arc<HashMap<H160, Pool>>,
    tokens_map: Arc<HashMap<H160, Token>>,
    // pending_txs: Arc<HashMap<B256, PendingTxInfo>>,
    pending_tx_info: Arc<PendingTxInfo>,
    hop_index: usize,
    original_tx: &AlloyTransaction,
) -> Result<Option<(OptimalSandwich, SwapPath, MiddleTx)>>
where
    P: AlloyProvider<BoxTransport, AnyNetwork> + 'static + Clone + Send + Sync,
{
    info!(
        "Starting Binary Search Optimal for tx_hash: {:?}, hop {}",
        tx_hash, hop_index
    );

    let (mut low, mut high) = determine_search_range(&path, tx_hash, &pools_map, &pending_tx_info)?;
    // debug!(
    //     "Initial search range for hop {} - low: {}, high: {}",
    //     hop_index, low, high
    // );

    let tx_hash = path.middle_hops[0].hop.tx_hash;
    let short_hash = &tx_hash.as_bytes()[0..7];
    let short_hash_str = hex::encode(short_hash);

    let mut best_profit = I256::MIN;
    let mut best_amount = U256::zero();
    let mut best_simulated_sandwich = None;
    let mut iteration_count = 0;
    let mut best_middle_tx = None;
    let mut consecutive_unprofitable = 0;
    let mut previous_profit = I256::MIN;

    for iteration in 0..MAX_ITERATIONS {
        iteration_count = iteration + 1;
        debug!(
            "Hop {}, Iteration {}: tx_hash: {:?}, Current range - low: {}, high: {}",
            hop_index, iteration, short_hash_str, low, high
        );

        let mid = low.saturating_add(high) / 2;
        let amounts = generate_diverse_amounts(mid, low, high, CONCURRENCY_LEVEL);

        info!(
            "Hop {}, Iteration {}: Testing amounts: {:?}",
            hop_index, iteration, amounts
        );

        let mut best_local_profit = I256::MIN;
        let mut best_local_amount = U256::zero();
        let mut best_local_simulated_sandwich = None;
        let mut best_local_middle_tx = None;
        let mut all_unprofitable = true;

        for &amount in amounts.iter() {
            match simulate_sandwich(
                provider.clone(),
                &new_block,
                tx_hash,
                &path,
                amount,
                &pools_map,
                &tokens_map,
                &pending_tx_info,
                hop_index,
                &original_tx,
            )
            .await
            {
                Ok((profit, simulated_result, middle_tx, continue_search)) => {
                    if !continue_search {
                        info!(
                            "Hop {}, Iteration {}: Simulation suggests stopping search for amount: {}",
                            hop_index, iteration, amount
                        );
                        return Ok(None);
                    }
                    info!(
                        "Hop {}, Iteration {}: Simulated amount: {}, profit: {}",
                        hop_index, iteration, amount, profit
                    );
                    if profit > I256::ZERO {
                        all_unprofitable = false;
                    }
                    if profit > best_local_profit {
                        best_local_profit = profit;
                        best_local_amount = amount;
                        best_local_simulated_sandwich = Some(simulated_result);
                        best_local_middle_tx = Some(middle_tx);
                    }
                }
                Err(e) => warn!(
                    "Hop {}, Iteration {}: Simulation error for amount {}: {:?}",
                    hop_index, iteration, amount, e
                ),
            }
        }

        if best_local_profit > best_profit {
            let improvement = best_local_profit.saturating_sub(best_profit);
            info!(
                "Hop {}, Iteration {}: New best profit found. Old: {}, New: {}, Improvement: {}",
                hop_index, iteration, best_profit, best_local_profit, improvement
            );
            best_middle_tx = best_local_middle_tx.clone();

            best_profit = best_local_profit;
            best_amount = best_local_amount;
            best_simulated_sandwich = best_local_simulated_sandwich;
            consecutive_unprofitable = 0;

            if improvement < I256::from_raw(ethers_u256_to_alloy_uint(PROFIT_IMPROVEMENT_THRESHOLD))
                && iteration >= MIN_ITERATIONS
            {
                info!(
                    "Hop {}, Iteration {}: Improvement below threshold and MIN_ITERATIONS reached. Stopping search.",
                    hop_index, iteration
                );
                break;
            }
        } else {
            consecutive_unprofitable += 1;
            info!(
                "Hop {}, Iteration {}: No improvement. Consecutive unprofitable: {}",
                hop_index, iteration, consecutive_unprofitable
            );
        }

        if all_unprofitable {
            high = mid;
            info!(
                "Hop {}, Iteration {}: All amounts unprofitable. Adjusting high to: {}",
                hop_index, iteration, high
            );
        } else if best_local_amount == amounts[CONCURRENCY_LEVEL - 1] {
            low = mid;
            info!(
                "Hop {}, Iteration {}: Best amount at upper bound. Adjusting low to: {}",
                hop_index, iteration, low
            );
        } else {
            high = best_local_amount + (mid - low) / 2;
            low = best_local_amount.saturating_sub((mid - low) / 2);
            info!(
                "Hop {}, Iteration {}: Adjusting range. New low: {}, New high: {}",
                hop_index, iteration, low, high
            );
        }

        if high.saturating_sub(low) <= MIN_SEARCH_RANGE {
            info!(
                "Hop {}, Iteration {}: Search range smaller than minimum. Stopping search.",
                hop_index, iteration
            );
            break;
        }

        if consecutive_unprofitable >= MAX_CONSECUTIVE_UNPROFITABLE {
            info!(
                "Hop {}, Iteration {}: {} consecutive unprofitable iterations. Stopping search.",
                hop_index, iteration, MAX_CONSECUTIVE_UNPROFITABLE
            );
            break;
        }

        // if best_profit < -SIGNIFICANT_LOSS_THRESHOLD && iteration >= MIN_ITERATIONS {
        //     info!(
        //         "Hop {}, Iteration {}: Significant loss detected. Stopping search.",
        //         hop_index, iteration
        //     );
        //     break;
        // }

        if best_profit < previous_profit && iteration >= MIN_ITERATIONS {
            info!(
                "Hop {}, Iteration {}: Profit decreasing. Stopping search.",
                hop_index, iteration
            );
            break;
        }

        previous_profit = best_profit;
    }

    info!(
        "Hop {}: Binary search completed after {} iterations. Best amount: {}, Best profit: {}",
        hop_index, iteration_count, best_amount, best_profit
    );

    if best_profit <= I256::ZERO || best_simulated_sandwich.is_none() || best_middle_tx.is_none() {
        info!(
            "Hop {}: No profitable sandwich found or missing data. Best profit: {}",
            hop_index, best_profit
        );
        return Ok(None);
    }

    let best_swap_path = create_swap_path_from_sandwich(&path, best_amount, tx_hash, original_tx);

    debug!("Completed Binary search for tx_hash {:?}", tx_hash);

    Ok(Some((
        OptimalSandwich {
            front_run_amount: best_amount,
            back_run_amount: best_amount,
            estimated_profit: best_profit,
            path: (*path).clone(),
            simulated_result: best_simulated_sandwich.expect("We checked for None above"),
            iteration_count: iteration_count.try_into().unwrap(),
            search_completed: true,
            hop_index,
        },
        best_swap_path,
        best_middle_tx.expect("We checked for None above"),
    )))
}

fn generate_diverse_amounts(mid: U256, low: U256, high: U256, count: usize) -> Vec<U256> {
    let mut amounts = vec![mid];
    let range = high.saturating_sub(low);
    let step = range / U256::from(count as u64);

    for i in 1..count {
        let offset = step.saturating_mul(U256::from(i as u64));
        let amount = if i % 2 == 0 {
            mid.saturating_add(offset)
        } else {
            mid.saturating_sub(offset)
        };
        amounts.push(amount.clamp(low, high));
    }

    amounts
}

// 0.0005 ETH (5 * 10^14 wei)
const MIN_BOUND: U256 = U256([5 * 10u64.pow(14), 0, 0, 0]);

// 0.2 ETH (2 * 10^17 wei)
// const MAX_UPPER_BOUND: U256 = U256([2 * 10u64.pow(17), 0, 0, 0]);
// const MAX_UPPER_BOUND: U256 = U256([1 * 10u64.pow(17), 0, 0, 0]); // 0.1
// const MAX_UPPER_BOUND: U256 = U256([12 * 10u64.pow(16), 0, 0, 0]); // 0.12 ETH
const MAX_UPPER_BOUND: U256 = U256([25 * 10u64.pow(16), 0, 0, 0]); // 0.25 ETH

fn determine_search_range(
    path: &SandwichPath,
    tx_hash: H256,
    pools_map: &HashMap<H160, Pool>,
    // pending_txs: &HashMap<B256, PendingTxInfo>,
    pending_tx_info: &PendingTxInfo,
) -> Result<(U256, U256)> {
    info!("Determining search range for transaction {:?}", tx_hash);

    // match to_string_pretty(path) {
    //     Ok(pretty) => {
    //         info!("Path is \n{}", pretty);
    //     }
    //     Err(e) => {
    //         warn!("Failed to serialize swap info: {}", e);
    //     }
    // }
    // info!("Pending tx are {:?}", pending_txs);

    // // Get the middle's transaction
    // let middle_tx_hash = tx_hash;
    // let middle_tx_info = pending_txs
    //     .get(&h256_to_b256(H256::from(middle_tx_hash)))
    //     .ok_or_else(|| anyhow!("middle transaction not found within determine_search_range"))?;

    let middle_tx_info = pending_tx_info;

    // Get the pool for the front-run
    let front_run_pool = pools_map
        .get(&path.front_run.hop.target_pair)
        .ok_or_else(|| anyhow!("Front-run pool not found"))?;

    // Determine the token we're buying in the front-run
    let token_in = if front_run_pool.token0 == h160_to_b160(path.front_run.hop.token_in.address) {
        front_run_pool.token1
    } else {
        front_run_pool.token0
    };

    // Get the reserves of the token we're buying
    let token_reserves = if token_in == front_run_pool.token0 {
        front_run_pool.reserves0
    } else {
        front_run_pool.reserves1
    };
    // info!("Token reserves: {}", token_reserves);

    // Set the maximum amount the bot can use (0.5 ETH)
    let max_bot_amount = rU256::from(5 * 10u64.pow(17)); // 0.5 ETH
                                                         // let max_bot_amount = rU256::from(5 * 10u64.pow(18)); // 5 ETH

    // Calculate the lower bound (0.1% of middle's transaction value or MIN_BOUND, whichever is higher)
    let lower_bound = std::cmp::max(
        middle_tx_info
            .pending_tx
            .tx
            .value
            .checked_div(rU256::from(1000))
            .unwrap_or(ethers_u256_to_alloy_uint(MIN_BOUND)),
        ethers_u256_to_alloy_uint(MIN_BOUND),
    );
    info!("Initial lower bound: {}", lower_bound);

    // Calculate the upper bound (5% of pool liquidity or MAX_UPPER_BOUND, whichever is lower)
    let upper_bound = std::cmp::min(
        std::cmp::max(
            token_reserves.checked_div(rU256::from(20)).unwrap_or(
                ethers_u256_to_alloy_uint(MIN_BOUND)
                    .saturating_add(ethers_u256_to_alloy_uint(MIN_BOUND)),
            ),
            ethers_u256_to_alloy_uint(MAX_UPPER_BOUND),
        ),
        std::cmp::min(max_bot_amount, ethers_u256_to_alloy_uint(MAX_UPPER_BOUND)),
    );
    // info!("Initial upper bound: {}", upper_bound);

    // Ensure the lower bound is not higher than the upper bound
    // but also not lower than MIN_BOUND
    let final_lower_bound = std::cmp::max(
        std::cmp::min(lower_bound, upper_bound),
        ethers_u256_to_alloy_uint(MIN_BOUND),
    );

    let final_upper_bound = std::cmp::max(upper_bound, final_lower_bound);

    // info!(
    //     "Final lower bound: {}, Final upper bound: {}",
    //     final_lower_bound, final_upper_bound
    // );

    let lower_bound_ethers = alloy_uint_to_ethers_u256(final_lower_bound);
    let upper_bound_ethers = alloy_uint_to_ethers_u256(final_upper_bound);

    Ok((lower_bound_ethers, upper_bound_ethers))
}

async fn simulate_sandwich<P>(
    provider: Arc<P>,
    new_block: &NewBlock,
    tx_hash: H256,
    path: &SandwichPath,
    amount: U256,
    pools_map: &HashMap<H160, Pool>,
    tokens_map: &HashMap<H160, Token>,
    pending_tx_info: &PendingTxInfo,
    hop_index: usize,
    original_tx: &AlloyTransaction,
) -> Result<(I256, SimulatedSandwich, MiddleTx, bool)>
where
    P: AlloyProvider<BoxTransport, AnyNetwork> + 'static + Clone,
{
    // info!("Running Simulate Sandwich for hop {}", hop_index);

    let is_multi_hop = path.middle_hops.len() > 1;

    let swap_path = create_swap_path_from_sandwich(path, amount, tx_hash, original_tx);

    // let b256_tx_hash = h256_to_b256(tx_hash);
    // // Retrieve the pending transaction information
    // let pending_tx_info = match pending_txs.get(&b256_tx_hash) {
    //     Some(info) => info,
    //     None => {
    //         warn!("Transaction {:?} not found in pending_txs", b256_tx_hash);
    //         return Err(anyhow::anyhow!("Transaction not found in pending_txs"));
    //     }
    // };

    let pending_tx = &pending_tx_info.pending_tx;
    // info!(
    //     "Retrieved pending transaction info for hop {}: {:?}",
    //     hop_index, pending_tx_info
    // );

    let middle_tx = MiddleTx {
        tx_hash,
        from: b160_to_h160(pending_tx.tx.from),
        to: b160_to_h160(pending_tx.tx.to.unwrap_or_default()),
        data: pending_tx.tx.input.0.clone().into(),
        value: ru256_to_u256(pending_tx.tx.value),
        gas_price: u128_to_u256(pending_tx.tx.gas_price.unwrap_or_default()),
        gas_limit: u64::try_from(pending_tx.tx.gas).ok(),
    };

    let sandwich = Sandwich {
        amount_in: amount,
        swap_path: swap_path.clone(),
        middle_tx: middle_tx.clone(),
        optimal_sandwich: None,
        hop_index,
    };

    // info!("Sandwich for hop {} is: {:?}", hop_index, sandwich);

    let batch_sandwich = BatchSandwich {
        sandwiches: vec![sandwich],
    };

    // match to_string_pretty(&swap_path) {
    //     Ok(pretty) => info!("Swap Path passed to simulate is \n{}", pretty),
    //     Err(e) => warn!("Failed to serialize swap info: {}", e),
    // }

    let simulation_result = batch_sandwich
        .simulate(
            provider.clone(),
            None,
            new_block.block_number.into(),
            new_block.base_fee.into(),
            new_block.next_base_fee.into(),
            None,
            None,
            None,
            vec![swap_path],
            pending_tx_info,
        )
        .await?;

    // Determine whether to continue based on the simulation result
    let continue_search = simulation_result.continue_search;

    debug!(
        "Continue search returned from simulation function is: {:?}",
        continue_search
    );

    // match to_string_pretty(&simulation_result) {
    //     Ok(pretty) => {
    //         info!("Simulation result is \n{}", pretty);
    //     }
    //     Err(e) => {
    //         warn!("Failed to serialize simulation result: {}", e);
    //     }
    // }

    let profit = if simulation_result.profit >= 0 {
        I256::from_raw(rU256::from(simulation_result.profit as u128))
    } else {
        -I256::from_raw(rU256::from((-simulation_result.profit) as u128))
    };

    // info!(
    //     "Hop {}: Profit is {} and simulation_result is {:?}",
    //     hop_index, profit, simulation_result
    // );

    Ok((profit, simulation_result, middle_tx, continue_search))
}
fn create_swap_path_from_sandwich(
    path: &SandwichPath,
    amount: U256,
    tx_hash: H256,
    original_tx: &AlloyTransaction,
) -> SwapPath {
    let mut hops = Vec::new();

    // Front-run hop (Buy)
    let mut front_run_hop = path.front_run.clone();
    front_run_hop.hop.amount_in = amount;
    front_run_hop.hop.direction = SwapDirection::Buy;
    // front_run_hop.hop.tx_hash = None;
    front_run_hop.swap_info.input_amount = amount;
    front_run_hop.swap_info.direction = SwapDirection::Buy;
    front_run_hop.swap_info.tx_hash = H256::zero();
    hops.push(front_run_hop);

    // middle hop
    let mut middle_hop = path.middle_hops[0].clone();
    middle_hop.hop.amount_in = path.middle_hops[0].swap_info.input_amount;
    // middle_hop.hop.tx_hash = Some(tx_hash);
    middle_hop.swap_info.input_amount = path.middle_hops[0].hop.amount_in;
    middle_hop.swap_info.tx_hash = tx_hash;
    hops.push(middle_hop);

    // Back-run hop (Sell)
    let mut back_run_hop = path.back_run.clone();
    back_run_hop.hop.amount_in = amount;
    back_run_hop.hop.direction = SwapDirection::Sell;
    // back_run_hop.hop.tx_hash = None;
    back_run_hop.swap_info.input_amount = amount;
    back_run_hop.swap_info.direction = SwapDirection::Sell;
    back_run_hop.swap_info.tx_hash = H256::zero();
    hops.push(back_run_hop);

    let matched_swap_path = MatchedSwapPath {
        hops,
        is_multi_hop: false,
        total_input_amount: amount,
        total_output_amount: U256::zero(), // Will be determined during simulation
        input_token: path.front_run.swap_info.main_currency.clone(),
        output_token: path.back_run.swap_info.target_token.clone(),
    };

    SwapPath {
        path: matched_swap_path,
        original_tx: original_tx.clone(),
    }
}
