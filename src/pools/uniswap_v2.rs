use alloy::json_abi::JsonAbi;
use alloy::providers::{Provider, ProviderBuilder, WsConnect};
use alloy::pubsub::PubSubFrontend;
use alloy_network::AnyNetwork;
use alloy_rpc_types_eth::{Block, BlockId, BlockNumberOrTag, BlockTransactionsKind, Filter};
use alloy_sol_types::SolValue;
use anyhow::Result;
#[allow(unused_imports)]
use ethers::utils::keccak256;
use revm::primitives::{Address, B256, U256 as rU256};
// use async_trait::async_trait;
// use super::generic_pool::Pool;
use super::generic_pool::{DexVariant, Pool};
use super::utils::{
    extract_pool_address, extract_token_addresses, get_block_timestamp, update_pool_reserves,
    validate_log_entry,
};
use itertools::Itertools;
use log::{error, info, warn};
use std::{
    collections::HashMap,
    fs::{create_dir_all, OpenOptions},
    path::Path,
    sync::Arc,
};

pub async fn fetch_uniswap_v2(
    rpc_provider: Arc<dyn Provider<PubSubFrontend, AnyNetwork>>,
    start_block: u64,
    end_block: u64,
    event_signature: &str,
) -> Result<Vec<Pool>> {
    info!(
        "Initiating Uniswap V2 pool fetch: blocks {} to {}",
        start_block, end_block
    );

    let mut liquidity_pools = Vec::new();
    let event_hash = keccak256(event_signature);
    let mut block_timestamps: HashMap<u64, u64> = HashMap::new();

    let event_query = Filter::new()
        .from_block(start_block)
        .to_block(end_block)
        .event(event_signature);

    let event_logs = match rpc_provider.get_logs(&event_query).await {
        Ok(logs) => {
            info!("Successfully retrieved {} event logs", logs.len());
            if logs.is_empty() {
                info!("No events found in specified range. Verify query parameters and blockchain data.");
            }
            logs
        }
        Err(e) => {
            info!("Log retrieval failed: {:?}", e);
            return Err(e.into());
        }
    };

    for log_entry in event_logs.iter() {
        let log_topics = &log_entry.inner.data.topics();
        if !validate_log_entry(log_topics, &event_hash) {
            continue;
        }

        let block_num = log_entry.block_number.unwrap_or_default();
        let block_time =
            get_block_timestamp(&rpc_provider, block_num, &mut block_timestamps).await?;

        let (token_a, token_b) = extract_token_addresses(log_topics);
        let pool_address = extract_pool_address(&log_entry.inner.data.data)?;

        let mut new_pool = Pool {
            id: -1,
            address: pool_address,
            version: DexVariant::UniswapV2,
            token0: token_a,
            token1: token_b,
            fee: 300, // Uniswap V2 default fee
            block_number: block_num,
            timestamp: block_time,
            reserves0: rU256::default(),
            reserves1: rU256::default(),
        };

        update_pool_reserves(&mut new_pool, &rpc_provider).await;
        liquidity_pools.push(new_pool);
    }

    info!(
        "Uniswap V2 pool fetch complete. Total pools: {}",
        liquidity_pools.len()
    );
    Ok(liquidity_pools)
}
