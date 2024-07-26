use alloy::primitives::U256;
use alloy::providers::{Provider, ProviderBuilder, WsConnect};
use alloy::pubsub::{PubSubConnect, PubSubFrontend, Subscription};
use alloy_network::AnyNetwork;
use alloy_rpc_types_eth::{BlockId, BlockNumberOrTag, BlockTransactionsKind, Filter};
use anyhow::Result;
#[allow(unused_imports)]
use ethers::utils::keccak256;
use revm::primitives::{Address, U256 as rU256};

// use async_trait::async_trait;
// use super::generic_pool::Pool;
use super::generic_pool::{DexVariant, Pool};
use log::{error, info};
use std::hash::Hash;
use std::{collections::HashMap, sync::Arc};

pub async fn fetch_uniswap_v3(
    // provider: Arc<P>,
    provider: Arc<dyn Provider<PubSubFrontend, AnyNetwork>>,
    from_block: u64,
    to_block: u64,
    event: &str,
) -> Result<Vec<Pool>> {
    info!(
        "Loading Uniswap V3 pools from block {} to block {}",
        from_block, to_block
    );

    let mut pools = Vec::new();
    let mut timestamp_map = HashMap::new();

    // Define the expected event signature
    let expected_event_signature = keccak256(event);

    let event_filter = Filter::new()
        .from_block(from_block)
        .to_block(to_block)
        .event(event);

    let logs = match provider.get_logs(&event_filter).await {
        Ok(logs) => {
            if logs.is_empty() {
                info!("No logs found for the specified range and filter. Check filter parameters and blockchain data availability.");
            }
            logs
        }
        Err(e) => {
            info!("Error fetching logs: {:?}", e);
            return Err(e.into()); // Handle or propagate the error
        }
    };

    for log in logs.iter() {
        let topics = &log.inner.data.topics();

        // Check if we have enough topics
        if topics.len() < 4 {
            // Uniswap V3 PoolCreated event has 4 topics
            info!("Log entry has fewer than 4 topics. Skipping.");
            continue;
        }

        // Check if the first topic matches the expected event signature
        if topics[0] != expected_event_signature {
            info!("Log entry does not match expected event signature. Skipping.");
            continue;
        }

        // Check if topics have enough length
        if topics[1].len() < 32 || topics[2].len() < 32 || topics[3].len() < 32 {
            info!("One or more topics are shorter than 32 bytes. Skipping.");
            continue;
        }

        let block_number = log.block_number.unwrap_or_default();

        // Retrieve the timestamp for the block
        let timestamp = if !timestamp_map.contains_key(&block_number) {
            let block = provider
                .get_block(
                    BlockId::Number(BlockNumberOrTag::Number(block_number)),
                    BlockTransactionsKind::Hashes,
                )
                .await
                .unwrap()
                .unwrap();
            let timestamp = block.header.timestamp;
            // Cache the timestamp for future use
            timestamp_map.insert(block_number, timestamp);
            timestamp
        } else {
            // If the timestamp is already cached, retrieve it from the map
            let timestamp = *timestamp_map.get(&block_number).unwrap();
            timestamp
        };

        let token0_bytes = &topics[1][12..32]; // Extract the last 20 bytes
        let token1_bytes = &topics[2][12..32]; // Extract the last 20 bytes

        let token0 = Address::from_slice(token0_bytes);
        let token1 = Address::from_slice(token1_bytes);

        // // Extract the fee from the third topic (topic[3])
        let fee_topic = topics[3];
        let fee_tier = u32::from_str_radix(&format!("{:x}", fee_topic)[2..], 16).unwrap();

        let pair_address_bytes = &topics[1][12..32]; // Assuming it's the second topic
        let pair_address = Address::from_slice(pair_address_bytes);

        let mut pool_data = Pool {
            id: -1,
            address: pair_address,
            version: DexVariant::UniswapV3,
            token0,
            token1,
            fee: fee_tier,
            block_number: block_number,
            timestamp,
            reserves0: rU256::default(),
            reserves1: rU256::default(),
        };

        match pool_data.get_current_reserves(provider.clone()).await {
            Ok((reserves0, reserves1)) => {
                pool_data.reserves0 = reserves0;
                pool_data.reserves1 = reserves1;
            }
            Err(e) => {
                // Log the error and continue with zero reserves
                info!(
                    "Failed to fetch reserves for pool {}: {:?}",
                    pair_address, e
                );
            }
        }

        info!(
            "Reserve0 is {} and Reserve1 is {} for TokenPair {}",
            pool_data.reserves0, pool_data.reserves1, pool_data.address
        );

        pools.push(pool_data);
    }
    info!(
        "Total number of Uniswap V3 pools processed for block range {} to {}: {}",
        from_block,
        to_block,
        pools.len()
    );

    Ok(pools)
}
