use alloy::providers::Provider as AlloyProvider;
use alloy::pubsub::PubSubFrontend;
use alloy_network::AnyNetwork;
use alloy_rpc_types_eth::{
    Block, BlockId, BlockNumberOrTag, BlockTransactionHashes, BlockTransactions,
    BlockTransactionsKind, Filter,
};
use log::info;
use std::sync::Arc;

use crate::common::constants::Env;
use crate::common::streams::{Event, NewBlock};
use crate::common::utils::eth_to_wei;
use crate::pools::generic_pool::{DexVariant, Pool};
use crate::pools::pool_filters::{filter_pools, PoolFilters};
use crate::pools::pool_loader::load_all_pools;

use crate::common::utils::calculate_next_block_base_fee;

use log::error;
use tokio::sync::broadcast::Sender;

pub async fn strategy<P>(
    provider: Arc<P>,
    event_sender: Sender<Event>,
) -> Result<(), Box<dyn std::error::Error>>
where
    P: AlloyProvider<PubSubFrontend, AnyNetwork> + 'static + Clone,
{
    info!("Executing strategy");
    let env = Env::new();

    // Load and filter pools
    info!("About to call load_all_pools");
    let (pools, current_block) = load_all_pools(env.wss_url.clone(), 10000000, 50000).await?;

    let filters = PoolFilters::new(
        eth_to_wei(25.0), // min_tvl: 25 ETH worth
        0.05,             // min_balance_ratio: 5%
        eth_to_wei(1.0),  // min_individual_reserve: 1 ETH worth
    );

    let filtered_pools = filter_pools(&pools, &filters);
    info!("Number of filtered pools: {}", filtered_pools.len());

    info!("About to get block number");
    let block_number = match provider.get_block_number().await {
        Ok(num) => num,
        Err(e) => {
            error!("Error getting block number: {:?}", e);
            return Ok(());
        }
    };

    let block = provider
        .get_block(
            BlockId::Number(BlockNumberOrTag::Number(block_number)),
            BlockTransactionsKind::Hashes,
        )
        .await
        .unwrap()
        .unwrap();

    let mut new_block = NewBlock {
        block_number: block.header.number.unwrap(),
        base_fee: block.header.base_fee_per_gas.unwrap(),
        next_base_fee: calculate_next_block_base_fee(
            block.header.gas_used,
            block.header.gas_limit,
            block.header.base_fee_per_gas.unwrap(),
        ),
    };

    info!("New block is: {:?}", new_block);

    Ok(())
}
