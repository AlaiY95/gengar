use alloy::providers::Provider as AlloyProvider;
use alloy::pubsub::PubSubFrontend;
use alloy_network::AnyNetwork;
use log::info;
use std::sync::Arc;

use crate::common::constants::Env;
use crate::common::streams::{Event, NewBlock};
use crate::common::utils::eth_to_wei;
use crate::pools::generic_pool::{DexVariant, Pool};
use crate::pools::pool_filters::{filter_pools, PoolFilters};
use crate::pools::pool_loader::load_all_pools;

use log::error;
use tokio::sync::broadcast::Sender;

pub async fn strategy<P>(provider: Arc<P>, event_sender: Sender<Event>)
where
    P: AlloyProvider<PubSubFrontend, AnyNetwork> + 'static + Clone,
{
    info!("Executing run_sandwich_strategy");
    let env = Env::new();

    // Load and filter pools
    info!("About to call load_all_pools");
    let (pools, last_processed_block) =
        match load_all_pools(env.wss_url.clone(), 10000000, 50000).await {
            Ok(result) => result,
            Err(e) => {
                error!("Error in load_all_pools: {:?}", e);
                return;
            }
        };

    let filters = PoolFilters::new(
        eth_to_wei(25.0), // min_tvl: 25 ETH worth
        0.05,             // min_balance_ratio: 5%
        eth_to_wei(1.0),  // min_individual_reserve: 1 ETH worth
    );

    let filtered_pools = filter_pools(&pools, &filters);
    info!("Number of filtered pools: {}", filtered_pools.len());
}
