use alloy_network::AnyNetwork;
use futures::executor::block_on;
use futures_util::future::join_all;
use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use std::collections::HashSet;
use std::time::SystemTime;
use tokio::time::Instant;

use super::generic_pool::Pool;
use super::protocols::{get_all_protocols, ProtocolLoader};
use alloy::primitives::{U128 as rU128, U64 as rU64};
use alloy::providers::Provider as AlloyProvider;
use alloy::pubsub::PubSubFrontend;

use super::utils::{
    calculate_block_range, cleanup_invalid_pools, create_or_open_csv_file, create_provider,
    is_valid_pool_address,
};
use super::utils::{create_progress_bar, finish_progress_bar, update_progress_bar};
use crate::common::constants::Env;
#[allow(unused_imports)]
use alloy::providers::{Provider, ProviderBuilder, WsConnect};
use anyhow::Result;
use log::{error, info};
use std::fs::create_dir_all;
use std::{path::Path, sync::Arc};
use tokio::sync::Mutex;

pub async fn load_all_pools(
    wss_url: String,
    from_block: u64,
    chunk: u64,
) -> Result<(Vec<Pool>, u64), Box<dyn std::error::Error>> {
    info!("Executing pools.load_all_pools()");
    info!(
        "Initial parameters - from_block: {}, chunk: {}",
        from_block, chunk
    );

    std::fs::create_dir_all("cache")?;
    let env = Env::new();
    let provider = create_provider(env.wss_url).await?;
    let provider = Arc::new(provider);
    let to_block = provider.get_block_number().await?;
    info!("Current block number (to_block): {}", to_block);

    let all_pools = Arc::new(Mutex::new(Vec::new()));
    let prev_pool_id = Arc::new(Mutex::new(-1i64));

    let protocols = get_all_protocols();
    let multi_progress = Arc::new(MultiProgress::new());

    let tasks = protocols.into_iter().map(|protocol_info| {
        let provider = provider.clone();
        let all_pools = all_pools.clone();
        let prev_pool_id = prev_pool_id.clone();
        let multi_progress = multi_progress.clone();

        tokio::spawn(async move {
            if let Err(e) = load_protocol_pools(
                protocol_info.as_ref(),
                provider,
                from_block,
                to_block,
                chunk,
                all_pools,
                prev_pool_id,
                multi_progress,
            )
            .await
            {
                error!("Error loading pools for {}: {:?}", protocol_info.name(), e);
            }
        })
    });

    join_all(tasks).await;

    let mut final_all_pools = Arc::try_unwrap(all_pools)
        .unwrap()
        .into_inner()
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    let final_prev_pool_id = Arc::try_unwrap(prev_pool_id).unwrap().into_inner();

    final_all_pools.sort_by_key(|p: &Pool| p.block_number);

    let current_block = provider.get_block_number().await?;
    // info!("Number of unique pool addresses: {}", final_all_pools.len());
    // info!("Final prev_pool_id: {}", final_prev_pool_id);

    Ok((final_all_pools, current_block.try_into().unwrap()))
}
async fn load_protocol_pools(
    protocol_info: &(dyn ProtocolLoader + Send + Sync),
    provider: Arc<dyn Provider<PubSubFrontend, AnyNetwork>>,
    from_block: u64,
    to_block: u64,
    chunk: u64,
    all_pools: Arc<Mutex<Vec<Vec<Pool>>>>,
    prev_pool_id: Arc<Mutex<i64>>,
    multi_progress: Arc<MultiProgress>,
) -> Result<(), Box<dyn std::error::Error>> {
    let start_time = std::time::Instant::now();
    let start_system_time = std::time::SystemTime::now();
    info!(
        "Starting to load pools for {} at {:?}",
        protocol_info.name(),
        start_system_time
    );

    let cache_file_name = format!(
        "cache/.cached-{}-pools.csv",
        protocol_info.name().to_lowercase()
    );
    let cache_file = Path::new(&cache_file_name);

    let (mut writer, mut pools, mut max_id) = create_or_open_csv_file(cache_file)?;

    let last_processed_block = pools.last().map_or(0, |pool| pool.block_number);

    let from_block = pools
        .last()
        .map_or(from_block, |pool| pool.block_number + 1);

    let block_range = calculate_block_range(from_block, to_block, chunk);

    let pb = multi_progress.add(create_progress_bar(block_range.len() as u64));

    let mut total_new_pools = 0;

    for (i, range) in block_range.iter().enumerate() {
        let range_start_time = std::time::Instant::now();

        info!(
            "Processing block range {} to {} for {} (range {}/{})",
            range.0,
            range.1,
            protocol_info.name(),
            i + 1,
            block_range.len()
        );

        match protocol_info
            .load_pools(provider.clone(), range.0, range.1)
            .await
        {
            Ok(mut new_pools) => {
                for pool in &mut new_pools {
                    if pool.block_number > last_processed_block {
                        max_id += 1;
                        pool.id = max_id;
                        writer.serialize(pool)?;
                    }
                }

                let new_pool_count = new_pools.len();
                total_new_pools += new_pool_count;
                pools.extend(new_pools);

                let elapsed = range_start_time.elapsed();
                let total_elapsed = start_time.elapsed();
                let message = format!(
                    "Processed blocks {} to {} for {}. New pools: {} (Total: {})",
                    range.0,
                    range.1,
                    protocol_info.name(),
                    new_pool_count,
                    total_new_pools
                );
                update_progress_bar(&pb, &message);
                info!(
                    "{} (Elapsed: {:?}, Total: {:?})",
                    message, elapsed, total_elapsed
                );
            }
            Err(e) => {
                error!(
                    "Error processing block range {} to {} for {}: {:?}",
                    range.0,
                    range.1,
                    protocol_info.name(),
                    e
                );
            }
        }
    }

    writer.flush()?;

    let total_duration = start_time.elapsed();
    finish_progress_bar(
        &pb,
        &format!(
            "Finished processing all blocks for {}. Total new pools: {} (Duration: {:?})",
            protocol_info.name(),
            total_new_pools,
            total_duration
        ),
    );

    {
        let mut all_pools_guard = all_pools.lock().await;
        all_pools_guard.push(pools.clone());
    }
    {
        let mut prev_pool_id_guard = prev_pool_id.lock().await;
        *prev_pool_id_guard = std::cmp::max(*prev_pool_id_guard, max_id);
    }

    info!(
        "Finished processing for {}. Total pools: {}, Max pool ID: {}",
        protocol_info.name(),
        pools.len(),
        max_id
    );

    Ok(())
}
