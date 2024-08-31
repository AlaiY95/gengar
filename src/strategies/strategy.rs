use alloy::providers::Provider as AlloyProvider;
use alloy::pubsub::PubSubFrontend;
use alloy_network::AnyNetwork;
use alloy_rpc_types_eth::{
    Block, BlockId, BlockNumberOrTag, BlockTransactionHashes, BlockTransactions,
    BlockTransactionsKind, Filter,
};
use dashmap::DashSet;
use ethers::providers::Provider as EthersProvider;
use ethers::types::{H160, U256};
use ethers_providers::Ws;
use log::{debug, error, info, warn};
use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use tokio::sync::broadcast::Sender;
use tokio::sync::Mutex;
use tokio::sync::Semaphore;
use tokio::time::Instant;

use revm::primitives::B256;

use ethers::signers::{LocalWallet, Signer};

use crate::common::constants::Env;
use crate::common::streams::NewPendingTx;
use crate::common::streams::{Event, NewBlock};
use crate::common::token_loader::{load_tokens, Token};
use crate::common::utils::calculate_next_block_base_fee;
use crate::common::utils::{b160_to_h160, eth_to_wei, fixed_bytes_to_h256};
use crate::pools::generic_pool::{DexVariant, Pool};
use crate::pools::pool_filters::{filter_pools, PoolFilters};
use crate::pools::pool_loader::load_all_pools;
use crate::simulation::optimizor::generate_and_simulate_paths;
use crate::simulation::types::PendingTxInfo;
use crate::simulation::types::Sandwich;
use crate::strategies::hop_extractor::detect_swaps;

pub async fn strategy<P>(
    provider: Arc<P>,
    block_sender: Sender<Event>,
    tx_sender: Sender<Event>,
) -> Result<(), Box<dyn std::error::Error>>
where
    P: AlloyProvider<PubSubFrontend, AnyNetwork> + 'static + Clone,
{
    info!("Executing strategy");
    let env = Env::new();

    let ws = Ws::connect(env.wss_url.clone()).await.unwrap();
    let ethers_provider = Arc::new(EthersProvider::new(ws));
    // info!("Connected to ethers_provider at {}", env.wss_url);

    // Load and filter pools
    info!("About to call load_all_pools");
    let (cached_pools, earliest_new_block, latest_loaded_block, current_block) =
        load_all_pools(env.wss_url.clone(), 10000000, 50000).await?;

    // let filters = PoolFilters::new(
    //     eth_to_wei(25.0), // min_tvl: 25 ETH worth
    //     0.05,             // min_balance_ratio: 5%
    //     eth_to_wei(1.0),  // min_individual_reserve: 1 ETH worth
    // );

    // let filtered_pools = filter_pools(&pools, &filters);
    // info!("Number of filtered pools: {}", filtered_pools.len());

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

    let tokens_map = Arc::new(
        load_tokens(
            env.wss_url.clone(),
            current_block,
            &cached_pools,
            earliest_new_block,
            latest_loaded_block,
        )
        .await?,
    );
    info!("Tokens map count: {:?}", tokens_map.len());

    let pools_map: Arc<HashMap<H160, Pool>> = Arc::new(
        cached_pools
            .into_iter()
            .filter(|p| {
                let token0_h160 = b160_to_h160(p.token0);
                let token1_h160 = b160_to_h160(p.token1);
                tokens_map.contains_key(&token0_h160) && tokens_map.contains_key(&token1_h160)
            })
            .map(|p| (b160_to_h160(p.address), p))
            .collect(),
    );

    info!("Filtered pools count: {}", pools_map.len());

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

    info!("Initial block is: {:?}", new_block);

    let bot_address = H160::from_str(&env.bot_address).unwrap();
    info!("Bot address set to: {:?}", bot_address);

    let wallet = env
        .private_key
        .parse::<LocalWallet>()
        .unwrap()
        .with_chain_id(1 as u64);
    info!("Wallet initialized with chain ID: {}", wallet.chain_id());

    let owner = wallet.address();
    info!("Owner address set to: {:?}", owner);

    let mut block_receiver = block_sender.subscribe();
    let mut tx_receiver = tx_sender.subscribe();

    info!("Event receivers subscribed");

    let pending_txs: Arc<Mutex<HashMap<B256, PendingTxInfo>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let promising_sandwiches: Arc<Mutex<HashMap<B256, Vec<Sandwich>>>> =
        Arc::new(Mutex::new(HashMap::new()));

    let processed_txs: Arc<DashSet<B256>> = Arc::new(DashSet::new());

    let semaphore_permits = 1;

    let semaphore = Arc::new(Semaphore::new(semaphore_permits));

    info!("Starting main loop");

    loop {
        tokio::select! {
            result = block_receiver.recv() => {
                match result {
                    Ok(Event::Block(block)) => {
                        info!("[Block #{:?}]", block.block_number);
                        new_block = block;

                        update_state_for_new_block(&new_block, &pending_txs, &promising_sandwiches).await;
                    },
                    Ok(Event::PendingTx(_)) => {
                        warn!("Received unexpected PendingTx event on block channel");
                    },
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        warn!("Block channel closed");
                        break;
                    },
                    Err(e) => {
                        warn!("Error receiving from block channel: {:?}", e);
                    }
                }
            }
            result = tx_receiver.recv() => {
                match result {
                    Ok(Event::PendingTx(pending_tx)) => {
                        let tx_hash = pending_tx.tx.hash;

                        if processed_txs.contains(&tx_hash) {
                            debug!("Skipping already processed tx: {:?}", tx_hash);
                            continue;
                        }

                        processed_txs.insert(tx_hash);


                        let semaphore_clone = Arc::clone(&semaphore);

                        let provider_clone = Arc::clone(&provider);
                        let ethers_provider_clone = Arc::clone(&ethers_provider);
                        let pools_map_clone = Arc::clone(&pools_map);
                        let tokens_map_clone = Arc::clone(&tokens_map);
                        let pending_txs_clone = Arc::clone(&pending_txs);
                        let promising_sandwiches_clone = Arc::clone(&promising_sandwiches);
                        let new_block_clone = new_block.clone();
                        let wss_url_clone = env.wss_url.clone();
                        let processed_txs_clone = Arc::clone(&processed_txs);


                        tokio::spawn(async move {

                            let _permit = semaphore_clone.acquire().await.unwrap();

                            process_pending_transaction(
                                wss_url_clone,
                                pending_tx,
                                &provider_clone,
                                &ethers_provider_clone,
                                &pools_map_clone,
                                &tokens_map_clone,
                                &new_block_clone,
                                &pending_txs_clone,
                                &promising_sandwiches_clone,
                                owner,
                                bot_address,
                                &processed_txs_clone,

                            ).await;
                        });
                    },
                    Ok(Event::Block(_)) => {
                        warn!("Received unexpected Block event on transaction channel");
                    },
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                        warn!("Transaction channel closed");
                        break;
                    },
                    Err(e) => {
                        warn!("Error receiving from transaction channel: {:?}", e);
                    }
                }
            }
        }
    }
    info!("Exiting run_sandwich_strategy");

    Ok(())
}

pub async fn process_pending_transaction<P>(
    wss_url: String,
    pending_tx: NewPendingTx,
    provider: &Arc<P>,
    ethers_provider: &Arc<EthersProvider<Ws>>,
    pools_map: &Arc<HashMap<H160, Pool>>,
    tokens_map: &Arc<HashMap<H160, Token>>,
    new_block: &NewBlock,
    pending_txs: &Arc<Mutex<HashMap<B256, PendingTxInfo>>>,
    promising_sandwiches: &Arc<Mutex<HashMap<B256, Vec<Sandwich>>>>,
    owner: H160,
    bot_address: H160,
    processed_txs: &DashSet<B256>,
) where
    P: AlloyProvider<PubSubFrontend, AnyNetwork> + 'static + Clone + Send + Sync,
{
    let start_time = Instant::now();
    let tx_hash = pending_tx.tx.hash;
    let tx_hash_str = format!("{:?}", tx_hash);

    info!("Processing pending tx: {:?}", tx_hash);

    // Check if the transaction is still pending
    if !is_transaction_still_pending(provider.clone(), tx_hash).await {
        debug!("Transaction {:?} is no longer pending, skipping", tx_hash);
        return;
    }

    // TODO add logic for checking stuck transactions before further processing!

    // Detect swaps in the transaction
    let swap_detection_start = Instant::now();
    let swap_result = detect_swaps(
        ethers_provider.clone(),
        new_block,
        &pending_tx,
        pools_map,
        tokens_map.clone(),
    )
    .await;

    let swap_detection_time = swap_detection_start.elapsed();

    match swap_result {
        Ok(Some(swap_paths)) => {
            info!(
                "Detected swap path for pending tx {:?}, detection time: {:?}",
                tx_hash, swap_detection_time
            );

            let pending_tx_info = PendingTxInfo {
                pending_tx: pending_tx.clone(),
                swap_path: Some(swap_paths.clone()),
            };

            // Add the pending transaction to our tracking
            {
                let mut pending_txs_guard = pending_txs.lock().await;
                pending_txs_guard.insert(tx_hash, pending_tx_info.clone());
            }

            // Generate and simulate sandwich paths
            let sandwich_gen_start = Instant::now();
            let sandwich_result = generate_and_simulate_paths(
                wss_url.clone(),
                Arc::new(new_block.clone()),
                fixed_bytes_to_h256(tx_hash),
                swap_paths,
                Arc::clone(pools_map),
                tokens_map.clone(),
                &pending_tx_info,
            )
            .await;

            let sandwich_generation_time = sandwich_gen_start.elapsed();

            match sandwich_result {
                Ok(sandwiches_map) => {
                    if !sandwiches_map.is_empty() {
                        info!(
                            "Sandwich path generated for tx_hash: {:?}, generation time: {:?}",
                            tx_hash, sandwich_generation_time
                        );

                        // Add promising sandwiches
                        {
                            let mut promising_sandwiches_guard = promising_sandwiches.lock().await;
                            promising_sandwiches_guard.extend(sandwiches_map.clone());
                        }

                        // Final check before sending bundle
                        if !is_transaction_still_pending(provider.clone(), tx_hash).await {
                            info!("Sending bundle for tx_hash: {:?}", tx_hash);

                            // let detection_time = pending_tx_info.pending_tx.detected_at;
                        } else {
                            warn!(
                                "Transaction confirmed before sending bundle. Tx Hash: {:?}",
                                tx_hash
                            );
                        }
                    } else {
                        info!(
                            "No profitable sandwiches found for tx {:?}, generation time: {:?}",
                            tx_hash, sandwich_generation_time
                        );
                    }
                }
                Err(e) => error!(
                    "Failed to generate and simulate sandwich paths for pending tx {:?}: {:?}",
                    tx_hash, e
                ),
            }
        }
        Ok(None) => {
            debug!(
                "No swap paths detected for pending transaction: {:?}",
                tx_hash
            );
        }
        Err(e) => {
            error!(
                "Error detecting swaps for pending tx {:?}: {:?}",
                tx_hash, e
            );
        }
    }

    // Mark the transaction as processed
    processed_txs.insert(tx_hash);

    let total_processing_time = start_time.elapsed();

    info!(
        "Finished processing pending tx {:?}, Total time taken: {:?}",
        tx_hash, total_processing_time
    );
}

pub async fn update_state_for_new_block(
    new_block: &NewBlock,
    pending_txs: &Arc<Mutex<HashMap<B256, PendingTxInfo>>>,
    promising_sandwiches: &Arc<Mutex<HashMap<B256, Vec<Sandwich>>>>,
) {
    let initial_pending_txs;
    let initial_promising_sandwiches;

    // Lock and update pending_txs
    {
        let mut pending_txs_guard = pending_txs.lock().await;
        initial_pending_txs = pending_txs_guard.len();
        pending_txs_guard.retain(|_, v| {
            v.pending_tx.added_block.map_or(false, |added_block| {
                new_block.block_number - added_block < 3 // Remove if older than 3 blocks
            })
        });
    }

    // Lock and update promising_sandwiches
    {
        let mut promising_sandwiches_guard = promising_sandwiches.lock().await;
        initial_promising_sandwiches = promising_sandwiches_guard.len();

        // We need to lock pending_txs again to check against it
        let pending_txs_guard = pending_txs.lock().await;
        promising_sandwiches_guard.retain(|h, _| pending_txs_guard.contains_key(h));
    }

    let removed_pending_txs;
    let removed_promising_sandwiches;

    // Calculate removed counts
    {
        let pending_txs_guard = pending_txs.lock().await;
        let promising_sandwiches_guard = promising_sandwiches.lock().await;
        removed_pending_txs = initial_pending_txs - pending_txs_guard.len();
        removed_promising_sandwiches =
            initial_promising_sandwiches - promising_sandwiches_guard.len();
    }

    info!(
        "Updated state for new block #{}: Removed {} pending txs and {} promising sandwiches. Current state: {} pending txs, {} promising sandwiches",
        new_block.block_number,
        removed_pending_txs,
        removed_promising_sandwiches,
        initial_pending_txs - removed_pending_txs,
        initial_promising_sandwiches - removed_promising_sandwiches
    );
}

async fn is_transaction_still_pending<P>(provider: Arc<P>, tx_hash: B256) -> bool
where
    P: AlloyProvider<PubSubFrontend, AnyNetwork> + 'static + Clone,
{
    match provider.get_transaction_receipt(tx_hash).await {
        Ok(Some(_)) => false,
        Ok(None) => true,
        Err(_) => {
            warn!("Error checking transaction status for {:?}", tx_hash);
            false
        }
    }
}
