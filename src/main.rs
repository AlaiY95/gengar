use alloy_network::AnyNetwork;
use alloy_provider::{ProviderBuilder, WsConnect};
use std::time::Duration;

// use ethers::providers::{Provider, Ws};

// use anyhow::Result;subscription
// use eyre::{anyhow, Result};
use log::{error, info, warn};
use std::sync::Arc;
use tokio::sync::broadcast::{self};
use tokio::task::JoinSet;

use gengar::common::constants::Env;
use gengar::common::streams::{stream_new_blocks, stream_pending_transactions, Event};

use gengar::common::utils::setup_logger;
use gengar::strategies::strategy::strategy;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Setup logger
    setup_logger()?;

    // Load environment variables
    dotenv::dotenv().ok();
    info!("Starting Gengarrrrr");

    // Initialize environment
    let env = Env::new();
    info!("Environment variables loaded");

    // Setup WebSocket connection
    let ws_connect = WsConnect {
        url: env.wss_url.clone(),
        auth: None,
    };
    info!("WebSocket connection established");

    // Initialize provider
    let provider = ProviderBuilder::new()
        .network::<AnyNetwork>()
        .with_recommended_fillers()
        .on_ws(ws_connect)
        .await?;
    let provider = Arc::new(provider);
    info!("Provider initialized");

    // Create channels
    const EVENT_CHANNEL_CAPACITY: usize = 20000;
    let (block_sender, _) = broadcast::channel(EVENT_CHANNEL_CAPACITY);
    let (tx_sender, _) = broadcast::channel(EVENT_CHANNEL_CAPACITY);

    // Initialize JoinSet for task management
    let mut set = JoinSet::new();

    // Spawn task for streaming new blocks
    let block_provider = Arc::clone(&provider);
    let block_sender_clone = block_sender.clone();
    set.spawn(async move {
        loop {
            match stream_new_blocks(Arc::clone(&block_provider), block_sender_clone.clone()).await {
                Ok(()) => {
                    info!("stream_new_blocks completed successfully, restarting...");
                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
                Err(e) => {
                    error!("stream_new_blocks error: {:?}, restarting...", e);
                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
            }
        }
    });

    // Spawn task for streaming pending transactions
    let tx_provider = Arc::clone(&provider);
    let tx_sender_clone = tx_sender.clone();
    set.spawn(async move {
        match stream_pending_transactions(tx_provider, tx_sender_clone).await {
            Ok(()) => info!("stream_pending_transactions completed successfully"),
            Err(e) => error!("stream_pending_transactions error: {:?}", e),
        }
    });

    // Spawn task for processing block events
    let mut block_receiver = block_sender.subscribe();
    set.spawn(async move {
        while let Ok(event) = block_receiver.recv().await {
            match event {
                Event::Block(block) => {
                    // Process block
                    info!("Received new block: {:?}", block.block_number);
                }
                Event::PendingTx(_) => {
                    error!("Received unexpected PendingTx event on block channel");
                }
            }
        }
        error!("Block receiver terminated");
    });

    // Spawn task for processing transaction events
    let mut tx_receiver = tx_sender.subscribe();
    set.spawn(async move {
        while let Ok(event) = tx_receiver.recv().await {
            match event {
                Event::PendingTx(pending_tx) => {
                    // Process pending transaction
                    // info!("Received pending transaction: {:?}", pending_tx.tx.hash);
                }
                Event::Block(_) => {
                    error!("Received unexpected Block event on transaction channel");
                }
            }
        }
        error!("Transaction receiver terminated");
    });

    // Spawn sandwich strategy task
    let strategy_provider = Arc::clone(&provider);
    let strategy_block_sender = block_sender.clone();
    let strategy_tx_sender = tx_sender.clone();
    set.spawn(async move {
        match strategy(strategy_provider, strategy_block_sender, strategy_tx_sender).await {
            Ok(()) => info!("Sandwich strategy completed successfully"),
            Err(e) => error!("Sandwich strategy error: {:?}", e),
        }
    });

    // Wait for all tasks to complete
    while let Some(res) = set.join_next().await {
        match res {
            Ok(()) => info!("Task completed successfully"),
            Err(e) => error!("Task error: {:?}", e),
        }
    }

    Ok(())
}
