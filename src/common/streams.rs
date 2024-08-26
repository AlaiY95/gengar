use alloy::pubsub::PubSubFrontend;

use alloy::rpc::types::Transaction;
use alloy_network::AnyNetwork;
use alloy_provider::Provider as AlloyProvider;

use core::primitive::u128;
use log::{debug, error, info, warn};
use std::collections::HashMap;

use std::ops::Deref;
use std::sync::Arc;
use tokio::time::interval;

use alloy_primitives::B256;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::broadcast;
use tokio::time::sleep;
use tokio::time::{Duration, Instant};
use tokio_stream::StreamExt;

use crate::common::utils::calculate_next_block_base_fee;

#[derive(Default, Debug, Clone)]
pub struct NewBlock {
    pub block_number: u64,
    pub base_fee: u128,
    pub next_base_fee: u128,
}

#[derive(Debug, Clone)]
pub struct NewPendingTx {
    pub added_block: Option<u64>,
    pub tx: Transaction,
    pub detected_at: Instant,
    pub timestamp: u64,
}

impl Default for NewPendingTx {
    fn default() -> Self {
        Self {
            added_block: None,
            tx: Transaction::default(),
            detected_at: Instant::now(),
            timestamp: 0,
        }
    }
}
#[derive(Debug, Clone)]
pub enum Event {
    Block(NewBlock),
    PendingTx(NewPendingTx),
}
pub async fn stream_new_blocks<P>(
    provider: Arc<P>,
    block_sender: tokio::sync::broadcast::Sender<Event>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    P: AlloyProvider<PubSubFrontend, AnyNetwork> + 'static + Clone,
{
    info!("Executing stream_new_blocks");

    let subscription = provider.subscribe_blocks().await?;
    let mut stream = subscription.into_stream();
    let mut consecutive_errors = 0;

    while let Some(block) = stream.next().await {
        if let Some(number) = block.header.number {
            let new_block = NewBlock {
                block_number: number,
                base_fee: block.header.base_fee_per_gas.unwrap_or_default(),
                next_base_fee: calculate_next_block_base_fee(
                    block.header.gas_used,
                    block.header.gas_limit,
                    block.header.base_fee_per_gas.unwrap_or_default(),
                ),
            };

            match block_sender.send(Event::Block(new_block)) {
                Ok(_) => {
                    consecutive_errors = 0;
                }
                Err(err) => {
                    consecutive_errors += 1;
                    error!(
                        "Failed to send block event for block number: {}. Error: {:?}. Consecutive errors: {}",
                        number, err, consecutive_errors
                    );
                    if consecutive_errors >= 10 {
                        return Err(Box::new(std::io::Error::new(
                            std::io::ErrorKind::Other,
                            "Multiple consecutive send errors. All receivers might have disconnected."
                        )));
                    }
                }
            }
        } else {
            warn!("Received a block without a number");
        }
    }

    info!("Exiting stream_new_blocks");
    Ok(())
}
pub async fn stream_pending_transactions<P>(
    provider: Arc<P>,
    tx_sender: broadcast::Sender<Event>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    P: AlloyProvider<PubSubFrontend, AnyNetwork> + 'static + Clone,
{
    info!("Executing stream_pending_transactions");

    let mut backoff = Duration::from_secs(1);
    let max_backoff = Duration::from_secs(60);

    loop {
        match run_subscription(provider.clone(), tx_sender.clone()).await {
            Ok(()) => {
                warn!("Pending transaction subscription ended, attempting to restart");
                backoff = Duration::from_secs(1);
            }
            Err(e) => {
                error!("Error in pending transaction subscription: {:?}", e);
                warn!("Restarting subscription in {:?}", backoff);
                sleep(backoff).await;
                backoff = std::cmp::min(backoff * 2, max_backoff);
            }
        }
    }
}

async fn run_subscription<P>(
    provider: Arc<P>,
    tx_sender: broadcast::Sender<Event>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    P: AlloyProvider<PubSubFrontend, AnyNetwork> + 'static + Clone,
{
    let subscription = provider.subscribe_full_pending_transactions().await?;
    let mut stream = subscription.into_stream();
    let mut seen_txs: HashMap<B256, Instant> = HashMap::new();
    let mut cleanup_interval = interval(Duration::from_secs(300));
    let mut stats_interval = interval(Duration::from_secs(60));
    let stale_threshold = Duration::from_secs(60); // Consider transactions older than 60 seconds as potentially stale
    let mut tx_count = 0;

    loop {
        tokio::select! {
            Some(with_other_fields_tx) = stream.next() => {
                let tx: &Transaction = with_other_fields_tx.deref();
                let now = Instant::now();

                if let Some(&first_seen) = seen_txs.get(&tx.hash) {
                    if now.duration_since(first_seen) > stale_threshold {
                        warn!("Potentially stale transaction detected: {:?}, age: {:?}", tx.hash, now.duration_since(first_seen));
                        continue;
                    }
                } else {
                    seen_txs.insert(tx.hash, now);
                    match process_transaction(tx, &provider, &tx_sender).await {
                        Ok(true) => tx_count += 1,
                        Ok(false) => {},
                        Err(e) => error!("Error processing transaction: {:?}", e),
                    }
                }
            }
            _ = cleanup_interval.tick() => {
                let now = Instant::now();
                seen_txs.retain(|_, &mut first_seen| now.duration_since(first_seen) <= stale_threshold);
                info!("Cleaned up seen transactions. Current count: {}", seen_txs.len());
            }
            _ = stats_interval.tick() => {
                info!("Processed {} new transactions in the last minute", tx_count);
                tx_count = 0;
            }
            else => break,
        }
    }

    Ok(())
}

async fn process_transaction<P>(
    tx: &Transaction,
    provider: &Arc<P>,
    tx_sender: &broadcast::Sender<Event>,
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>>
where
    P: AlloyProvider<PubSubFrontend, AnyNetwork> + 'static + Clone,
{
    // Check if the transaction is still pending
    if let Ok(receipt) = provider.get_transaction_receipt(tx.hash).await {
        if receipt.is_some() {
            warn!("Transaction {:?} is no longer pending, skipping", tx.hash);
            return Ok(false);
        }
    }

    let block_number = match provider.get_block_number().await {
        Ok(number) => Some(number),
        Err(e) => {
            error!("Failed to get current block number: {:?}", e);
            None
        }
    };

    let new_pending_tx = NewPendingTx {
        added_block: block_number,
        tx: tx.clone(),
        detected_at: Instant::now(),
        timestamp: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs(),
    };

    match tx_sender.send(Event::PendingTx(new_pending_tx)) {
        Ok(_) => {
            // debug!("Sent pending transaction event. Hash: {}", tx.hash);
            Ok(true)
        }
        Err(e) => {
            error!(
                "Failed to send pending transaction event. Hash: {}. Error: {:?}",
                tx.hash, e
            );
            Err(Box::new(e))
        }
    }
}
