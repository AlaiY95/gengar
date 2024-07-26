use alloy::pubsub::{PubSubConnect, PubSubFrontend, Subscription};
use alloy::rpc::types::serde_helpers::WithOtherFields;
use alloy::rpc::types::Transaction;
use alloy_network::AnyNetwork;
use alloy_provider::{Provider as AlloyProvider, ProviderBuilder, WsConnect};
use alloy_transport::BoxTransport;
use core::primitive::u128;
use log::{error, info, warn};
use revm::primitives::{
    uint, Address, Bytes as rBytes, FixedBytes, HandlerCfg, Log, U256 as rU256,
};
use std::ops::Deref;
use std::sync::mpsc::SendError;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;
use tokio::sync::broadcast::Sender;

use tokio_stream::StreamExt;

use crate::common::utils::calculate_next_block_base_fee;

#[derive(Default, Debug, Clone)]
pub struct NewBlock {
    pub block_number: u64,
    pub base_fee: u128,
    pub next_base_fee: u128,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NewPendingTx {
    pub added_block: Option<u64>,
    pub tx: Transaction,
}

impl Default for NewPendingTx {
    fn default() -> Self {
        Self {
            added_block: None,
            tx: Transaction::default(),
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
    event_sender: tokio::sync::broadcast::Sender<Event>,
) where
    P: AlloyProvider<PubSubFrontend, AnyNetwork> + 'static + Clone,
{
    info!("Executing stream_new_blocks");
    let subscription = match provider.subscribe_blocks().await {
        Ok(sub) => sub,
        Err(e) => {
            error!("Failed to subscribe to blocks: {:?}", e);
            return;
        }
    };

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

            match event_sender.send(Event::Block(new_block)) {
                Ok(num_receivers) => {
                    consecutive_errors = 0;
                    info!(
                        "Successfully sent block event for block number: {}. Receivers: {}",
                        number, num_receivers
                    );
                }
                Err(err) => {
                    consecutive_errors += 1;
                    error!(
                        "Failed to send block event for block number: {}. Error: No active receivers. Consecutive errors: {}",
                        number, consecutive_errors
                    );
                    if consecutive_errors >= 5 {
                        warn!("Multiple consecutive send errors. All receivers might have disconnected.");
                        break;
                    }
                }
            }
        } else {
            warn!("Received a block without a number");
        }
    }
    info!("Exiting stream_new_blocks");
}

pub async fn stream_pending_transactions<P>(
    provider: Arc<P>,
    event_sender: broadcast::Sender<Event>,
) where
    // P: AlloyProvider<PubSubFrontend, AnyNetwork> + 'static,
    P: AlloyProvider<PubSubFrontend, AnyNetwork> + 'static + Clone,
{
    // info!("Executing stream_pending_transactions");

    let subscription = match provider.subscribe_full_pending_transactions().await {
        Ok(sub) => sub,
        Err(e) => {
            error!("Failed to subscribe to full pending transactions: {:?}", e);
            return;
        }
    };

    let mut stream = subscription.into_stream();

    while let Some(with_other_fields_tx) = stream.next().await {
        let tx: &Transaction = with_other_fields_tx.deref();

        let new_pending_tx = NewPendingTx {
            added_block: None,
            tx: tx.clone(),
        };

        match event_sender.send(Event::PendingTx(new_pending_tx)) {
            Ok(receiver_count) => {
                // info!(
                //     "Sent pending transaction event. Hash: {}. Receivers: {}",
                //     tx.hash, receiver_count
                // );
            }
            Err(err) => {
                error!(
                    "Failed to send pending transaction event. Hash: {}. Error: {}",
                    tx.hash, err
                );
            }
        }
    }

    info!("Exiting stream_pending_transactions");
}
