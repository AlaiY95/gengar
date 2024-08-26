#[allow(unused_imports)]
use alloy_rpc_types_eth::{TransactionInput, TransactionRequest};
use csv::ReaderBuilder;
use csv::Writer;
use log4rs::encode::writer;
use std::error::Error;

use alloy::providers::{Provider, ProviderBuilder, WsConnect};
use alloy::pubsub::PubSubFrontend;
use alloy_network::AnyNetwork;
use alloy_rpc_types_eth::{Block, BlockId, BlockNumberOrTag, BlockTransactionsKind, Filter};
use alloy_serde::WithOtherFields;
use alloy_sol_types::SolValue;
use anyhow::Result;
use revm::primitives::{hex, uint, Address, TxKind, B256, U256 as rU256};
// use async_trait::async_trait;
use super::generic_pool::Pool;
use ethers::abi::{parse_abi, ParamType};
use ethers::prelude::*;
use indicatif::{ProgressBar, ProgressStyle};
use log::{debug, error, info, warn};
use std::collections::HashMap;
use std::fs::File;
use std::hash::Hash;
use std::{fs::OpenOptions, path::Path, sync::Arc};

pub fn calculate_block_range(from_block: u64, to_block: u64, chunk: u64) -> Vec<(u64, u64)> {
    let mut block_range = Vec::new();
    let mut current_block = from_block;

    while current_block < to_block {
        let end_block = std::cmp::min(current_block + chunk - 1, to_block);
        block_range.push((current_block, end_block));
        current_block = end_block + 1;
    }

    block_range
}

pub fn create_progress_bar(len: u64) -> ProgressBar {
    let pb = ProgressBar::new(len);
    pb.set_style(
        ProgressStyle::with_template(
            "[{elapsed_precise}] {bar:40.cyan/blue} {pos:>7}/{len:7} {msg}",
        )
        .unwrap()
        .progress_chars("##-"),
    );
    pb
}

pub fn update_progress_bar(pb: &ProgressBar, message: &str) {
    pb.inc(1);
    pb.set_message(message.to_string());
}

pub fn finish_progress_bar(pb: &ProgressBar, message: &str) {
    pb.finish_with_message(message.to_string());
}

// You can add other utility functions here, for example:

pub fn create_event_filter(from_block: u64, to_block: u64, event: &str) -> Filter {
    Filter::new()
        .from_block(from_block)
        .to_block(to_block)
        .event(event)
}

pub async fn is_valid_pool_address(
    address: Address,
    provider: Arc<dyn Provider<PubSubFrontend, AnyNetwork>>,
) -> bool {
    // First, check if the address has a balance
    match provider.get_balance(address).await {
        Ok(balance) if balance > rU256::default() => return true,
        _ => {}
    }

    // If balance check fails, try to call a known function (e.g., 'getReserves' for Uniswap V2-like pools)
    let call_data = hex::decode("0x0902f1ac").unwrap(); // 'getReserves()' function selector
    let tx = WithOtherFields::new(TransactionRequest {
        to: Some(TxKind::Call(address)),
        input: TransactionInput::new(call_data.into()),
        ..Default::default()
    });

    match provider.call(&tx).await {
        Ok(result) if !result.is_empty() => true,
        _ => false,
    }
}

pub async fn cleanup_invalid_pools(
    pools: &mut Vec<Pool>,
    provider: Arc<dyn Provider<PubSubFrontend, AnyNetwork>>,
) {
    pools.retain(|pool| {
        futures::executor::block_on(async {
            is_valid_pool_address(pool.address, provider.clone()).await
        })
    });
}

pub fn create_or_open_csv_file(
    file_path: &Path,
) -> Result<(Writer<File>, Vec<Pool>, i64), Box<dyn Error>> {
    let file_exists = file_path.exists();
    let file = OpenOptions::new()
        .write(true)
        .read(true)
        .create(true)
        .open(file_path)?;

    let mut writer = csv::Writer::from_writer(file.try_clone()?);
    let mut pools = Vec::new();
    let mut max_id = -1;

    if file_exists {
        let reader = ReaderBuilder::new()
            .has_headers(true)
            .from_path(file_path)?;

        for (index, row) in reader.into_records().enumerate() {
            match row {
                Ok(record) => {
                    let pool_result = std::panic::catch_unwind(|| Pool::from(record.clone()));
                    match pool_result {
                        Ok(pool) => {
                            max_id = max_id.max(pool.id);
                            pools.push(pool);
                        }
                        Err(e) => {
                            let error_message = if let Some(string) = e.downcast_ref::<String>() {
                                string.clone()
                            } else if let Some(&s) = e.downcast_ref::<&'static str>() {
                                s.to_string()
                            } else {
                                "Unknown error".to_string()
                            };
                            error!(
                                "Failed to parse pool at line {}: {:?}",
                                index + 2,
                                error_message
                            );
                            println!("Problematic record: {:?}", record);
                        }
                    }
                }
                Err(e) => {
                    error!("Error reading CSV at line {}: {:?}", index + 2, e);
                }
            }
        }
    }

    let mut writer = csv::WriterBuilder::new()
        .has_headers(!file_exists)
        .from_writer(file);

    if !file_exists {
        debug!("Writing headers");
        writer.write_record(&[
            "id",
            "address",
            "version",
            "token0",
            "token1",
            "fee",
            "block_number",
            "timestamp",
            "reserves0",
            "reserves1",
        ])?;
        writer.flush()?;
    }

    Ok((writer, pools, max_id))
}

pub async fn create_provider(
    wss_url: String,
) -> Result<Arc<impl Provider<PubSubFrontend, AnyNetwork>>, Box<dyn std::error::Error>> {
    let ws_connect = WsConnect {
        url: wss_url,
        auth: None,
    };

    let provider = ProviderBuilder::new()
        .network::<AnyNetwork>()
        .with_recommended_fillers()
        .on_ws(ws_connect)
        .await?;

    Ok(Arc::new(provider))
}

pub fn parse_event_signature(event: &str) -> H256 {
    let abi = parse_abi(&[&format!("event {}", event)]).unwrap();
    abi.event(event.split('(').next().unwrap())
        .unwrap()
        .signature()
}

pub fn validate_log_entry(topics: &[B256], expected_hash: &[u8; 32]) -> bool {
    if topics.len() < 3 || topics[0] != *expected_hash {
        info!("Invalid log entry. Skipping.");
        return false;
    }
    if topics[1].len() < 32 || topics[2].len() < 32 {
        info!("Insufficient topic length. Skipping.");
        return false;
    }
    true
}

pub async fn get_block_timestamp(
    provider: &Arc<dyn Provider<PubSubFrontend, AnyNetwork>>,
    block_num: u64,
    timestamp_cache: &mut HashMap<u64, u64>,
) -> Result<u64> {
    if let Some(&cached_time) = timestamp_cache.get(&block_num) {
        return Ok(cached_time);
    }

    let block = provider
        .get_block(
            BlockId::Number(BlockNumberOrTag::Number(block_num)),
            BlockTransactionsKind::Hashes,
        )
        .await?
        .ok_or_else(|| anyhow::anyhow!("Block not found"))?;

    let block_time = block.header.timestamp;
    timestamp_cache.insert(block_num, block_time);
    Ok(block_time)
}

pub fn extract_token_addresses(topics: &[B256]) -> (Address, Address) {
    let token_a = Address::from_slice(&topics[1][12..32]);
    let token_b = Address::from_slice(&topics[2][12..32]);
    (token_a, token_b)
}

pub fn extract_pool_address(data: &[u8]) -> Result<Address> {
    let decoded: (Address, rU256) = SolValue::abi_decode(data, true)?;
    Ok(decoded.0)
}

pub async fn update_pool_reserves(
    pool: &mut Pool,
    provider: &Arc<dyn Provider<PubSubFrontend, AnyNetwork>>,
) {
    match pool.get_current_reserves(provider.clone()).await {
        Ok((res0, res1)) => {
            pool.reserves0 = res0;
            pool.reserves1 = res1;
        }
        Err(e) => {
            warn!(
                "Failed to fetch reserves for pool {}: {:?}. Using default values.",
                pool.address, e
            );
        }
    }
}
