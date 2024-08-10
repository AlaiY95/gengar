use alloy_primitives::Address as AlloyAddress;
use anyhow::{Context, Result};
use csv::{ReaderBuilder, WriterBuilder};
use indicatif::{ProgressBar, ProgressStyle};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs::File;
use std::io::Write;
use std::io::{BufReader, BufWriter};

use crate::common::constants::Env;
use alloy_rpc_types_eth::{
    Block, BlockId, BlockNumberOrTag, BlockTransactionHashes, BlockTransactionsKind, Filter,
};
use ethers::providers::spoof::State;
use eyre::anyhow;
use lazy_static::lazy_static;
use once_cell::sync::Lazy;
use tokio::sync::Mutex;

use csv::StringRecord;
use ethers::abi::parse_abi;
use ethers::prelude::BaseContract;
use ethers::{
    abi::{decode, encode, AbiDecode, ParamType},
    contract::abigen,
    providers::{call_raw::RawCall, Middleware, Provider, Ws},
    types::{BlockId as EthersBlockId, BlockNumber as EthersBlockNumber, H160},
};

use indicatif::MultiProgress;

use revm::primitives::{uint, Bytes as rBytes, FixedBytes, HandlerCfg, Log, B256, U256 as rU256};
use std::{collections::HashMap, fs::OpenOptions, path::Path, str::FromStr, sync::Arc};

// use crate::common::pools::Pool;
use crate::pools::generic_pool::{DexVariant, Pool};

use crate::common::utils::create_new_wallet;
use crate::common::utils::{b160_to_h160, h160_to_b160};
use futures::StreamExt;
use tokio::time::{Duration, Instant};

use log::{debug, error, info, warn};

impl Token {
    pub fn to_cache_entry(&self) -> TokenCacheEntry {
        TokenCacheEntry {
            id: self.id,
            address: format!("{:?}", self.address),
            name: self.name.clone(),
            symbol: self.symbol.clone(),
            decimals: self.decimals,
        }
    }
}

impl TryFrom<TokenCacheEntry> for Token {
    type Error = anyhow::Error;

    fn try_from(entry: TokenCacheEntry) -> Result<Self, Self::Error> {
        Ok(Token {
            id: entry.id,
            address: H160::from_str(&entry.address).context("Failed to parse token address")?,
            name: entry.name,
            symbol: entry.symbol,
            decimals: entry.decimals,
        })
    }
}
#[derive(Debug, Clone, Serialize, Default, Deserialize, Eq, PartialEq, Hash)]

pub struct Token {
    pub id: u64,
    pub address: H160,
    pub name: String,
    pub symbol: String,
    pub decimals: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenCacheEntry {
    pub id: u64,
    pub address: String,
    pub name: String,
    pub symbol: String,
    pub decimals: u8,
}
pub static TOKEN_CACHE: Lazy<Arc<Mutex<HashMap<H160, Token>>>> =
    Lazy::new(|| Arc::new(Mutex::new(HashMap::new())));

pub async fn load_tokens(
    wss_url: String,
    current_block: u64,
    pools: &[Pool],
    earliest_new_block: u64,
    latest_loaded_block: u64,
) -> Result<HashMap<H160, Token>> {
    info!("Loading all tokens");
    info!("Total number of pools: {}", pools.len());
    info!("Current block number: {}", current_block);
    info!("Earliest new block: {}", earliest_new_block);
    info!("Latest loaded block: {}", latest_loaded_block);

    let start_time = Instant::now();

    let mut tokens_map = load_token_cache()?;
    info!("Loaded {} tokens from cache", tokens_map.len());

    let env = Env::new();
    let ws = Ws::connect(env.wss_url.clone())
        .await
        .context("Failed to connect to WebSocket")?;
    let provider = Arc::new(Provider::new(ws));

    let new_pools: Vec<&Pool> = pools
        .iter()
        .filter(|p| {
            p.block_number >= earliest_new_block
                || !tokens_map.contains_key(&b160_to_h160(p.token0))
                || !tokens_map.contains_key(&b160_to_h160(p.token1))
        })
        .collect();

    info!("Number of pools to process: {}", new_pools.len());

    let new_token_addresses: HashSet<H160> = new_pools
        .iter()
        .flat_map(|p| [p.token0, p.token1])
        .map(b160_to_h160)
        .filter(|addr| !tokens_map.contains_key(addr))
        .collect();

    info!(
        "Number of new tokens to fetch: {}",
        new_token_addresses.len()
    );

    let mut new_or_updated_tokens = HashMap::new();
    let mut next_id = tokens_map.values().map(|t| t.id).max().unwrap_or(0) + 1;

    if !new_token_addresses.is_empty() {
        let ethers_block_id =
            EthersBlockId::Number(EthersBlockNumber::Number(latest_loaded_block.into()));

        let token_addresses_vec: Vec<H160> = new_token_addresses.into_iter().collect();

        let multi_progress = MultiProgress::new();
        let fetch_pb = multi_progress.add(ProgressBar::new(token_addresses_vec.len() as u64));
        fetch_pb.set_style(
            ProgressStyle::default_bar()
                .template("[{elapsed_precise}] {bar:40.cyan/blue} {pos:>7}/{len:7} {msg}")
                .unwrap()
                .progress_chars("##-"),
        );
        fetch_pb.set_message("Fetching new tokens");

        let new_tokens = get_token_info_multi(
            provider.clone(),
            ethers_block_id,
            &token_addresses_vec,
            fetch_pb.clone(),
        )
        .await
        .context("Failed to fetch new token info")?;

        for (address, mut token) in new_tokens {
            if token.name != "Unknown" && token.symbol != "UNK" {
                token.id = next_id;
                next_id += 1;
                tokens_map.insert(address, token.clone());
                new_or_updated_tokens.insert(address, token);
            } else {
                debug!("Skipping unknown token: {:?}", address);
            }
        }

        fetch_pb.finish_with_message("Finished fetching new tokens");
    }

    if !new_or_updated_tokens.is_empty() {
        save_token_cache(&new_or_updated_tokens).context("Failed to save token cache")?;
        info!(
            "Saved {} new or updated tokens to cache",
            new_or_updated_tokens.len()
        );
    } else {
        info!("No new or updated tokens to save to cache");
    }

    let duration = start_time.elapsed();
    info!(
        "Updated token cache with {} total tokens ({} new or updated) in {:?}",
        tokens_map.len(),
        new_or_updated_tokens.len(),
        duration
    );

    Ok(tokens_map)
}

pub async fn get_token_info_wrapper(
    provider: Arc<Provider<Ws>>,
    block: EthersBlockId,
    token_address: H160,
) -> Result<Token> {
    {
        let cache = TOKEN_CACHE.lock().await;
        if let Some(token) = cache.get(&token_address) {
            return Ok(token.clone());
        }
    }

    let token = fetch_token_info(provider, block, token_address).await?;

    TOKEN_CACHE
        .lock()
        .await
        .insert(token_address, token.clone());

    Ok(token)
}
abigen!(
    ERC20,
    r#"[
        function name() external view returns (string)
        function symbol() external view returns (string)
        function decimals() external view returns (uint8)
    ]"#,
);

pub async fn get_token_info_multi(
    provider: Arc<Provider<Ws>>,
    block: EthersBlockId,
    tokens: &[H160],
    pb: ProgressBar,
) -> Result<HashMap<H160, Token>> {
    debug!("Executing get_token_info_multi for {} tokens", tokens.len());
    let mut token_info = HashMap::new();
    let mut to_retry: Vec<H160> = tokens.to_vec();

    for attempt in 0..3 {
        debug!(
            "Attempt {}: processing {} tokens",
            attempt + 1,
            to_retry.len()
        );

        let current_batch = to_retry.clone();
        to_retry.clear();

        let futures = current_batch.into_iter().map(|token| {
            let provider = provider.clone();
            async move {
                let result = fetch_token_info(provider, block, token).await;
                (token, result)
            }
        });

        let mut results_stream = futures::stream::iter(futures).buffer_unordered(20);

        while let Some((token, result)) = results_stream.next().await {
            match result {
                Ok(info) => {
                    token_info.insert(token, info);
                    pb.inc(1);
                    pb.set_message(format!("Fetched info for token {:?}", token));
                }
                Err(e) if attempt < 2 => {
                    debug!(
                        "Failed to fetch info for token {:?}, will retry: {:?}",
                        token, e
                    );
                    to_retry.push(token);
                }
                Err(e) => {
                    warn!("Failed to fetch info for token {:?}: {:?}", token, e);
                    token_info.insert(
                        token,
                        Token {
                            id: 0,
                            address: token,
                            name: "Unknown".to_string(),
                            symbol: "UNK".to_string(),
                            decimals: 18,
                        },
                    );
                    pb.inc(1);
                    pb.set_message(format!("Using default info for token {:?}", token));
                }
            }
        }

        if to_retry.is_empty() {
            debug!("No tokens to retry, breaking out of retry loop");
            break;
        } else {
            debug!("Tokens to retry in next attempt: {:?}", to_retry);
            tokio::time::sleep(Duration::from_millis(100 * 2u64.pow(attempt as u32))).await;
        }
    }

    debug!(
        "Finished all attempts, returning token info for {} tokens",
        token_info.len()
    );
    Ok(token_info)
}

async fn fetch_token_info(
    provider: Arc<Provider<Ws>>,
    block: EthersBlockId,
    token_address: H160,
) -> Result<Token> {
    let token_contract = ERC20::new(token_address, provider.clone());

    let name = match token_contract.name().block(block).call().await {
        Ok(name) => name,
        Err(e) => {
            debug!("Failed to fetch name for token {}: {:?}", token_address, e);
            "Unknown".to_string()
        }
    };

    let symbol = match token_contract.symbol().block(block).call().await {
        Ok(symbol) => symbol,
        Err(e) => {
            debug!(
                "Failed to fetch symbol for token {}: {:?}",
                token_address, e
            );
            "UNK".to_string()
        }
    };

    let decimals = match token_contract.decimals().block(block).call().await {
        Ok(decimals) => decimals,
        Err(e) => {
            debug!(
                "Failed to fetch decimals for token {}: {:?}",
                token_address, e
            );
            18
        }
    };

    Ok(Token {
        id: 0,
        address: token_address,
        name,
        symbol,
        decimals,
    })
}

pub fn load_token_cache() -> Result<HashMap<H160, Token>> {
    let cache_file = Path::new("cache/token_cache.csv");
    let mut tokens_map = HashMap::new();

    if cache_file.exists() {
        let file = File::open(cache_file).context("Failed to open token cache file")?;
        let reader = BufReader::new(file);
        let mut csv_reader = ReaderBuilder::new()
            .has_headers(true)
            .flexible(true)
            .from_reader(reader);

        for (i, result) in csv_reader.records().enumerate() {
            let record = result.context(format!("Failed to read CSV record at line {}", i + 2))?;
            if record.len() < 5 {
                warn!(
                    "Skipping invalid record at line {}: insufficient fields",
                    i + 2
                );
                continue;
            }

            let id = record[0]
                .parse()
                .with_context(|| format!("Failed to parse id at line {}: {}", i + 2, &record[0]))?;
            let address = H160::from_str(&record[1]).with_context(|| {
                format!("Failed to parse address at line {}: {}", i + 2, &record[1])
            })?;
            let decimals = record[4].parse().with_context(|| {
                format!("Failed to parse decimals at line {}: {}", i + 2, &record[4])
            })?;

            let token = Token {
                id,
                address,
                name: record[2].to_string(),
                symbol: record[3].to_string(),
                decimals,
            };

            if token.name != "Unknown" && token.symbol != "UNK" {
                tokens_map.insert(address, token);
            } else {
                debug!("Skipping unknown token at line {}: {:?}", i + 2, address);
            }
        }

        info!("Loaded {} tokens from cache", tokens_map.len());
    } else {
        info!("Token cache file does not exist. Starting with empty cache.");
    }

    Ok(tokens_map)
}

pub fn save_token_cache(new_tokens: &HashMap<H160, Token>) -> Result<()> {
    info!("Starting to save new tokens to cache");
    let cache_file = Path::new("cache/token_cache.csv");

    // Create the cache directory if it doesn't exist
    if let Some(parent) = cache_file.parent() {
        std::fs::create_dir_all(parent).context("Failed to create cache directory")?;
        info!("Cache directory created or already exists");
    }

    let file = OpenOptions::new()
        .write(true)
        .create(true)
        .append(true)
        .open(cache_file)
        .context("Failed to open token cache file")?;

    let mut writer = WriterBuilder::new()
        .has_headers(false)
        .from_writer(BufWriter::new(file));

    // If the file is newly created, write headers
    if cache_file.metadata()?.len() == 0 {
        writer
            .write_record(&["id", "address", "name", "symbol", "decimals"])
            .context("Failed to write headers")?;
        info!("Headers written to new token cache file");
    }

    let mut tokens_saved = 0;
    for (i, token) in new_tokens.values().enumerate() {
        if token.name == "Unknown" || token.symbol == "UNK" {
            debug!("Skipping unknown token during save: {:?}", token.address);
            continue;
        }

        writer
            .write_record(&[
                token.id.to_string(),
                format!("{:?}", token.address),
                token.name.clone(),
                token.symbol.clone(),
                token.decimals.to_string(),
            ])
            .context(format!("Failed to write token data for entry {}", i))?;

        tokens_saved += 1;
        if tokens_saved % 1000 == 0 {
            info!("Processed {} new tokens", tokens_saved);
        }
    }

    writer
        .flush()
        .context("Failed to flush token cache to disk")?;
    info!("Token cache flushed to disk");
    info!("Saved {} new tokens to cache", tokens_saved);

    Ok(())
}
pub fn create_token_progress_bar(len: u64) -> ProgressBar {
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

pub fn update_token_progress_bar(pb: &ProgressBar, message: &str) {
    pb.inc(1);
    pb.set_message(message.to_string());
}

pub fn finish_token_progress_bar(pb: &ProgressBar, message: &str) {
    pb.finish_with_message(message.to_string());
}
