use super::generic_pool::{DexVariant, Pool};
// use super::sushiswap_v2::load_sushiswap_v2_pools;
use super::sushiswap_v2::fetch_sushiswap_v2;
use super::uniswap_v2::fetch_uniswap_v2;
use super::uniswap_v3::fetch_uniswap_v3;

// use super::uniswap_v3::load_uniswap_v3_pools;
use alloy::providers::Provider;
use alloy::pubsub::PubSubFrontend;
use alloy_network::AnyNetwork;
use anyhow::Result;
use revm::primitives::Address;
use serde::{Deserialize, Serialize};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MarketInfo {
    pub pool: Pool,
    pub protocol: ProtocolData,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProtocolData {
    pub name: String,
    pub version: String,
}

// #[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Copy)]
// pub enum ProtocolVersion {
//     UniswapV2,
//     UniswapV3,
//     SushiswapV2,
//     SushiswapV3,
//     // Add other versions as needed
// }

pub trait ProtocolInfo {
    fn name(&self) -> &'static str;
    fn variant(&self) -> DexVariant;
    fn factory_address(&self) -> Address;
    fn router_address(&self) -> Address;
    fn event_signature(&self) -> &'static str;
    fn cache_file_path(&self) -> &'static str;
}

pub trait ProtocolLoader: ProtocolInfo + Send + Sync {
    fn load_pools(
        &self,
        provider: Arc<dyn Provider<PubSubFrontend, AnyNetwork>>,
        from_block: u64,
        to_block: u64,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Pool>>> + Send + '_>>;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UniswapV2;

impl ProtocolInfo for UniswapV2 {
    fn name(&self) -> &'static str {
        "UniswapV2"
    }
    fn variant(&self) -> DexVariant {
        DexVariant::UniswapV2
    }
    fn factory_address(&self) -> Address {
        "0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f"
            .parse()
            .unwrap()
    }
    fn router_address(&self) -> Address {
        "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D"
            .parse()
            .unwrap()
    }
    fn event_signature(&self) -> &'static str {
        "PairCreated(address,address,address,uint256)"
    }
    fn cache_file_path(&self) -> &'static str {
        "cache/.cached-v2-pools.csv"
    }
}

impl ProtocolLoader for UniswapV2 {
    fn load_pools(
        &self,
        provider: Arc<dyn Provider<PubSubFrontend, AnyNetwork>>,
        from_block: u64,
        to_block: u64,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Pool>>> + Send + '_>> {
        Box::pin(fetch_uniswap_v2(
            provider,
            from_block,
            to_block,
            self.event_signature(),
        ))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UniswapV3;

impl ProtocolInfo for UniswapV3 {
    fn name(&self) -> &'static str {
        "UniswapV3"
    }
    fn variant(&self) -> DexVariant {
        DexVariant::UniswapV3
    }
    fn factory_address(&self) -> Address {
        "0x1F98431c8aD98523631AE4a59f267346ea31F984"
            .parse()
            .unwrap()
    }
    // Need to get the correct router address
    fn router_address(&self) -> Address {
        "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D"
            .parse()
            .unwrap()
    }
    fn event_signature(&self) -> &'static str {
        "PoolCreated(address,address,uint24,int24,address)"
    }
    fn cache_file_path(&self) -> &'static str {
        "cache/.cached-v3-pools.csv"
    }
}

impl ProtocolLoader for UniswapV3 {
    fn load_pools(
        &self,
        provider: Arc<dyn Provider<PubSubFrontend, AnyNetwork>>,
        from_block: u64,
        to_block: u64,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Pool>>> + Send + '_>> {
        Box::pin(fetch_uniswap_v3(
            provider,
            from_block,
            to_block,
            self.event_signature(),
        ))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SushiswapV2; // Add this struct

// - (Uni|Sushi)swapV2Factory - https://etherscan.io/address/0xc0aee478e3658e2610c5f7a4a2e1777ce9e4f2ac
// - (Uni|Sushi)swapV2Router02 - https://etherscan.io/address/0xd9e1ce17f2641f24ae83637ab66a2cca9c378b9f
// - (Uni|Sushi)swapV2Pair init code hash - `e18a34eb0e04b04f7a0ac29a6e80748dca96319b42c54d679cb821dca90c6303`
impl ProtocolInfo for SushiswapV2 {
    fn name(&self) -> &'static str {
        "SushiswapV2"
    }

    fn variant(&self) -> DexVariant {
        DexVariant::SushiswapV2
    }

    fn factory_address(&self) -> Address {
        "0xc0aee478e3658e2610c5f7a4a2e1777ce9e4f2ac"
            .parse()
            .unwrap()
    }
    fn router_address(&self) -> Address {
        "0xd9e1cE17f2641f24aE83637ab66a2cca9C378B9F"
            .parse()
            .unwrap()
    }

    fn event_signature(&self) -> &'static str {
        "PairCreated(address,address,address,uint256)"
    }

    fn cache_file_path(&self) -> &'static str {
        "cache/.cached-sushiswap-v2-pools.csv"
    }
}

impl ProtocolLoader for SushiswapV2 {
    fn load_pools(
        &self,
        provider: Arc<dyn Provider<PubSubFrontend, AnyNetwork>>,
        from_block: u64,
        to_block: u64,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<Pool>>> + Send + '_>> {
        Box::pin(fetch_sushiswap_v2(
            provider,
            from_block,
            to_block,
            self.event_signature(),
        ))
    }
}

pub fn get_all_protocols() -> Vec<Box<dyn ProtocolLoader + Send + Sync>> {
    vec![
        Box::new(UniswapV2),
        // Box::new(UniswapV2),
        // Box::new(SushiswapV2),
        // Box::new(SushiswapV3),

        // Add other protocols here
    ]
}

pub fn get_protocol(variant: DexVariant) -> Box<dyn ProtocolInfo> {
    match variant {
        DexVariant::UniswapV2 => Box::new(UniswapV2),
        // DexVariant::SushiswapV2 => Box::new(SushiswapV2),
        // Add other variants as needed
        _ => panic!("Unsupported DEX variant"),
    }
}

// shibaswap router 0xd9e1cE17f2641f24aE83637ab66a2cca9C378B9F
