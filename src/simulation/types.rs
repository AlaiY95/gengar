use ethers::types::{transaction::eip2930::AccessList, Bytes as eBytes, H160, H256, I256, U256};
use serde::Deserialize;
use serde::Serialize;

use crate::common::token_loader::Token;
use crate::pools::DexVariant;
use crate::strategies::hop_extractor::SwapDirection;

use crate::strategies::hop_extractor::SwapPath;
use crate::{common::streams::NewPendingTx, strategies::hop_extractor::MatchedSwapHop};

#[derive(Debug, Clone)]
pub struct PendingTxInfo {
    pub pending_tx: NewPendingTx,
    pub swap_path: Option<SwapPath>,
}

pub struct MiddleTx {
    pub tx_hash: H256,
    pub from: H160,
    pub to: H160,
    pub data: eBytes,
    pub value: U256,
    pub gas_price: U256,
    pub gas_limit: Option<u64>,
}
pub struct Sandwich {
    pub amount_in: U256,
    pub swap_path: SwapPath,
    pub middle_tx: MiddleTx,
    pub optimal_sandwich: Option<OptimalSandwich>,
    pub hop_index: usize,
}

pub struct SandwichPath {
    front_run: MatchedSwapHop,
    middle_hops: Vec<MatchedSwapHop>,
    back_run: MatchedSwapHop,
    hop_index: usize,
}
pub struct OptimalSandwich {
    pub front_run_amount: U256,
    pub back_run_amount: U256,
    pub estimated_profit: I256,
    pub path: SandwichPath,
    pub simulated_result: SimulatedSandwich,
    pub iteration_count: u32,
    pub search_completed: bool,
    hop_index: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct SwapHop {
    pub dex: DexVariant,
    pub token_in: Token,
    pub token_out: Token,
    pub amount_in: U256,
    pub amount_out: U256,
    pub target_pair: H160,
    pub direction: SwapDirection,
    pub tx_hash: H256,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct VictimTx {
    pub tx_hash: H256,
    pub from: H160,
    pub to: H160,
    pub data: eBytes,
    pub value: U256,
    pub gas_price: U256,
    pub gas_limit: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulatedSandwich {
    pub revenue: i128,
    pub profit: i128,
    pub gas_cost: i128,
    pub front_gas_used: u64,
    pub back_gas_used: u64,
    pub front_access_list: AccessList,
    pub back_access_list: AccessList,
    pub front_calldata: eBytes,
    pub back_calldata: eBytes,
    pub continue_search: bool,
}
