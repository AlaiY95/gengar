use ethers::types::{transaction::eip2930::AccessList, Bytes as eBytes, H160, H256, I256, U256};
use serde::Deserialize;
use serde::Serialize;

use crate::simulation::optimizor::OptimalSandwich;
use crate::strategies::hop_extractor::SwapPath;
use crate::{common::streams::NewPendingTx, strategies::hop_extractor::MatchedSwapHop};

#[derive(Debug, Clone)]
pub struct PendingTxInfo {
    pub pending_tx: NewPendingTx,
    pub swap_path: Option<SwapPath>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MiddleTx {
    pub tx_hash: H256,
    pub from: H160,
    pub to: H160,
    pub data: eBytes,
    pub value: U256,
    pub gas_price: U256,
    pub gas_limit: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sandwich {
    pub amount_in: U256,
    pub swap_path: SwapPath,
    pub middle_tx: MiddleTx,
    pub optimal_sandwich: Option<OptimalSandwich>,
    pub hop_index: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]

pub struct SandwichPath {
    pub front_run: MatchedSwapHop,
    pub middle_hops: Vec<MatchedSwapHop>,
    pub back_run: MatchedSwapHop,
    pub hop_index: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
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

impl Default for SimulatedSandwich {
    fn default() -> Self {
        SimulatedSandwich {
            revenue: 0,
            profit: 0,
            gas_cost: 0,
            front_gas_used: 0,
            back_gas_used: 0,
            front_access_list: AccessList::default(),
            back_access_list: AccessList::default(),
            front_calldata: eBytes::default(),
            back_calldata: eBytes::default(),
            continue_search: true,
        }
    }
}
