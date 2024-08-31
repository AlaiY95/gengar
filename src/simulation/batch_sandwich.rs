use alloy::providers::Provider as AlloyProvider;
use alloy::transports::BoxTransport;
use alloy_network::AnyNetwork;

use ethers::types::{transaction::eip2930::AccessList, H160, U256, U64};
use std::sync::Arc;

use anyhow::Result;

use crate::simulation::types::PendingTxInfo;
use crate::simulation::types::{Sandwich, SimulatedSandwich};
use crate::strategies::hop_extractor::SwapPath;

#[derive(Debug, Default, Clone)]
pub struct BatchSandwich {
    pub sandwiches: Vec<Sandwich>,
}

impl BatchSandwich {
    pub async fn simulate<P>(
        &self,
        provider: Arc<P>,
        owner: Option<H160>,
        block_number: U64,
        base_fee: U256,
        max_fee: U256,
        front_access_list: Option<AccessList>,
        back_access_list: Option<AccessList>,
        bot_address: Option<H160>,
        swap_paths: Vec<SwapPath>,
        pending_tx_info: &PendingTxInfo,
    ) -> Result<SimulatedSandwich>
    where
        P: AlloyProvider<BoxTransport, AnyNetwork> + 'static + Clone,
    {
        unimplemented!()
    }
}
