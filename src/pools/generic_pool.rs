use alloy::dyn_abi::{FunctionExt, JsonAbiExt};
use alloy::providers::{Provider, WsConnect};
use alloy::pubsub::PubSubFrontend;
use alloy_dyn_abi::DynSolValue;
use alloy_rpc_types_eth::{TransactionInput, TransactionRequest};
use alloy_serde::WithOtherFields;
use anyhow::{anyhow, Context, Result};
// use alloy_contract::{AbiItem, CallData, ContractError};
use crate::common::utils::b160_to_h160;
use crate::pools::protocols::ProtocolData;
use alloy::json_abi::JsonAbi;
use alloy_network::AnyNetwork;
use csv::StringRecord;
use ethers_core::types::H160;
use log::{error, info};
use revm::primitives::{Address, Bytes, TxKind, U256 as rU256};
use serde::{Deserialize, Serialize};
use std::str::FromStr;
use std::sync::Arc;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Eq, PartialEq, Hash)]
pub enum DexVariant {
    UniswapV2,
    UniswapV3,
    SushiswapV2,
    SushiswapV3,
    // Add more variants here as you add support for more DEXes
}

impl DexVariant {
    fn get_protocol_data(&self) -> ProtocolData {
        match self {
            DexVariant::UniswapV2 => ProtocolData {
                name: "Uniswap".to_string(),
                version: DexVariant::UniswapV2,
            },
            DexVariant::UniswapV3 => ProtocolData {
                name: "Uniswap".to_string(),
                version: DexVariant::UniswapV3,
            },
            DexVariant::SushiswapV2 => ProtocolData {
                name: "Sushiswap".to_string(),
                version: DexVariant::SushiswapV2,
            },
            DexVariant::SushiswapV3 => ProtocolData {
                name: "Sushiswap".to_string(),
                version: DexVariant::SushiswapV3,
            },
            // Add other variants as needed
        }
    }
    pub fn num(&self) -> u8 {
        match self {
            DexVariant::UniswapV2 => 2,
            DexVariant::UniswapV3 => 3,
            DexVariant::SushiswapV2 => 2,
            DexVariant::SushiswapV3 => 3,
            // Add more cases here as you add more variants
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Eq, PartialEq, Hash)]
pub struct Pool {
    pub id: i64,
    pub address: Address,
    pub version: DexVariant,
    pub token0: Address,
    pub token1: Address,
    pub fee: u32,
    pub block_number: u64,
    pub timestamp: u64,
    pub reserves0: rU256,
    pub reserves1: rU256,
}

impl From<StringRecord> for Pool {
    fn from(record: StringRecord) -> Self {
        let id = match record.get(0).unwrap().parse::<i64>() {
            Ok(id) => id,
            Err(e) => {
                error!("Failed to parse id: {}", e);
                -1 // or any default value you choose
            }
        };

        // Similarly, handle other fields with proper error handling
        let address = match Address::from_str(record.get(1).unwrap()) {
            Ok(address) => address,
            Err(e) => {
                error!("Failed to parse address: {}", e);
                // Handle error case appropriately
                Default::default() // or any default value
            }
        };
        let version = match record.get(2).unwrap() {
            // 2 => DexVariant::UniswapV2,
            "UniswapV2" => DexVariant::UniswapV2,
            "UniswapV3" => DexVariant::UniswapV3,
            "SushiswapV2" => DexVariant::SushiswapV2,
            "SushiswapV3" => DexVariant::SushiswapV3,

            // 3 => DexVariant::UniswapV3,
            _ => DexVariant::UniswapV2, // Default to UniswapV2 if the version is unknown
        };
        Self {
            id: record.get(0).unwrap().parse().unwrap(),
            address: Address::from_str(record.get(1).unwrap()).unwrap(),
            version,
            token0: Address::from_str(record.get(3).unwrap()).unwrap(),
            token1: Address::from_str(record.get(4).unwrap()).unwrap(),
            fee: record.get(5).unwrap().parse().unwrap(),
            block_number: record.get(6).unwrap().parse().unwrap(),
            timestamp: record.get(7).unwrap().parse().unwrap(),
            reserves0: rU256::from_str(record.get(8).unwrap()).unwrap(),
            reserves1: rU256::from_str(record.get(9).unwrap()).unwrap(),
        }
    }
}

impl Pool {
    pub fn cache_row(
        &self,
    ) -> (
        i64,
        String,
        i32,
        String,
        String,
        u32,
        u64,
        u64,
        String,
        String,
    ) {
        (
            self.id,
            format!("{:?}", self.address),
            self.version.num() as i32,
            format!("{:?}", self.token0),
            format!("{:?}", self.token1),
            self.fee,
            self.block_number,
            self.timestamp,
            self.reserves0.to_string(),
            self.reserves1.to_string(),
        )
    }

    pub fn get_protocol_data(&self) -> ProtocolData {
        match self.version {
            DexVariant::UniswapV2 => ProtocolData {
                name: "Uniswap".to_string(),
                version: DexVariant::UniswapV2,
            },
            DexVariant::UniswapV3 => ProtocolData {
                name: "Uniswap".to_string(),
                version: DexVariant::UniswapV3,
            },
            DexVariant::SushiswapV2 => ProtocolData {
                name: "SushiSwap".to_string(),
                version: DexVariant::SushiswapV2,
            },
            DexVariant::SushiswapV3 => ProtocolData {
                name: "SushiSwap".to_string(),
                version: DexVariant::SushiswapV3,
            },
            // Add other variants as needed
        }
    }

    pub fn trades(&self, token_a: Address, token_b: Address) -> bool {
        let is_zero_for_one = self.token0 == token_a && self.token1 == token_b;
        let is_one_for_zero = self.token1 == token_a && self.token0 == token_b;
        is_zero_for_one || is_one_for_zero
    }

    pub fn pretty_msg(&self) -> String {
        format!(
            "[{:?}] {:?}: {:?} --> {:?}",
            self.version, self.address, self.token0, self.token1
        )
    }

    pub fn pretty_print(&self) {
        info!("{}", self.pretty_msg());
    }

    pub fn calculate_price_impact(&self, trade_amount: rU256) -> f64 {
        let reserves0 = self.reserves0;
        let reserves1 = self.reserves1;

        // Convert U256 to f64
        fn to_f64(value: rU256) -> f64 {
            let mut result = 0.0;
            let mut current = value;
            let mut digit = 0;

            while !current.is_zero() {
                let (new_current, remainder) = current.div_rem(rU256::from(10u64));
                result += (remainder.as_limbs()[0] as f64) * 10f64.powi(digit);
                current = new_current;
                digit += 1;
            }

            result
        }

        let reserves0_f64 = to_f64(reserves0);
        let reserves1_f64 = to_f64(reserves1);
        let trade_amount_f64 = to_f64(trade_amount);

        let k = reserves0_f64 * reserves1_f64;
        let new_reserves0 = reserves0_f64 + trade_amount_f64;
        let new_reserves1 = k / new_reserves0;

        let price_before = reserves1_f64 / reserves0_f64;
        let price_after = new_reserves1 / new_reserves0;

        (price_before - price_after).abs() / price_before
    }

    pub async fn get_current_reserves(
        &self,
        provider: Arc<dyn Provider<PubSubFrontend, AnyNetwork>>,
    ) -> Result<(rU256, rU256)> {
        let abi = JsonAbi::parse([
            "function getReserves() external view returns (uint112 reserve0, uint112 reserve1, uint32 blockTimestampLast)"
        ])?;

        // Get the function from the ABI
        let function = abi
            .functions
            .get("getReserves")
            .and_then(|funcs| funcs.first())
            .ok_or_else(|| anyhow!("getReserves function not found in ABI"))?;

        // Encode the function call
        let call_data = function.abi_encode_input(&[])?;
        // Convert Alloy Address to ethers Address

        // Create an Alloy TransactionRequest
        let tx = WithOtherFields::new(TransactionRequest {
            to: Some(TxKind::Call(self.address)),
            input: TransactionInput::new(call_data.into()),
            ..Default::default()
        });

        // Make the call
        let result = provider
            .call(&tx)
            .await
            .map_err(|e| anyhow!("Provider call failed: {}", e))?;

        // Decode the result
        let decoded: Vec<DynSolValue> = function
            .abi_decode_output(&result, true)
            .map_err(|e| anyhow!("Failed to decode output: {}", e))?;

        if decoded.len() < 3 {
            return Err(anyhow!("Unexpected number of return values"));
        }

        let reserve0 = decoded[0]
            .as_uint()
            .ok_or_else(|| anyhow!("Failed to decode reserve0"))?
            .0; // Extract U256 from the tuple

        let reserve1 = decoded[1]
            .as_uint()
            .ok_or_else(|| anyhow!("Failed to decode reserve1"))?
            .0; // Extract U256 from the tuple

        Ok((reserve0, reserve1))
    }

    pub fn contains_token(&self, token: H160) -> bool {
        b160_to_h160(self.token0) == token || b160_to_h160(self.token1) == token
    }
}
