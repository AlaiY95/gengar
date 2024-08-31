use alloy::eips::eip2930::AccessList as rAccessList;

use ethers::types::transaction::eip2930::AccessList as eAccessList;
use log::{error, info, warn};

use alloy::eips::{BlockId, BlockNumberOrTag};
use serde::{Deserialize, Serialize};

use alloy::network::AnyNetwork;
use alloy::providers::Provider as AlloyProvider;
use alloy::transports::BoxTransport;
use anyhow::{anyhow, Result};
use ethers::prelude::abi;

use revm::primitives::specification::SpecId;
// use ethers::providers::Middleware;
use ethers::types::{Bytes as eBytes, H160, H256, U256, U64};

use foundry_evm::fork::{BlockchainDb, BlockchainDbMeta, SharedBackend};

use foundry_evm::inspectors::AccessListInspector;
use revm::primitives::{Address, Bytes as rBytes, FixedBytes, HandlerCfg, Log, U256 as rU256};
use revm::{
    db::{CacheDB, Database},
    primitives::{keccak256, AccountInfo, Bytecode, ExecutionResult, Output, TransactTo, B256},
    Context,
    Evm,
    Handler,
    // Handler::{self, HandlerCfg, InstructionTables, ValidationHandler, HandleRegisters, PreExecutionHandler, PostExecutionHandler, ExecutionHandler, Host},
};
use std::collections::HashMap;
use std::{default::Default, str::FromStr, sync::Arc};

use crate::common::abi::Abi;
use crate::common::constants::COINBASE;
use crate::common::token_loader::Token;
use crate::simulation::types::MiddleTx;

use crate::common::utils::{
    access_list_to_ethers, access_list_to_revm, alloy_to_ethers_bytes, b160_to_h160,
    create_new_wallet, ethers_to_alloy_bytes, get_precompiles_for, h160_to_b160, ru256_to_u256,
    u256_to_ru256,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tx {
    pub caller: H160,
    pub transact_to: H160,
    pub data: eBytes,
    pub value: U256,
    pub gas_price: U256,
    pub gas_limit: u64,
}

impl Tx {
    pub fn from(tx: MiddleTx) -> Self {
        let gas_limit = match tx.gas_limit {
            Some(gas_limit) => gas_limit,
            None => 5000000,
        };
        Self {
            caller: tx.from,
            transact_to: tx.to,
            data: tx.data,
            value: tx.value,
            gas_price: tx.gas_price,
            gas_limit,
        }
    }
    pub fn default() -> Self {
        Tx {
            caller: H160::zero(),
            transact_to: H160::zero(),
            data: eBytes::default(),
            value: U256::zero(),
            gas_price: U256::zero(),
            gas_limit: 0,
        }
    }
}

#[derive(Debug, Clone)]
pub struct TxResult {
    pub output: eBytes,
    pub logs: Option<Vec<Log>>,
    pub gas_used: u64,
    pub gas_refunded: u64,
}

pub struct EvmSimulator<'a, P>
where
    P: AlloyProvider<BoxTransport, AnyNetwork> + 'static + Clone, // utilising the Provider trait that is generic over T: Transport and Clone
{
    pub provider: Arc<P>,
    // transport: T,
    pub owner: H160,
    pub evm: Evm<'a, (), CacheDB<SharedBackend>>,
    pub block_number: U64,
    pub abi: Abi,
    // pub common_pairs: CommonPairs,
    // pub tokens: HashMap<H160, Token>,
}

impl<'a, P> EvmSimulator<'a, P>
where
    P: AlloyProvider<BoxTransport, AnyNetwork> + 'static + Clone,
{
    pub fn new(
        provider: Arc<P>,
        owner: Option<H160>,
        block_number: U64,
    ) -> Result<Self, anyhow::Error> {
        let blockchain_db = BlockchainDb::new(
            BlockchainDbMeta {
                cfg_env: Default::default(),
                block_env: Default::default(),
                hosts: std::collections::BTreeSet::from(["".to_string()]),
            },
            None,
        );

        let block_id = BlockId::Number(BlockNumberOrTag::Number(block_number.as_u64()));

        // The SharedBackend::spawn_backend_thread method required both T: Transport + Clone + Unpin and P: Provider<T, AnyNetwork> +Unpin + static + Clone,
        let shared_backend = SharedBackend::spawn_backend_thread(
            Arc::clone(&provider),
            blockchain_db,
            Some(block_id),
        );

        let db = CacheDB::new(shared_backend);

        // MIGHT HAVE TO USE A HELPER FUNCTION!!
        EvmSimulator::new_with_db(provider, owner, block_number, db)
    }

    pub fn new_with_db(
        provider: Arc<P>,
        owner: Option<H160>,
        block_number: U64,
        db: CacheDB<SharedBackend>,
        // tokens: HashMap<H160, Token>,
    ) -> Result<Self, anyhow::Error> {
        let owner = match owner {
            Some(owner) => owner,
            None => create_new_wallet().1,
        };

        let context = Context::new_with_db(db);

        let handler_cfg = HandlerCfg::new(SpecId::LATEST);

        let handler = Handler::new(handler_cfg);

        let mut evm = Evm::new(context, handler);

        // evm.database(db);
        let block_num: u64 = block_number.as_u64();

        evm.context.evm.inner.env.block.number = rU256::from(block_num + 1);
        // WHAT IS THE POINT OF SETTING THIS COINBASE??
        evm.context.evm.inner.env.block.coinbase = Address::from_str(COINBASE).unwrap().into();

        Ok(Self {
            provider,
            owner,
            evm,
            block_number,
            abi: Abi::new(),
            // common_pairs,
            // tokens,
        })
    }

    pub fn clone_db(&mut self) -> CacheDB<SharedBackend> {
        self.evm.context.evm.inner.db.clone()
    }

    pub fn insert_db(&mut self, db: CacheDB<SharedBackend>) {
        let new_context = Context::new_with_db(db);
        let handler_cfg = self.evm.handler.cfg.clone();
        let new_handler = Handler::new(handler_cfg);
        let mut evm = Evm::new(new_context, new_handler);

        // Maintain the current block number and coinbase values
        evm.context.evm.inner.env.block.number = self.evm.context.evm.inner.env.block.number;
        evm.context.evm.inner.env.block.coinbase = self.evm.context.evm.inner.env.block.coinbase;

        self.evm = evm;
    }

    pub fn get_block_number(&mut self) -> U256 {
        let revm_u256 = self.evm.context.evm.inner.env.block.number;
        ru256_to_u256(revm_u256)
    }

    pub fn get_coinbase(&mut self) -> H160 {
        let revm_address = self.evm.context.evm.inner.env.block.coinbase;

        b160_to_h160(revm_address)
    }

    pub fn get_base_fee(&mut self) -> U256 {
        let revm_u256 = self.evm.context.evm.inner.env.block.basefee;
        ru256_to_u256(revm_u256)
    }

    pub fn set_base_fee(&mut self, base_fee: U256) {
        self.evm.context.evm.inner.env.block.basefee = u256_to_ru256(base_fee);
    }

    /*
        Purpose:
    This function is trying to generate an AccessList for a given transaction without actually executing the transaction.
    An AccessList is a feature introduced in EIP-2930 that allows specifying a list of addresses and storage keys that
    a transaction will access. This can help reduce gas costs for transactions that access the same addresses and storage slots repeatedly.
     */
    // pub fn get_access_list(&mut self, tx: Tx) -> Result<eAccessList, Box<dyn Error>> {
    pub fn get_access_list(&mut self, tx: Tx) -> eAccessList {
        self.evm.context.evm.inner.env.tx.caller = h160_to_b160(tx.caller);
        self.evm.context.evm.inner.env.tx.transact_to =
            TransactTo::Call(h160_to_b160(tx.transact_to));
        self.evm.context.evm.inner.env.tx.data = ethers_to_alloy_bytes(tx.data);
        self.evm.context.evm.inner.env.tx.value = u256_to_ru256(tx.value);
        self.evm.context.evm.inner.env.tx.gas_price = u256_to_ru256(tx.gas_price);
        self.evm.context.evm.inner.env.tx.gas_limit = tx.gas_limit;

        let mut access_list_inspector = AccessListInspector::new(
            Default::default(),
            h160_to_b160(tx.caller),
            h160_to_b160(tx.transact_to),
            get_precompiles_for(SpecId::LATEST),
        );

        match self.evm.transact() {
            Ok(_) => {
                let access_list: rAccessList = access_list_inspector.access_list();
                let access_list_vec: Vec<(Address, Vec<rU256>)> = access_list
                    .0
                    .iter()
                    .map(|item| {
                        (
                            item.address,
                            item.storage_keys.iter().map(|key| (*key).into()).collect(),
                        )
                    })
                    .collect();

                access_list_to_ethers(access_list_vec)
            }
            Err(_) => eAccessList::default(),
        }
    }

    pub fn set_access_list(&mut self, access_list: eAccessList) {
        self.evm.context.evm.inner.env.tx.access_list = access_list_to_revm(access_list);
    }

    pub fn staticcall(&mut self, mut tx: Tx) -> Result<TxResult> {
        // info!("STATICCALL EXECUTED!! LETS GOOOOO!!!");
        const MAX_RETRIES: u8 = 3;
        let mut retries = 0;
        let mut current_gas_price = tx.gas_price.max(self.get_base_fee());

        loop {
            tx.gas_price = current_gas_price;
            match self._call(tx.clone(), false) {
                Ok(result) => return Ok(result),
                Err(e) => {
                    if retries >= MAX_RETRIES {
                        return Err(anyhow!("Max retries reached. Last error: {:?}", e));
                    }
                    if e.to_string().contains("GasPriceLessThanBasefee") {
                        current_gas_price = current_gas_price * 120 / 100; // Increase by 20%
                        retries += 1;
                        println!(
                            "Retrying staticcall with increased gas price: {:?}",
                            current_gas_price
                        );
                    } else {
                        return Err(e);
                    }
                }
            }
        }
    }

    pub fn call(&mut self, mut tx: Tx) -> Result<TxResult> {
        info!("Executing transaction: {:?}", tx);
        const MAX_RETRIES: u8 = 3;
        let mut retries = 0;
        let mut current_gas_price = tx.gas_price.max(self.get_base_fee());

        loop {
            tx.gas_price = current_gas_price;
            // info!(
            //     "Attempt {} with gas price: {}",
            //     retries + 1,
            //     current_gas_price
            // );

            match self._call(tx.clone(), true) {
                Ok(result) => {
                    // info!("Transaction successful. Gas used: {}", result.gas_used);
                    return Ok(result);
                }
                Err(e) => {
                    if retries >= MAX_RETRIES {
                        error!("Max retries reached. Last error: {:?}", e);
                        return Err(anyhow!("Max retries reached. Last error: {:?}", e));
                    }
                    if e.to_string().contains("GasPriceLessThanBasefee") {
                        current_gas_price = current_gas_price * 120 / 100; // Increase by 20%
                        retries += 1;
                        warn!("Retrying with increased gas price: {:?}", current_gas_price);
                    } else {
                        error!("Transaction failed: {:?}", e);
                        return Err(e);
                    }
                }
            }
        }
    }

    pub fn _call(&mut self, tx: Tx, commit: bool) -> Result<TxResult> {
        self.evm.context.evm.inner.env.tx.caller = h160_to_b160(tx.caller);
        self.evm.context.evm.inner.env.tx.transact_to =
            TransactTo::Call(h160_to_b160(tx.transact_to));
        self.evm.context.evm.inner.env.tx.data = ethers_to_alloy_bytes(tx.data); // Should this require conversion from alloy/ethers bytes to the other????
        self.evm.context.evm.inner.env.tx.value = u256_to_ru256(tx.value);
        self.evm.context.evm.inner.env.tx.gas_price = u256_to_ru256(tx.gas_price);
        self.evm.context.evm.inner.env.tx.gas_limit = tx.gas_limit;

        let result;

        if commit {
            result = match self.evm.transact_commit() {
                Ok(result) => result,
                Err(e) => return Err(anyhow!("EVM call failed: {:?}", e)),
            };
        } else {
            let ref_tx = self
                .evm
                .transact()
                .map_err(|e| anyhow!("EVM staticcall failed: {:?}", e))?;
            result = ref_tx.result;
        }

        let output = match result {
            ExecutionResult::Success {
                gas_used,
                gas_refunded,
                output,
                logs,
                ..
            } => match output {
                Output::Call(o) => TxResult {
                    output: alloy_to_ethers_bytes(o),
                    logs: Some(logs),
                    gas_used,
                    gas_refunded,
                },
                Output::Create(o, _) => TxResult {
                    output: alloy_to_ethers_bytes(o),
                    logs: Some(logs),
                    gas_used,
                    gas_refunded,
                },
            },
            ExecutionResult::Revert { gas_used, output } => {
                return Err(anyhow!(
                    "EVM REVERT: {:?} / Gas used: {:?}",
                    output,
                    gas_used
                ))
            }
            ExecutionResult::Halt { reason, .. } => return Err(anyhow!("EVM HALT: {:?}", reason)),
        };

        Ok(output)
    }

    pub fn basic(&mut self, target: H160) -> Result<Option<AccountInfo>> {
        self.evm
            .context
            .evm
            .inner
            .db
            .basic(h160_to_b160(target))
            .map_err(|e| anyhow!("Basic error: {e:?}"))
    }

    pub fn insert_account_info(&mut self, target: H160, account_info: AccountInfo) {
        self.evm
            .context
            .evm
            .inner
            .db
            .insert_account_info(h160_to_b160(target), account_info);
    }

    pub fn insert_account_storage(
        &mut self,
        target: H160,
        slot: rU256,
        value: rU256,
    ) -> Result<()> {
        self.evm
            .context
            .evm
            .inner
            .db
            .insert_account_storage(h160_to_b160(target), slot, value)?;
        Ok(())
    }

    pub fn deploy(&mut self, target: H160, bytecode: Bytecode) {
        let contract_info = AccountInfo::new(rU256::ZERO, 0, B256::ZERO, bytecode);
        self.insert_account_info(target, contract_info);
    }

    pub fn get_eth_balance_of(&mut self, target: H160) -> U256 {
        let acc = self.basic(target).unwrap().unwrap();
        ru256_to_u256(acc.balance)
    }

    pub fn set_eth_balance(&mut self, target: H160, amount: U256) {
        let user_balance = u256_to_ru256(amount);
        let user_info = AccountInfo::new((user_balance), 0, B256::ZERO, Bytecode::default());
        self.insert_account_info(target.into(), user_info);
    }

    // pub fn get_token_balance(&mut self, token_address: H160, owner: H160) -> Result<U256> {
    //     info!("Running get token balance");
    //     let calldata = self.abi.token.encode("balanceOf", owner)?;
    //     // let alloy_calldata = ethers_to_alloy_bytes(calldata);

    //     // Create the transaction
    //     let tx = Tx {
    //         caller: self.owner,
    //         transact_to: token_address,
    //         // data: calldata.0,
    //         data: ethers::types::Bytes((calldata.0)),
    //         value: U256::zero(),
    //         gas_price: U256::zero(),
    //         gas_limit: 5000000,
    //     };
    //     info!("Transaction created: {:?}", tx);

    //     // Perform the static call
    //     let value = match self.staticcall(tx) {
    //         Ok(result) => {
    //             info!("Static call successful, received value: {:?}", result);
    //             result
    //         }
    //         Err(e) => {
    //             error!("Error performing static call: {:?}", e);
    //             return Err(e.into());
    //         }
    //     };

    //     let out = self.abi.token.decode_output("balanceOf", value.output)?;
    //     Ok(out)
    // }

    pub fn get_token_balance(&mut self, token_address: H160, owner: H160) -> Result<U256> {
        let calldata = self.abi.token.encode("balanceOf", owner)?;
        // let alloy_calldata = ethers_to_alloy_bytes(calldata);
        let value = self.staticcall(Tx {
            caller: self.owner,
            transact_to: token_address,
            // data: calldata.0,
            data: ethers::types::Bytes((calldata.0)),
            value: U256::zero(),
            gas_price: U256::zero(),
            gas_limit: 5000000,
        })?;
        let out = self.abi.token.decode_output("balanceOf", value.output)?;
        Ok(out)
    }

    // pub fn get_token_balance(&mut self, token_address: H160, owner: H160) -> Result<U256> {
    //     info!(
    //         "Attempting to get token balance for token: {:?}, owner: {:?}",
    //         token_address, owner
    //     );

    //     let calldata = match self.abi.token.encode("balanceOf", owner) {
    //         Ok(data) => {
    //             info!("Successfully encoded balanceOf calldata");
    //             data
    //         }
    //         Err(e) => {
    //             error!("Failed to encode balanceOf calldata: {:?}", e);
    //             return Err(anyhow::anyhow!("Failed to encode balanceOf calldata"));
    //         }
    //     };

    //     info!("Encoded calldata: {:?}", calldata);

    //     let tx = Tx {
    //         caller: self.owner,
    //         transact_to: token_address,
    //         data: ethers::types::Bytes((calldata.0)),
    //         value: U256::zero(),
    //         gas_price: U256::zero(),
    //         gas_limit: 5000000,
    //     };

    //     info!("Preparing to make staticcall with tx: {:?}", tx);

    //     let value = match self.staticcall(tx) {
    //         Ok(v) => {
    //             info!("Staticcall successful");
    //             v
    //         }
    //         Err(e) => {
    //             error!("Staticcall failed: {:?}", e);
    //             return Err(anyhow::anyhow!("Staticcall failed"));
    //         }
    //     };

    //     info!("Staticcall output: {:?}", value.output);

    //     let out = match self.abi.token.decode_output("balanceOf", value.output) {
    //         Ok(o) => {
    //             info!("Successfully decoded balanceOf output");
    //             o
    //         }
    //         Err(e) => {
    //             error!("Failed to decode balanceOf output: {:?}", e);
    //             return Err(anyhow::anyhow!("Failed to decode balanceOf output"));
    //         }
    //     };

    //     info!(
    //         "Token balance for {:?} of owner {:?}: {:?}",
    //         token_address, owner, out
    //     );

    //     Ok(out)
    // }

    pub fn set_token_balance(
        &mut self,
        token_address: H160,
        to: H160,
        slot: u32,
        amount: ethers::types::U256,
    ) -> Result<()> {
        info!(
            "Setting balance for token {:?}, account {:?}, slot {}, amount {}",
            token_address, to, slot, amount
        );

        let balance_slot = keccak256(&abi::encode(&[
            abi::Token::Address(to.into()),
            abi::Token::Uint(ethers::types::U256::from(slot)),
        ]));

        let amount_ru256 = u256_to_ru256(amount);

        self.insert_account_storage(token_address, balance_slot.into(), amount_ru256)?;
        Ok(())
    }

    pub fn get_pair_reserves(&mut self, pair_address: H160) -> Result<(U256, U256)> {
        let calldata = self.abi.pair.encode("getReserves", ())?;
        let tx = Tx {
            caller: self.owner,
            transact_to: pair_address,
            data: ethers::types::Bytes(calldata.0),
            value: U256::zero(),
            gas_price: self.get_base_fee(), // Use base_fee as the minimum gas price
            gas_limit: 5000000,
        };
        let value = self.staticcall(tx)?;
        let out: (U256, U256, U256) = self.abi.pair.decode_output("getReserves", value.output)?;
        Ok((out.0, out.1))
    }

    // pub fn get_pair_reserves(&mut self, pair_address: H160) -> Result<(U256, U256)> {
    //     // Log the start of the function call
    //     info!(
    //         "Starting get_pair_reserves for pair address: {:?}",
    //         pair_address
    //     );

    //     // Encode the calldata
    //     let calldata = match self.abi.pair.encode("getReserves", ()) {
    //         Ok(data) => {
    //             info!("Successfully encoded calldata for getReserves");
    //             data
    //         }
    //         Err(e) => {
    //             error!("Error encoding calldata for getReserves: {:?}", e);
    //             return Err(e.into());
    //         }
    //     };

    //     // Create the transaction
    //     let tx = Tx {
    //         caller: self.owner,
    //         transact_to: pair_address,
    //         data: ethers::types::Bytes(calldata.0),
    //         value: U256::zero(),
    //         gas_price: self.get_base_fee(), // Use base_fee as the minimum gas price
    //         gas_limit: 5000000,
    //     };
    //     info!("Transaction created: {:?}", tx);

    //     // Perform the static call
    //     let value = match self.staticcall(tx) {
    //         Ok(result) => {
    //             info!("Static call successful, received value: {:?}", result);
    //             result
    //         }
    //         Err(e) => {
    //             error!("Error performing static call: {:?}", e);
    //             return Err(e.into());
    //         }
    //     };

    //     // Decode the output
    //     let out: (U256, U256, U256) = match self.abi.pair.decode_output("getReserves", value.output)
    //     {
    //         Ok(decoded) => {
    //             info!("Successfully decoded output for getReserves");
    //             decoded
    //         }
    //         Err(e) => {
    //             error!("Error decoding output for getReserves: {:?}", e);
    //             return Err(e.into());
    //         }
    //     };

    //     // Log the successful retrieval of reserves
    //     info!(
    //         "Successfully retrieved reserves: ({:?}, {:?})",
    //         out.0, out.1
    //     );
    //     Ok((out.0, out.1))
    // }

    pub fn get_balance_slot(&mut self, token_address: H160) -> Result<i32> {
        let calldata = self.abi.token.encode("balanceOf", token_address)?;
        self.evm.context.evm.inner.env.tx.caller = h160_to_b160(self.owner);
        self.evm.context.evm.inner.env.tx.transact_to =
            TransactTo::Call(h160_to_b160(token_address));
        self.evm.context.evm.inner.env.tx.data = rBytes(calldata.0);
        let result = match self.evm.transact() {
            Ok(result) => result,
            Err(e) => return Err(anyhow!("EVM ref call failed: {e:?}")),
        };
        let token_b160: Address = h160_to_b160(token_address);
        let token_acc = result.state.get(&token_b160).unwrap();
        let token_touched_storage = token_acc.storage.clone();
        for i in 0..30 {
            let slot_bytes: FixedBytes<32> = keccak256(&abi::encode(&[
                abi::Token::Address(token_address),
                abi::Token::Uint(U256::from(i)),
            ]));

            // Convert FixedBytes<32> to revm::U256 directly
            let slot: rU256 = rU256::from_be_bytes(slot_bytes.0);

            match token_touched_storage.get(&slot) {
                Some(_) => {
                    return Ok(i);
                }
                None => {}
            }
        }

        Ok(-1)
    }

    // fn find_pair_address(&self, token_a: H160, token_b: H160) -> Result<H160> {
    //     let weth = self
    //         .tokens
    //         .values()
    //         .find(|t| t.symbol == "WETH")
    //         .map(|t| t.address)
    //         .ok_or_else(|| anyhow::anyhow!("WETH token not found"))?;

    //     if token_a == weth || token_b == weth {
    //         let non_weth_token = if token_a == weth { token_b } else { token_a };
    //         if let Some(&pair) = self.common_pairs.weth_pairs.get(&non_weth_token) {
    //             return Ok(pair);
    //         }
    //     }

    //     let sorted_tokens = if token_a < token_b {
    //         (token_a, token_b)
    //     } else {
    //         (token_b, token_a)
    //     };
    //     if let Some(&pair) = self.common_pairs.other_pairs.get(&sorted_tokens) {
    //         return Ok(pair);
    //     }

    //     let uniswap_v2_factory = UniswapV2.factory_address();
    //     // let uniswap_v3_factory = UniswapV3.factory_address();

    //     let salt = keccak256(&[&token_a.as_bytes()[..], &token_b.as_bytes()[..]].concat());

    //     let init_code_hash = hex::decode(UNISWAP_V2_PAIR_INIT_CODE_HASH)
    //         .map_err(|e| anyhow::anyhow!("Failed to decode init code hash: {}", e))?;
    //     let init_code_hash: [u8; 32] = init_code_hash
    //         .try_into()
    //         .map_err(|_| anyhow::anyhow!("Invalid init code hash length"))?;

    //     let v2_pair = self.create2_address(uniswap_v2_factory, *salt, init_code_hash)?;

    //     if self.pair_exists(v2_pair)? {
    //         return Ok(v2_pair);
    //     } else {
    //         Err(anyhow::anyhow!(
    //             "Pair not found for tokens {:?} and {:?}",
    //             token_a,
    //             token_b
    //         ))
    //     }

    //     /*
    //      * If V2 pair doesn't exist, try V3
    //      * Note: V3 pair creation is more complex and depends on the fee tier.
    //      * This is a simplified version and may needto be adjusted
    //      */
    //     // let v3_salt = keccak256(&[
    //     //     &token_a.as_bytes()[..],
    //     //     &token_b.as_bytes()[..],
    //     //     &[0,0,0,0,0,0,5,0] // Assuming 0.3% fee tier (3000)
    //     // ].concat());

    //     // let v3_pair = self.create2_address(uniswap_v3_factory, *v3_salt, UNISWAP_V3_PAIR_INIT_CODE_HASH)?;

    //     // if self.pair_exists(v3_pair)? {
    //     //     return Ok(v2_pair);
    //     // } else {
    //     //     Err(anyhow::anyhow! ("Pair not found for tokens {:?} and {:?}", token_a, token_b))
    //     // }

    //     // self.common_pairs
    //     //     .other_pairs
    //     //     .get(&sorted_tokens) // This line is now correct
    //     //     .copied()
    //     //     .ok_or_else(|| {
    //     //         anyhow::anyhow!("Pair not found for tokens {:?} and {:?}", token_a, token_b)
    //     //     })
    // }

    fn create2_address(
        &self,
        factory: Address,
        salt: [u8; 32],
        init_code_hash: [u8; 32],
    ) -> Result<H160> {
        let address =
            ethers::utils::get_create2_address(b160_to_h160(factory), salt, init_code_hash);
        Ok(H160::from_slice(&address[..]))
    }

    fn pair_exists(&self, pair_address: H160) -> Result<bool> {
        Ok(pair_address != H160::zero())
    }

    // pub fn convert_token_to_weth(&mut self, token: H160, amount: U256) -> Result<U256> {
    //     let weth_address = self
    //         .tokens
    //         .values()
    //         .find(|t| t.symbol == "WETH")
    //         .map(|t| t.address)
    //         .ok_or_else(|| anyhow::anyhow!("WETH token not found"))?;

    //     if token == weth_address {
    //         return Ok(amount);
    //     }

    //     let pair_address = self.find_pair_address(token, weth_address)?;
    //     let (reserve_token, reserve_weth) = self.get_pair_reserves(pair_address)?;

    //     // Use the constant product formula to calculate the amount of WETH
    //     // This is a simplified version and doesn't account for fees
    //     let amount_out = amount * reserve_weth / (reserve_token + amount);

    //     Ok(amount_out)
    // }

    // pub fn convert_profit_to_weth(&mut self, total_profit: I256) -> Result<I256> {
    //     let weth_address = self
    //         .tokens
    //         .values()
    //         .find(|t| t.symbol == "WETH")
    //         .map(|t| t.address)
    //         .ok_or_else(|| anyhow::anyhow!("WETH token not found"))?;

    //     let mut weth_profit = I256::zero();

    //     // Extract owner address
    //     let owner = self.owner;

    //     // Collect all necessary information beforehand
    //     let token_data: Vec<_> = self
    //         .tokens
    //         .iter()
    //         .map(|(token, info)| (*token, info.symbol.clone(), info.name.clone()))
    //         .collect();

    //     for (token, symbol, name) in token_data {
    //         if token == weth_address {
    //             continue; // Skip WETH itself
    //         }

    //         // Get the token balance
    //         let balance = self.get_token_balance(token, owner)?;

    //         // If the balance is non-zero, convert it to WETH
    //         if balance > U256::zero() {
    //             let weth_amount = self.convert_token_to_weth(token, balance)?;
    //             weth_profit += I256::from_raw(weth_amount);
    //         }

    //         // println!(
    //         //     "Converted profit for token {}: {} ({})",
    //         //     symbol, weth_profit, name
    //         // );
    //     }

    //     // Add the WETH balance itself
    //     let weth_balance = self.get_token_balance(weth_address, owner)?;
    //     weth_profit += I256::from_raw(weth_balance);

    //     Ok(weth_profit)
    // }

    pub fn get_token_allowance(&mut self, token: H160, owner: H160, spender: H160) -> Result<U256> {
        let calldata = self.abi.token.encode("allowance", (owner, spender))?;
        let value = self.staticcall(Tx {
            caller: self.owner,
            transact_to: token,
            data: ethers::types::Bytes(calldata.0),
            value: U256::zero(),
            gas_price: U256::zero(),
            gas_limit: 5000000,
        })?;
        let out = self.abi.token.decode_output("allowance", value.output)?;
        Ok(out)
    }
    // Does this get every token in the evm?? what the frick
    // pub fn get_all_tokens(&self) -> impl Iterator<Item = &H160> + '_ {
    //     self.tokens.keys()
    // }

    // pub fn get_all_pairs(&self) -> impl Iterator<Item = &H160> + '_ {
    //     self.common_pairs
    //         .weth_pairs
    //         .values()
    //         .chain(self.common_pairs.usdt_pairs.values())
    //         .chain(self.common_pairs.usdc_pairs.values())
    //         .chain(self.common_pairs.other_pairs.values())
    // }
}
