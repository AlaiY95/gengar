use anyhow::Result;
use ethers::prelude::*;
use ethers::providers::{Provider, Ws};
use ethers::types::spoof::State;
use ethers::{
    self,
    types::{
        transaction::eip2930::AccessList as eAccessList, Bytes, Eip1559TransactionRequest,
        NameOrAddress, U256, U64,
    },
};
use serde::{Deserialize, Serialize};
#[allow(unused_imports)]
use serde_json::to_string_pretty;

use alloy::rpc::types::Transaction as AlloyTransaction;
use log::warn;
use std::{default::Default, sync::Arc};

use crate::common::streams::{NewBlock, NewPendingTx};
use crate::common::utils::b160_to_h160;
// use crate::pools::protocols::{UniswapV2, UniswapV3};
use crate::simulation::types::*;

use std::cmp::max;
// use std::convert::TryFrom;

pub static V2_SWAP_EVENT_ID: &str = "0xd78ad95f";
pub static V3_SWAP_EVENT_ID: &str = "0xc42079f9";

fn convert_alloy_tx_to_ethers_eip1559(tx: &AlloyTransaction) -> Eip1559TransactionRequest {
    Eip1559TransactionRequest {
        from: Some(Address::from_slice(tx.from.as_slice())),
        to: tx
            .to
            .map(|t| NameOrAddress::Address(Address::from_slice(t.as_slice()))),
        gas: Some(U256::from(tx.gas)),
        value: Some(U256::from_str_radix(&tx.value.to_string(), 10).unwrap_or_default()),
        data: Some(Bytes::from(tx.input.to_vec())),
        nonce: Some(U256::from(tx.nonce)),
        access_list: eAccessList::default(), // You might need to convert this if present
        max_priority_fee_per_gas: tx
            .max_priority_fee_per_gas
            .map(|f| U256::from_str_radix(&f.to_string(), 10).unwrap_or_default()),
        max_fee_per_gas: tx
            .max_fee_per_gas
            .map(|f| U256::from_str_radix(&f.to_string(), 10).unwrap_or_default()),
        chain_id: tx.chain_id.map(U64::from),
    }
}

pub async fn debug_trace_call_with_retry(
    provider: &Arc<Provider<Ws>>,
    new_block: &NewBlock,
    pending_tx: &NewPendingTx,
    max_retries: u32,
) -> Result<Option<CallFrame>> {
    let mut retries = 0;
    let mut tx = pending_tx.tx.clone();

    while retries < max_retries {
        let base_fee = new_block.next_base_fee;
        let max_fee_per_gas = max(tx.max_fee_per_gas.unwrap_or(base_fee), base_fee * 2);

        // Adjust the transaction's gas price
        tx.max_fee_per_gas = Some(max_fee_per_gas);

        //    info!(
        //         "Attempting debug_trace_call for tx {:?}, attempt {}/{}",
        //         tx.hash,
        //         retries + 1,
        //         max_retries
        //     );

        // Create tracing options with state override
        let mut opts = GethDebugTracingCallOptions::default();

        let mut state_overrides = State::default();
        state_overrides.account(b160_to_h160(tx.from)).balance =
            // Some(U256::from(1_000_000_000_000_000_000_u128)); // 1 ETH
            // Some(U256::from(10_000_000_000_000_000_000_u128)); // 10 ETH
            Some(U256::from(100_000_000_000_000_000_000_u128)); // 100 ETH

        opts.state_overrides = Some(state_overrides);

        // Configure call tracing with logging enabled
        let mut call_config = CallConfig::default();
        call_config.with_log = Some(true); // required for accessing transaction logs.

        // Set the tracer to the built-in call tracer
        opts.tracing_options.tracer = Some(GethDebugTracerType::BuiltInTracer(
            GethDebugBuiltInTracerType::CallTracer,
        ));

        // Set the tracer configuration to the call tracer with logging enabled
        opts.tracing_options.tracer_config = Some(GethDebugTracerConfig::BuiltInTracer(
            GethDebugBuiltInTracerConfig::CallTracer(call_config),
        ));

        match debug_trace_call(
            provider,
            new_block,
            &NewPendingTx {
                tx: tx.clone(),
                ..pending_tx.clone()
            },
            &opts,
        )
        .await
        {
            Ok(Some(frame)) => return Ok(Some(frame)),
            Ok(None) => {
                warn!("Debug trace call returned None for tx {:?}", tx.hash);
                return Ok(None);
            }
            Err(e) => {
                let error_message = e.to_string();
                if error_message.contains("max fee per gas less than block base fee") {
                    retries += 1;
                    // info!(
                    //     "Retrying debug_trace_call with higher gas price. Attempt {}/{}",
                    //     retries, max_retries
                    // );
                } else if error_message.contains("insufficient funds") {
                    warn!(
                        "Insufficient funds for tracing, even with balance override. Tx: {:?}",
                        tx.hash
                    );
                    return Ok(None);
                } else {
                    // error!("Unexpected error in debug_trace_call: {:?}", e);
                    return Err(e.into());
                }
            }
        }
    }

    // warn!(
    //     "Failed to debug trace call after {} retries for tx {:?}",
    //     max_retries, tx.hash
    // );
    Ok(None)
}

pub async fn debug_trace_call(
    provider: &Arc<Provider<Ws>>,
    new_block: &NewBlock,
    pending_tx: &NewPendingTx,
    opts: &GethDebugTracingCallOptions,
) -> Result<Option<CallFrame>> {
    // Get the block number from the new block
    let block_number = new_block.block_number;

    // Clone the pending transaction
    let mut tx = pending_tx.tx.clone();

    // Get the nonce for the transaction sender at the given block number
    let nonce = provider
        .get_transaction_count(b160_to_h160(tx.from), Some(block_number.into()))
        .await
        .unwrap_or_default();

    let nonce_u64 = if nonce > U256::from(u64::MAX) {
        u64::MAX
    } else {
        nonce.as_u64()
    };

    // Set the nonce for the transaction
    tx.nonce = nonce_u64;

    // Convert the Alloy transaction to an Ethers Eip1559TransactionRequest
    let ethers_tx = convert_alloy_tx_to_ethers_eip1559(&tx);

    // Create a TypedTransaction from the Eip1559TransactionRequest
    let typed_tx = ethers::types::transaction::eip2718::TypedTransaction::Eip1559(ethers_tx);

    // Perform a debug trace call using the provider, transaction, block number, and tracing options
    let trace = provider
        .debug_trace_call(typed_tx, Some(block_number.into()), opts.clone())
        .await?;

    // Match the result of the trace call
    match trace {
        GethTrace::Known(call_tracer) => match call_tracer {
            GethTraceFrame::CallTracer(frame) => Ok(Some(frame)),
            _ => Ok(None),
        },
        _ => Ok(None),
    }
}

/*
Example of Call Frame
{
    "call_type": "CALL",
    "from": "0x123...",
    "to": "0x456...",
    "input": "0x...",
    "output": "0x...",
    "gas": 21000,
    "gas_used": 19000,
    "value": "0x0",
    "depth": 1,
    "error": null,
    "logs": [
        {
            "address": "0x789...",
            "topics": ["0x...", "0x..."],
            "data": "0x..."
        }
    ],
    "calls": [
        {
            "call_type": "CALL",
            "from": "0x456...",
            "to": "0x789...",
            "input": "0x...",
            "output": "0x...",
            "gas": 20000,
            "gas_used": 15000,
            "value": "0x0",
            "depth": 2,
            "error": null,
            "logs": [
                {
                    "address": "0xabc...",
                    "topics": ["0x...", "0x..."],
                    "data": "0x..."
                }
            ],
            "calls": []
        }
    ]
}
*/
pub fn extract_logs(call_frame: &CallFrame, logs: &mut Vec<CallLogFrame>) {
    // info!("Executing simulation.extract_logs()");

    // Check if the call frame has logs
    if let Some(ref logs_vec) = call_frame.logs {
        // Extend the logs vector with the logs from the call frame
        logs.extend(logs_vec.iter().cloned());
    }

    // Check if the call frame has nested calls
    if let Some(ref calls_vec) = call_frame.calls {
        // Iterate over the nested calls
        for call in calls_vec {
            // Recursively call extract_logs to extract logs from nested calls
            extract_logs(call, logs);
        }
    }
}
