use super::generic_pool::Pool;
use crate::common::utils::{ru256_to_u256, u256_to_f64};
use alloy::primitives::U256;
use alloy::providers::Provider;
use alloy::pubsub::PubSubFrontend;
use alloy_network::AnyNetwork;
use std::cmp::min;
use std::sync::Arc;

// //  Add a filter for uniswap v3 fees!
// pub struct PoolFilters {
//     pub min_liquidity: U256,
//     pub min_volume: U256,
//     pub max_price_impact: f64,
//     pub trade_amount: U256,
// }

pub struct PoolFilters {
    pub min_tvl: U256,
    pub min_balance_ratio: f64,
    pub min_individual_reserve: U256,
}

impl PoolFilters {
    pub fn new(min_tvl: U256, min_balance_ratio: f64, min_individual_reserve: U256) -> Self {
        Self {
            min_tvl,
            min_balance_ratio,
            min_individual_reserve,
        }
    }

    pub fn apply(&self, pool: &Pool) -> bool {
        let reserves0 = pool.reserves0;
        let reserves1 = pool.reserves1;

        // Calculate total value locked (TVL)
        let tvl = reserves0 + reserves1;
        if tvl < self.min_tvl {
            return false;
        }

        // Check minimum individual reserve
        if reserves0 < self.min_individual_reserve || reserves1 < self.min_individual_reserve {
            return false;
        }

        // Calculate balance ratio
        let balance_ratio = self.calculate_balance_ratio(reserves0, reserves1);
        if balance_ratio < self.min_balance_ratio {
            return false;
        }

        true
    }

    fn calculate_balance_ratio(&self, reserves0: U256, reserves1: U256) -> f64 {
        let min_reserve = min(reserves0, reserves1);
        let max_reserve = if reserves0 > reserves1 {
            reserves0
        } else {
            reserves1
        };

        // Convert to f64 for division
        let min_f64 = u256_to_f64(ru256_to_u256(min_reserve));
        let max_f64 = u256_to_f64(ru256_to_u256(max_reserve));

        min_f64 / max_f64
    }
}

pub fn filter_pools(pools: &[Pool], filters: &PoolFilters) -> Vec<Pool> {
    pools
        .iter()
        .filter(|pool| filters.apply(pool))
        .cloned()
        .collect()
}
