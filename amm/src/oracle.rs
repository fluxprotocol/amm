use crate::*;
use near_sdk::serde_json::json;

#[ext_contract]
pub trait OracleContractExt {
    fn get_config() -> Promise;
}

pub fn fetch_oracle_config(oracle_contract_id: &str) -> Promise {
    oracle_contract_ext::get_config(&oracle_contract_id, 0, 4_000_000_000_000)
} 

const GAS_BASE_CREATE_REQUEST: Gas = 50_000_000_000_000;

impl AMMContract {
    pub fn create_data_request(&self, bond_token: &AccountId, amount: Balance, market_args: &CreateMarketArgs) -> Promise {
        let is_scalar = market_args.is_scalar.unwrap_or(false);
        let outcomes: Vec<String> = if is_scalar {
            // TODO: What should we do with scalar markets?
            [].to_vec()
        } else {
            market_args.outcome_tags.clone()
        };

        // Should do a fungible token transfer to the oracle
        fungible_token::fungible_token_transfer_call(
            bond_token, 
            self.oracle.to_string(), 
            amount,
            json!({
                "NewDataRequest": {
                    // TODO: 12 hour challenge period,
                    // TODO: Turn this back in to a U64(), it's not correct on the oracle side
                    "challenge_period": 2999,
                    "settlement_time": U64(ms_to_ns(market_args.resolution_time.into())),
                    "target_contract": env::current_account_id(),
                    "outcomes": outcomes,
                    "sources": [],
                    "description": format!("{} - {}", market_args.description, market_args.extra_info),
                },
            }).to_string(),
            Some(GAS_BASE_CREATE_REQUEST),
        )
    }
}

