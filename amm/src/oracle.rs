use crate::*;
use near_sdk::serde_json::json;

#[ext_contract]
pub trait OracleContractExt {
    fn get_config() -> Promise;
}

pub fn fetch_oracle_config(oracle_contract_id: &str) -> Promise {
    oracle_contract_ext::get_config(&oracle_contract_id, 0, 4_000_000_000_000)
}

pub struct DataRequestArgs {
    pub settlement_time: u64,
    pub outcomes: Option<Vec<String>>,
    pub description: String,
    pub tags: Vec<String>,
    pub sources: Vec<Source>,
    pub challenge_period: U64,
}

const GAS_BASE_CREATE_REQUEST: Gas = 50_000_000_000_000;

impl AMMContract {
    pub fn create_data_request(&self, bond_token: &AccountId, amount: Balance, request_args: DataRequestArgs) -> Promise {
        // Should do a fungible token transfer to the oracle
        fungible_token::fungible_token_transfer_call(
            bond_token, 
            self.oracle.to_string(), 
            amount,
            json!({
                "NewDataRequest": {
                    // 12 hours in nano seconds
                    "challenge_period": request_args.challenge_period,
                    "settlement_time": U64(request_args.settlement_time),
                    "target_contract": env::current_account_id(),
                    "outcomes": request_args.outcomes,
                    "sources": request_args.sources,
                    "description": request_args.description,
                    "tags": request_args.tags,
                },
            }).to_string(),
            Some(GAS_BASE_CREATE_REQUEST),
        )
    }
}

