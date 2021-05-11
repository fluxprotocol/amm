use crate::*;
use near_sdk::serde_json::json;

#[ext_contract]
pub trait OracleContractExt {
    fn get_config() -> Promise;
}

pub fn fetch_oracle_config(oracle_contract_id: &str) -> Promise {
    oracle_contract_ext::get_config(&oracle_contract_id, 0, 4_000_000_000_000)
} 

impl AMMContract {
    pub fn create_data_request(&self, bond_token: AccountId, amount: Balance) -> Promise {
        let oracle_contract_id = "oracle";
        // Should do a fungible token transfer to the oracle
        fungible_token::fungible_token_transfer(
            bond_token, 
            oracle_contract_id.to_string(), 
            amount,
            json!({
                "NewDataRequest": {
                    // 12 hour challenge period,
                    "challenge_period": U64(2999),
                    "settlement_time": U64(2999),
                    "target_contract": "oracle".to_string(),
                    "sources": [],
                    "description": "test"
                },
            }).to_string()
        )
    }
}

