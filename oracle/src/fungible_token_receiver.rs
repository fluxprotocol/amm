use crate::*;

use storage_manager::{ STORAGE_PRICE_PER_BYTE };
use near_sdk::serde::{ Serialize, Deserialize };
use near_sdk::serde_json;

#[derive(Serialize, Deserialize)]
pub enum Payload {
    NewDataRequest(NewDataRequestArgs),
    StakeDataRequest(StakeDataRequestArgs)
}

pub trait FungibleTokenReceiver {
    // @returns amount of unused tokens
    fn ft_on_transfer(&mut self, sender_id: AccountId, amount: U128, msg: String) -> U128;
}

#[near_bindgen]
impl FungibleTokenReceiver for Contract {
    // @returns amount of unused tokens
    fn ft_on_transfer(
        &mut self,
        sender_id: AccountId,
        amount: U128,
        msg: String
    ) -> U128 {
        let initial_storage_usage = env::storage_usage();
        let initial_user_balance = self.accounts.get(&sender_id).unwrap_or(0);
        let payload: Payload =  serde_json::from_str(&msg).expect("Failed to parse the payload, invalid `msg` format");
        let unspent: U128 = match payload {
            Payload::NewDataRequest(payload) => self.dr_new(sender_id.clone(), amount.into(), payload),
            Payload::StakeDataRequest(payload) => self.dr_stake(sender_id.clone(), amount.into(), payload),
        }.into();

        if env::storage_usage() >= initial_storage_usage {
            // used more storage, deduct from balance
            let difference : u128 = u128::from(env::storage_usage() - initial_storage_usage);
            self.accounts.insert(&sender_id, &(initial_user_balance - difference * STORAGE_PRICE_PER_BYTE));
        } else {
            // freed up storage, add to balance
            let difference : u128 = u128::from(initial_storage_usage - env::storage_usage());
            self.accounts.insert(&sender_id, &(initial_user_balance + difference * STORAGE_PRICE_PER_BYTE));
        }

        unspent
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[cfg(test)]
mod mock_token_basic_tests {
    use super::*;
    use std::convert::TryInto;

    use near_sdk::{ MockedBlockchain };
    use near_sdk::{ testing_env, VMContext };
    use crate::storage_manager::StorageManager;

    fn alice() -> AccountId {
        "alice.near".to_string()
    }

    fn bob() -> AccountId {
        "bob.near".to_string()
    }

    fn carol() -> AccountId {
        "carol.near".to_string()
    }

    fn token() -> AccountId {
        "token.near".to_string()
    }

    fn target() -> AccountId {
        "target.near".to_string()
    }

    fn gov() -> AccountId {
        "gov.near".to_string()
    }

    fn to_valid(account: AccountId) -> ValidAccountId {
        account.try_into().expect("invalid account")
    }

    fn config() -> oracle_config::OracleConfig {
        oracle_config::OracleConfig {
            gov: gov(),
            final_arbitrator: alice(),
            bond_token: token(),
            stake_token: token(),
            validity_bond: U128(100),
            max_outcomes: 8,
            default_challenge_window_duration: 1000,
            min_initial_challenge_window_duration: 1000,
            final_arbitrator_invoke_amount: U128(250),
            resolution_fee_percentage: 0,
        }
    }

    fn get_context(predecessor_account_id: AccountId) -> VMContext {
        VMContext {
            current_account_id: token(),
            signer_account_id: bob(),
            signer_account_pk: vec![0, 1, 2],
            predecessor_account_id,
            input: vec![],
            block_index: 0,
            block_timestamp: 0,
            account_balance: 1000 * 10u128.pow(24),
            account_locked_balance: 0,
            storage_usage: 10u64.pow(6),
            attached_deposit: 1000 * 10u128.pow(24),
            prepaid_gas: 10u64.pow(18),
            random_seed: vec![0, 1, 2],
            is_view: false,
            output_data_receivers: vec![],
            epoch_height: 0,
        }
    }

    #[test]
    #[should_panic(expected = "attempt to subtract with overflow")]
    fn transfer_storage_no_funds() {
        testing_env!(get_context(token()));
        let whitelist = Some(vec![to_valid(bob()), to_valid(carol())]);
        let mut contract = Contract::new(whitelist, config());

        contract.dr_new(bob(), 100, NewDataRequestArgs{
            sources: Vec::new(),
            outcomes: Some(vec!["a".to_string(), "b".to_string()].to_vec()),
            challenge_period: U64(1500),
            settlement_time: U64(0),
            target_contract: target(),
            description: Some("a".to_string()),
        });

        let msg = serde_json::json!({
            "StakeDataRequest": {
                "id": "0",
                "outcome": data_request::Outcome::Answer("a".to_string())
            }
        });
        contract.ft_on_transfer(alice(), U128(100), msg.to_string());
    }

    #[test]
    fn transfer_storage_funds() {
        testing_env!(get_context(token()));
        let whitelist = Some(vec![to_valid(bob()), to_valid(carol())]);
        let mut contract = Contract::new(whitelist, config());

        contract.dr_new(bob(), 100, NewDataRequestArgs{
            sources: Vec::new(),
            outcomes: Some(vec!["a".to_string(), "b".to_string()].to_vec()),
            challenge_period: U64(1500),
            settlement_time: U64(0),
            target_contract: target(),
            description: Some("a".to_string()),
        });

        let storage_start = 10u128.pow(24);

        let mut c : VMContext = get_context(alice());
        c.attached_deposit = storage_start;
        testing_env!(c);
        contract.storage_deposit(Some(to_valid(alice())));

        testing_env!(get_context(token()));
        let msg = serde_json::json!({
            "StakeDataRequest": {
                "id": "0",
                "outcome": data_request::Outcome::Answer("a".to_string())
            }
        });
        contract.ft_on_transfer(alice(), U128(100), msg.to_string());

        let b = contract.accounts.get(&alice());
        assert!(b.unwrap() < storage_start);
    }
}
