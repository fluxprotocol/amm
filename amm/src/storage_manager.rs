use super::*;
use near_sdk::{Promise};
use near_sdk::json_types::{ValidAccountId, U128};
use near_sdk::serde::Serialize;

/// Price per 1 byte of storage from mainnet config after `0.18` release and protocol version `42`.
/// It's 10 times lower than the genesis price.
pub const STORAGE_PRICE_PER_BYTE: Balance = 10_000_000_000_000_000_000;

pub const STORAGE_MINIMUM_BALANCE: Balance = 10_000_000_000_000_000_000_000;

#[derive(Serialize)]
#[serde(crate = "near_sdk::serde")]
pub struct AccountStorageBalance {
    total: U128,
    available: U128,
}

pub trait StorageManager {
    fn storage_deposit(&mut self, account_id: Option<ValidAccountId>) -> AccountStorageBalance;

    fn storage_withdraw(&mut self, amount: U128) -> AccountStorageBalance;

    fn storage_minimum_balance(&self) -> U128;

    fn storage_balance_of(&self, account_id: ValidAccountId) -> AccountStorageBalance;
}

fn assert_one_yocto() {
    assert_eq!(
        env::attached_deposit(),
        1,
        "Requires attached deposit of exactly 1 yoctoNEAR"
    )
}

#[near_bindgen]
impl StorageManager for AMMContract {

    #[payable]
    fn storage_deposit(&mut self, account_id: Option<ValidAccountId>) -> AccountStorageBalance {
        let amount = env::attached_deposit();
        let account_id = account_id
            .map(|a| a.into())
            .unwrap_or_else(|| env::predecessor_account_id());

        let mut balance = self.accounts.get(&account_id).unwrap_or(0);
        balance += amount;
        self.accounts.insert(&account_id, &balance);
        AccountStorageBalance {
            total: balance.into(),
            available: balance.into(),
        }
    }

    #[payable]
    fn storage_withdraw(&mut self, amount: U128) -> AccountStorageBalance {
        assert_one_yocto();
        let amount: Balance = amount.into();
        let account_id = env::predecessor_account_id();

        let mut balance = self.accounts.get(&account_id).unwrap_or(0);
        balance -= amount;
        self.accounts.insert(&account_id, &balance);
        Promise::new(account_id).transfer(amount + 1);
        AccountStorageBalance {
            total: balance.into(),
            available: balance.into(),
        }
    }

    fn storage_minimum_balance(&self) -> U128 {
        U128(STORAGE_MINIMUM_BALANCE)
    }

    fn storage_balance_of(&self, account_id: ValidAccountId) -> AccountStorageBalance {
        if let Some(balance) = self.accounts.get(account_id.as_ref()) {
            AccountStorageBalance {
                total: self.storage_minimum_balance(),
                available: if balance > 0 {
                    0.into()
                } else {
                    self.storage_minimum_balance()
                },
            }
        } else {
            AccountStorageBalance {
                total: 0.into(),
                available: 0.into(),
            }
        }
    }
}

impl AMMContract {
    pub fn use_storage(&mut self, sender_id: &AccountId, initial_storage_usage: u64, initial_user_balance: u128) {
        if env::storage_usage() >= initial_storage_usage {
            // used more storage, deduct from balance
            let difference : u128 = u128::from(env::storage_usage() - initial_storage_usage);
            self.accounts.insert(sender_id, &(initial_user_balance - difference * STORAGE_PRICE_PER_BYTE));
        } else {
            // freed up storage, add to balance
            let difference : u128 = u128::from(initial_storage_usage - env::storage_usage());
            self.accounts.insert(sender_id, &(initial_user_balance + difference * STORAGE_PRICE_PER_BYTE));
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[cfg(test)]
mod mock_token_basic_tests {
    use super::*;
    use std::convert::TryInto;
    use near_sdk::{ MockedBlockchain };
    use near_sdk::{ testing_env, VMContext };
    use collateral_whitelist::Token;

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

    fn oracle() -> AccountId {
        "oracle.near".to_string()
    }

    fn _target() -> AccountId {
        "target.near".to_string()
    }

    fn gov() -> AccountId {
        "gov.near".to_string()
    }

    fn to_valid(account: AccountId) -> ValidAccountId {
        account.try_into().expect("invalid account")
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
    fn storage_manager_deposit() {
        testing_env!(get_context(token()));

        let mut contract = AMMContract::init(
            to_valid(bob()),
            vec![collateral_whitelist::Token{account_id: token(), decimals: 24}],
            oracle().try_into().unwrap()
        );

        let balance = contract.accounts.get(&alice()).unwrap_or(0);
        assert_eq!(balance, 0);

        let amount = 10u128.pow(24);

        //deposit
        let mut c : VMContext = get_context(alice());
        c.attached_deposit = amount;
        testing_env!(c);
        contract.storage_deposit(Some(to_valid(alice())));

        let balance = contract.accounts.get(&alice()).unwrap_or(0);
        assert_eq!(balance, amount);

        //deposit again
        let mut c : VMContext = get_context(alice());
        c.attached_deposit = amount;
        testing_env!(c);
        contract.storage_deposit(Some(to_valid(alice())));

        let balance = contract.accounts.get(&alice()).unwrap_or(0);
        assert_eq!(balance, amount*2);
    }

    #[test]
    fn storage_manager_withdraw() {
        testing_env!(get_context(token()));

        let mut contract = AMMContract::init(
            to_valid(bob()),
            vec![collateral_whitelist::Token{account_id: token(), decimals: 24}],
            oracle().try_into().unwrap()
        );

        let balance = contract.accounts.get(&alice()).unwrap_or(0);
        assert_eq!(balance, 0);

        let amount = 10u128.pow(24);

        //deposit
        let mut c : VMContext = get_context(alice());
        c.attached_deposit = amount;
        testing_env!(c);
        contract.storage_deposit(Some(to_valid(alice())));

        // withdraw
        let mut c : VMContext = get_context(alice());
        c.attached_deposit = 1;
        testing_env!(c);

        contract.storage_withdraw(U128(amount/2));
        let balance = contract.accounts.get(&alice()).unwrap_or(0);
        assert_eq!(balance, amount/2);
    }

    #[test]
    #[should_panic(expected = "attempt to subtract with overflow")]
    fn storage_manager_withdraw_too_much() {
        testing_env!(get_context(token()));

        let mut contract = AMMContract::init(
            to_valid(bob()),
            vec![collateral_whitelist::Token{account_id: token(), decimals: 24}],
            oracle().try_into().unwrap()
        );

        let balance = contract.accounts.get(&alice()).unwrap_or(0);
        assert_eq!(balance, 0);

        let amount = 10u128.pow(24);

        //deposit
        let mut c : VMContext = get_context(alice());
        c.attached_deposit = amount;
        testing_env!(c);
        contract.storage_deposit(Some(to_valid(alice())));

        // withdraw
        let mut c : VMContext = get_context(alice());
        c.attached_deposit = 1;
        testing_env!(c);

        contract.storage_withdraw(U128(amount*2));
    }
}
