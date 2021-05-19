#![allow(clippy::too_many_arguments)]
use near_sdk::borsh::{self, BorshDeserialize, BorshSerialize};
use near_sdk::json_types::{U128, U64, ValidAccountId};
use near_sdk::collections::{Vector, UnorderedMap, LookupMap};
use near_sdk::{
    PromiseOrValue,
    Balance,
    StorageUsage,
    Gas,
    ext_contract,
    near_bindgen,
    Promise,
    PanicOnDefault,
    AccountId,
    env
};

near_sdk::setup_alloc!();

mod types;
mod helper;
mod pool;
mod logger;
mod constants;
mod outcome_token;
mod pool_factory;
mod resolution_escrow;
mod market;
mod gov; 
mod fungible_token_receiver;
mod oracle;
mod market_creation;
mod fungible_token;
mod storage_manager;

pub mod collateral_whitelist; // pub for integration tests 
pub mod math; // pub for integration tests

use crate::types::*;
use crate::fungible_token_receiver::*;
use crate::helper::*;
use crate::market::Market;
use crate::pool::Pool;
use crate::collateral_whitelist::Whitelist;
use crate::storage_manager::AccountStorageBalance;

const GAS_BASE_COMPUTE: Gas = 5_000_000_000_000;

#[ext_contract]
pub trait CollateralToken {
    fn ft_transfer(&mut self, receiver_id: AccountId, amount: U128, memo: Option<String>);
}

#[near_bindgen]
#[derive(BorshDeserialize, BorshSerialize, PanicOnDefault)]
pub struct AMMContract {
    oracle: AccountId, // The Flux Oracle address
    gov: AccountId, // The gov of all markets
    markets: Vector<Market>, // Vector containing all markets where the index represents the market id
    collateral_whitelist: Whitelist, // Map a token's account id to number of decimals it's denominated in
    paused: bool, // If true certain functions are no longer callable, settable by `gov`
    accounts: LookupMap<AccountId, AccountStorageBalance> // Storage map
}

#[near_bindgen]
impl AMMContract {
    /**
     * @notice Initialize the contract by setting global contract attributes
     * @param gov is the `AccountId` of the account with governance privilages
     * @param collateral_whitelist is a list of tokens that can be used ås collateral
     */
    #[init]
    pub fn init(
        gov: ValidAccountId, 
        tokens: Vec<collateral_whitelist::Token>,
        oracle: ValidAccountId,
    ) -> Self {
        assert!(!env::state_exists(), "ERR_CONTRACT_IS_INITIALIZED");
        let collateral_whitelist: Whitelist = Whitelist::new(tokens);

        logger::log_whitelist(&collateral_whitelist);

        Self {
            oracle: oracle.into(),
            gov: gov.into(),
            markets: Vector::new(b"m".to_vec()),
            collateral_whitelist: collateral_whitelist, 
            paused: false,
            accounts: LookupMap::new(b"a".to_vec()),
        }
    }
}

