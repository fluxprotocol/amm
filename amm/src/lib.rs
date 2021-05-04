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
pub mod collateral_whitelist; // pub for integration tests 
pub mod math; // pub for integration tests

use crate::fungible_token_receiver::{BuyArgs, AddLiquidityArgs};
use crate::helper::*;
use crate::market::Market;
use crate::pool::Pool;
use crate::collateral_whitelist::Whitelist;

const GAS_BASE_COMPUTE: Gas = 5_000_000_000_000;
const STORAGE_PRICE_PER_BYTE: Balance = 100_000_000_000_000_000_000;

#[ext_contract]
pub trait CollateralToken {
    fn ft_transfer(&mut self, receiver_id: AccountId, amount: U128, memo: Option<String>);
}

#[near_bindgen]
#[derive(BorshDeserialize, BorshSerialize, PanicOnDefault)]
pub struct AMMContract {
    gov: AccountId, // The gov of all markets
    markets: Vector<Market>, // Vector containing all markets where the index represents the market id
    collateral_whitelist: Whitelist, // Map a token's account id to number of decimals it's denominated in
    paused: bool // If true certain functions are no longer callable, settable by `gov`
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
    ) -> Self {
        assert!(!env::state_exists(), "ERR_CONTRACT_IS_INITIALIZED");
        let collateral_whitelist: Whitelist = Whitelist::new(tokens);

        logger::log_whitelist(&collateral_whitelist);

        Self {
            gov: gov.into(),
            markets: Vector::new(b"m".to_vec()),
            collateral_whitelist: collateral_whitelist, 
            paused: false
        }
    }
}

/*** Private methods ***/
impl AMMContract {
    /**
     * @notice refunds any cleared up or overpaid storage to original sender, also checks if the sender added enough deposit to cover storage
     * @param initial_storage is the storage at the beginning of the function call
     * @param sender_id is the `AccountId` that's to be refunded
     */
    fn refund_storage(
        &self, 
        initial_storage: StorageUsage, 
        sender_id: AccountId
    ) {
        let current_storage = env::storage_usage();
        let attached_deposit = env::attached_deposit();
        let refund_amount = if current_storage > initial_storage {
            let required_deposit =
                Balance::from(current_storage - initial_storage) * STORAGE_PRICE_PER_BYTE;
            assert!(
                required_deposit <= attached_deposit,
                "The required attached deposit is {}, but the given attached deposit is is {}",
                required_deposit,
                attached_deposit,
            );
            attached_deposit - required_deposit
        } else {
            attached_deposit
                + Balance::from(initial_storage - current_storage) * STORAGE_PRICE_PER_BYTE
        };
        if refund_amount > 0 {
            Promise::new(sender_id).transfer(refund_amount);
        }
    }
}