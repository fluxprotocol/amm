use crate::*;
use crate::market::OutcomeTag;
use near_sdk::PromiseResult;
const STORAGE_PRICE_PER_BYTE: Balance = 100_000_000_000_000_000_000;

/**
 * @panics if the sender is not the collateral token
 */
pub fn assert_collateral_token(collateral_token: &AccountId) {
    assert_eq!(&env::predecessor_account_id(), collateral_token, "ERR_INVALID_COLLATERAL");
}

/**
 * @panics if the caller is not the contract itself (for promises)
 */
pub fn assert_self() {
    assert_eq!(
        env::predecessor_account_id(),
        env::current_account_id(),
        "Method is private"
    );
}

/**
 * @returns a converted timestamp from nanoseconds to miliseconds
 */
pub fn ns_to_ms(ns_timestamp: u64) -> u64 {
    ns_timestamp / 1_000_000
}

/**
 * @returns a converted timestamp from miliseconds to nanoseconds
 */
pub fn ms_to_ns(ms_timestamp: u64) -> u64 {
    ms_timestamp * 1_000_000
}

pub fn is_promise_success() -> bool {
    assert_eq!(
        env::promise_results_count(),
        1,
        "Contract expected a result on the callback"
    );
    matches!(env::promise_result(0), PromiseResult::Successful(_))
}

pub fn assert_prev_promise_successful() {
    assert_eq!(is_promise_success(), true, "previous promise failed");
}

pub fn clamp_u128(value: u128, min: u128, max: u128) -> u128 {
    if value > max {
        max
    } else if value < min {
        min
    } else {
        value
    }
}

pub fn flatten_outcome_tags(outcome_tags: &Vec<OutcomeTag>) -> Vec<String> {
    outcome_tags.iter().map(|tag| {
        match tag {
            OutcomeTag::String(value) => value.to_string(),
            OutcomeTag::Number(num) => num.value.0.to_string(),
        }
    }).collect()
}

/** 
 * @notice refunds any cleared up or overpaid storage to original sender, also checks if the sender added enough deposit to cover storage
 * @param initial_storage is the storage at the beginning of the function call
 * @param sender_id is the `AccountId` that's to be refunded
 */
pub fn refund_storage(
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
