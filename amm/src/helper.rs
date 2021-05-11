use crate::*;
use near_sdk::PromiseResult;
const STORAGE_PRICE_PER_BYTE: Balance = 100_000_000_000_000_000_000;

/**
 * @panics if the sender is not the collateral token
 */
pub(crate) fn assert_collateral_token(collateral_token: &AccountId) {
    assert_eq!(&env::predecessor_account_id(), collateral_token, "ERR_INVALID_COLLATERAL");
}

/**
 * @panics if the caller is not the contract itself (for promises)
 */
pub(crate) fn assert_self() {
    assert_eq!(
        env::predecessor_account_id(),
        env::current_account_id(),
        "Method is private"
    );
}

/**
 * @returns a converted timestamp from nanoseconds to miliseconds
 */
pub (crate) fn ns_to_ms(ns_timestamp: u64) -> u64 {
    ns_timestamp / 1_000_000
}

/**
 * @returns a converted timestamp from miliseconds to nanoseconds
 */
pub (crate) fn ms_to_ns(ms_timestamp: u64) -> u64 {
    ms_timestamp * 1_000_000
}
pub(crate) fn is_promise_success() -> bool {
    assert_eq!(
        env::promise_results_count(),
        1,
        "Contract expected a result on the callback"
    );
    match env::promise_result(0) {
        PromiseResult::Successful(_) => true,
        _ => false,
    }
}

pub(crate) fn assert_prev_promise_successful() {
    assert_eq!(is_promise_success(), true, "previous promise failed");
}

/** 
 * @notice refunds any cleared up or overpaid storage to original sender, also checks if the sender added enough deposit to cover storage
 * @param initial_storage is the storage at the beginning of the function call
 * @param sender_id is the `AccountId` that's to be refunded
 */
pub (crate) fn refund_storage(
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