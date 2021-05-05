use near_sdk::AccountId;
use near_sdk::env;
use near_sdk::PromiseResult;
// TODO: should add storage refund to this

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
