use near_sdk::AccountId;
use near_sdk::env;
// TODO: should add storage refund to this

/**
 * @panics if the sender is not the collateral token
 */
pub(crate) fn assert_collateral_token(collateral_token: &AccountId) {
    assert_eq!(&env::predecessor_account_id(), collateral_token, "ERR_INVALID_COLLATERAL");
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
