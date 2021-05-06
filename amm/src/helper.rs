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

pub (crate) fn alice() -> AccountId {
    "alice.near".to_string()
}

pub (crate) fn bob() -> AccountId {
    "bob.near".to_string()
}

pub (crate) fn token() -> AccountId {
    "token".to_string()
}

pub (crate) fn empty_string() -> String {
    "".to_string()
}

pub (crate) fn empty_string_vec(len: u16) -> Vec<String> {
    let mut tags: Vec<String> = vec![];
    for i in 0..len {
        tags.push(empty_string());
    }
    tags
}
