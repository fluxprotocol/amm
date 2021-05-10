use near_sdk::AccountId;
use crate::pool::Pool;
use near_sdk::Balance;

// TODO: remove, completely redunant function

/**
 * @notice takes pool params and creates and returns a new pool
 */
pub fn new_pool(
    pool_id: u64,
    outcomes: u16,
    collateral_token_id: AccountId,
    collateral_decimals: u32,
    swap_fee: Balance,
) -> Pool {
    Pool::new(
        pool_id,
        collateral_token_id,
        collateral_decimals,
        outcomes,
        swap_fee
    )
}
