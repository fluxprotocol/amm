use crate::test_utils::*;
use near_sdk::json_types::{U64, U128};
use near_sdk::serde_json::json;
use near_sdk_sim::{to_yocto, view};

#[test]
fn pool_initial_state_test() {
    let (_master_account, amm, token, alice, _bob, _carol) = init("carol".to_string());

    let market_id = create_market(&alice, &amm, 2, Some(U128(0)));
    assert_eq!(market_id, U64(0));
    
    let seed_amount = to_token_denom(100);
    let half = to_token_denom(5) / 10;
    let weights = Some(vec![U128(half), U128(half)]);
    
    ft_transfer_call(&alice, seed_amount, compose_add_liquidity_args(market_id, weights));

    let seeder_balance: u128 = ft_balance_of(&alice, &alice.account_id()).into();
    assert_eq!(seeder_balance, init_balance() - seed_amount);
    let amm_collateral_balance: u128 = ft_balance_of(&alice, &"amm".to_string()).into();
    assert_eq!(amm_collateral_balance, seed_amount);

    let pool_balances: Vec<U128> = view!(amm.get_pool_balances(market_id)).unwrap_json();

    assert_eq!(pool_balances[0], pool_balances[1]);
    assert_eq!(pool_balances[0], U128(seed_amount));
    assert_eq!(pool_balances[1], U128(seed_amount));
}
