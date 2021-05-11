use crate::test_utils::*;
use near_sdk::json_types::{U64, U128};
use near_sdk::serde_json::json;
use near_sdk_sim::{to_yocto, view};

#[test]
fn pool_initial_state_test() {
    let init_res = init("carol".to_string());
    let oracle = init_res.oracle_contract;

    let res = create_market(&init_res.alice, &init_res.amm_contract, 2, Some(U128(0)));
    println!("create market result: {:?}", res);
    
    let dr_exists: bool = view!(oracle.dr_exists(U64(0))).unwrap_json();
    println!("the dr exists: {}", dr_exists);
    
//     let seed_amount = to_token_denom(100);
//     let half = to_token_denom(5) / 10;
//     let weights = Some(vec![U128(half), U128(half)]);

//     let add_liquidity_args = json!({
//         "function": "add_liquidity",
//         "args": {
//             "market_id": U64(0),
//             "weight_indication": weights
//         }
//     }).to_string();
//     ft_transfer_call(&alice, seed_amount, add_liquidity_args);

//     let seeder_balance: u128 = ft_balance_of(&alice, &alice.account_id()).into();
//     assert_eq!(seeder_balance, init_balance() - seed_amount);
//     let amm_collateral_balance: u128 = ft_balance_of(&alice, &"amm".to_string()).into();
//     assert_eq!(amm_collateral_balance, seed_amount);

//     let pool_balances: Vec<U128> = view!(amm.get_pool_balances(U64(0))).unwrap_json();

//     assert_eq!(pool_balances[0], pool_balances[1]);
//     assert_eq!(pool_balances[0], U128(seed_amount));
//     assert_eq!(pool_balances[1], U128(seed_amount));
}
