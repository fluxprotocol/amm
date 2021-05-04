use crate::test_utils::*;
use near_sdk::json_types::{U64, U128};
use near_sdk::serde_json::json;
use near_sdk_sim::{to_yocto, call, view, STORAGE_AMOUNT};

#[test]
fn add_liquidity_even_liq_test() {
    let (master_account, amm, token, alice, bob, carol) = init("carol".to_string());
    let market_id: U64 = create_market(&alice, &amm, 2, Some(U128(0)));

    assert_eq!(market_id, U64(0));

    let seed_amount = to_token_denom(10);
    let half = U128(to_token_denom(5) / 10);
    let weights = vec![half, half];

    ft_transfer_call(&alice, seed_amount, compose_add_liquidity_args(market_id, Some(weights)));

    let pool_token_balance: U128 = view!(amm.get_pool_token_balance(market_id, &alice.account_id())).unwrap_json();
    assert_eq!(pool_token_balance, U128(seed_amount));
    let seeder_balance = ft_balance_of(&alice, &alice.account_id().to_string());
    assert_eq!(seeder_balance, U128(to_yocto("1000") - seed_amount));
    let amm_collateral_balance = ft_balance_of(&alice, &"amm".to_string());
    assert_eq!(amm_collateral_balance, U128(seed_amount));

    ft_transfer_call(&bob, seed_amount, compose_add_liquidity_args(market_id, None));

    let pool_token_balance_after_join: U128 = view!(amm.get_pool_token_balance(market_id, &bob.account_id())).unwrap_json();
    assert_eq!(pool_token_balance_after_join, U128(to_token_denom(10)));

    let joiner_balance = ft_balance_of(&alice, &bob.account_id().to_string());
    assert_eq!(joiner_balance, U128(to_yocto("1000") - seed_amount));
    let amm_collateral_balance = ft_balance_of(&alice, &"amm".to_string());
    assert_eq!(amm_collateral_balance, U128(seed_amount * 2));
}

#[test]
fn add_liquidity_uneven_liq_test() {
    let (master_account, amm, token, alice, bob, carol) = init("carol".to_string());
    let (master_account, amm, token, alice, bob, carol) = init("carol".to_string());
    let transfer_amount = to_token_denom(100);

    let market_id: U64 = create_market(&alice, &amm, 3, Some(U128(0)));

    assert_eq!(market_id, U64(0));

    let target_price_a = U128(to_token_denom(60) / 100);
    let target_price_b_c = U128(to_token_denom(20) / 100);

    let weights = calc_weights_from_price(vec![target_price_a, target_price_b_c,target_price_b_c]);
    let seed_amount = to_token_denom(100);

    ft_transfer_call(&alice, seed_amount, compose_add_liquidity_args(market_id, Some(weights)));

    let price_0: U128 = view!(amm.get_spot_price_sans_fee(market_id, 0)).unwrap_json();
    let price_1: U128 = view!(amm.get_spot_price_sans_fee(market_id, 1)).unwrap_json();
    let price_2: U128 = view!(amm.get_spot_price_sans_fee(market_id, 2)).unwrap_json();

    assert_eq!(price_0, target_price_a);
    assert_eq!(price_1, target_price_b_c);
    assert_eq!(price_2, target_price_b_c);

    let pool_balances_after_seed: Vec<U128> = view!(amm.get_pool_balances(market_id)).unwrap_json();

    let outcome_balance_0: U128 = view!(amm.get_share_balance(&alice.account_id(), market_id, 0)).unwrap_json();
    let outcome_balance_1: U128 = view!(amm.get_share_balance(&alice.account_id(), market_id, 1)).unwrap_json();
    let outcome_balance_2: U128 = view!(amm.get_share_balance(&alice.account_id(), market_id, 2)).unwrap_json();

    assert_eq!(u128::from(outcome_balance_0), seed_amount - u128::from(pool_balances_after_seed[0]));
    assert_eq!(outcome_balance_1, U128(0));
    assert_eq!(outcome_balance_2, U128(0));


    let creator_pool_token_balance: U128 = view!(amm.get_pool_token_balance(market_id, &alice.account_id())).unwrap_json();

    ft_transfer_call(&bob, seed_amount, compose_add_liquidity_args(market_id, None));
    

    let joiner_share_balance_a: U128 = view!(amm.get_share_balance(&bob.account_id(), market_id, 0)).unwrap_json();

    assert_eq!(u128::from(joiner_share_balance_a), seed_amount - u128::from(pool_balances_after_seed[0]));

    let joiner_pool_token_balance: U128 = view!(amm.get_pool_token_balance(market_id, &bob.account_id())).unwrap_json();
    assert_eq!(creator_pool_token_balance, joiner_pool_token_balance);
}

#[test]
fn multiple_pool_exits_test() {
    let (master_account, amm, token, alice, bob, carol) = init("carol".to_string());
    let market_id: U64 = create_market(&bob, &amm, 2, Some(U128(0)));
    let transfer_amount = to_token_denom(100);
    assert_eq!(market_id, U64(0));

    let seed_amount = to_token_denom(100);
    let join_amount0 = to_token_denom(500);
    let join_amount1 = to_token_denom(300);

    let exit_amount0 = to_token_denom(100);
    let exit_amount1 = to_token_denom(200);
    let exit_amount2 = to_token_denom(50);
    let exit_amount3 = to_token_denom(33);

    let buy_amount = to_token_denom(10);

    let half = U128(to_token_denom(5) / 10);
    let weights = Some(vec![half, half]);

    ft_transfer_call(&bob, seed_amount, compose_add_liquidity_args(market_id, weights));

    let pool_token_balance: U128 = view!(amm.get_pool_token_balance(market_id, &bob.account_id())).unwrap_json();
    assert_eq!(pool_token_balance, U128(seed_amount));

    ft_transfer_call(&alice, join_amount0, compose_add_liquidity_args(market_id, None));

    let buy_args = json!({
        "function": "buy",
        "args": {
            "market_id": market_id,
            "outcome_target": 0,
            "min_shares_out": U128(to_token_denom(15) / 10)
        }
    }).to_string();
    let buy_args2 = json!({
        "function": "buy",
        "args": {
            "market_id": market_id,
            "outcome_target": 1,
            "min_shares_out": U128(to_token_denom(15) / 10)
        }
    }).to_string();

    let buy_res = ft_transfer_call(&alice, buy_amount, buy_args);
    let buy_res = ft_transfer_call(&alice, buy_amount, buy_args2);

    ft_transfer_call(&alice, join_amount1, compose_add_liquidity_args(market_id, None));
    let alice_pool_token_balance_pre_exit: U128 = view!(amm.get_pool_token_balance(market_id, &alice.account_id())).unwrap_json();


    let alice_exit_res = call!(
        alice,
        amm.exit_pool(market_id, U128(exit_amount0)),
        deposit = STORAGE_AMOUNT
    );

    let alice_exit_res1 = call!(
        alice,
        amm.exit_pool(market_id, U128(exit_amount1)),
        deposit = STORAGE_AMOUNT
    );

    let alice_exit_res2 = call!(
        alice,
        amm.exit_pool(market_id, U128(exit_amount2)),
        deposit = STORAGE_AMOUNT
    );

    let alice_exit_res3 = call!(
        alice,
        amm.exit_pool(market_id, U128(exit_amount3)),
        deposit = STORAGE_AMOUNT
    );

    // assert pool balances
    let alice_pool_token_balance_post_exit: U128 = view!(amm.get_pool_token_balance(market_id, &alice.account_id())).unwrap_json();
    assert_eq!(alice_pool_token_balance_post_exit, U128(u128::from(alice_pool_token_balance_pre_exit) - exit_amount0 - exit_amount1 -exit_amount2 - exit_amount3));
}

#[test]
fn join_zero_liq_test() {
    let (master_account, amm, token, alice, bob, carol) = init("carol".to_string());
    let market_id: U64 = create_market(&bob, &amm, 2, Some(U128(0)));
    let transfer_amount = to_token_denom(100);
    assert_eq!(market_id, U64(0));

    let seed_amount = to_token_denom(100);
    let join_amount0 = to_token_denom(500);

    let half = U128(to_token_denom(5) / 10);
    let weights = Some(vec![half, half]);

    ft_transfer_call(&alice, seed_amount, compose_add_liquidity_args(market_id, weights));

    let pool_token_balance: U128 = view!(amm.get_pool_token_balance(market_id, &alice.account_id())).unwrap_json();
    assert_eq!(pool_token_balance, U128(seed_amount));

    let seed_exit_res = call!(
        alice,
        amm.exit_pool(market_id, U128(seed_amount)),
        deposit = STORAGE_AMOUNT
    );

    let join_res = ft_transfer_call(&alice, join_amount0, compose_add_liquidity_args(market_id, None));
}

#[test]
fn add_liquidity_redeem() {
    let (master_account, amm, token, alice, bob, carol) = init("carol".to_string());

    // Fund Bob
    let transfer_amount = to_token_denom(100);
    transfer_unsafe(&alice, &bob.account_id(), transfer_amount);

    // Create / validate market
    let market_id: U64 = create_market(&bob, &amm, 2, Some(U128(0)));
    assert_eq!(market_id, U64(0));

    // Seed params
    let seed_amount = to_token_denom(10);
    let half = U128(to_token_denom(5) / 10);
    let weights = vec![half, half];

    ft_transfer_call(&bob, seed_amount, compose_add_liquidity_args(market_id, Some(weights)));

    // Exit pool
    let bob_exit_res = call!(
        bob,
        amm.exit_pool(market_id, U128(seed_amount)),
        deposit = STORAGE_AMOUNT
    );
    assert!(bob_exit_res.is_ok());

    // Redeem liquidity
    let redeem_call = call!(
        bob,
        amm.burn_outcome_tokens_redeem_collateral(market_id, U128(seed_amount)),
        deposit = STORAGE_AMOUNT
    );
    assert!(redeem_call.is_ok());

    // Assert pool token balance
    let pool_token_balance: U128 = view!(amm.get_pool_token_balance(market_id, &bob.account_id())).unwrap_json();
    assert_eq!(pool_token_balance, U128(0));
 
    // Assert collateral balance
    let collateral_balance = ft_balance_of(&bob, &bob.account_id());
    assert_eq!(collateral_balance, U128(to_yocto("1000") + transfer_amount));
    
    // Assert if shares are burned
    let outcome_balance_0: U128 = view!(amm.get_share_balance(&bob.account_id(), market_id, 0)).unwrap_json();
    let outcome_balance_1: U128 = view!(amm.get_share_balance(&bob.account_id(), market_id, 1)).unwrap_json();
    assert_eq!(outcome_balance_0, U128(0));
    assert_eq!(outcome_balance_1, U128(0));
}

#[test]
fn liquidity_exit_scene() {
    let (_master_account, amm, _token, alice, bob, _carol) = init("carol".to_string());
    let market_id: U64 = create_market(&bob, &amm, 2, Some(swap_fee()));

    assert_eq!(market_id, U64(0));

    let seed_amount = 20000000000000000000;

    let weights = Some(vec![U128(70000000), U128(30000000)]);

    ft_transfer_call(&alice, seed_amount, compose_add_liquidity_args(market_id, weights));

    let pool_token_balance: U128 = view!(amm.get_pool_token_balance(market_id, &alice.account_id())).unwrap_json();
    assert_eq!(pool_token_balance, U128(seed_amount));

    let buy_args = json!({
        "function": "buy",
        "args": {
            "market_id": market_id,
            "outcome_target": 0,
            "min_shares_out": U128(0)
        }
    }).to_string();

    
    let buy_res = ft_transfer_call(&alice, 100000000000000000, buy_args.to_string());
    let buy_res = ft_transfer_call(&alice, 1000000000000000000000000, buy_args);
    
    let add_more_liquidity_args = json!({
        "function": "add_liquidity",
        "args": {
            "market_id": market_id,
        }
    }).to_string();
    ft_transfer_call(&alice, 1000000000000000000, add_more_liquidity_args.to_string());
    ft_transfer_call(&alice, 1000000000000000000000000, add_more_liquidity_args);
    let pool_token_balance: U128 = view!(amm.get_pool_token_balance(market_id, &alice.account_id())).unwrap_json();

    let seed_exit_res = call!(
        alice,
        amm.exit_pool(market_id, pool_token_balance),
        deposit = STORAGE_AMOUNT
    );
}


#[test]
fn liquidity_exit_after_swap() {
    let (_master_account, amm, _token, alice, bob, _carol) = init("carol".to_string());
    let market_id: U64 = create_market(&bob, &amm, 2, Some(swap_fee()));

    assert_eq!(market_id, U64(0));

    let seed_amount = to_yocto("24");
    let buy_amount = to_yocto("5");

    let weights = Some(vec![U128(50), U128(50)]);

    ft_transfer_call(&alice, seed_amount, compose_add_liquidity_args(market_id, weights));

    let pool_token_balance: U128 = view!(amm.get_pool_token_balance(market_id, &alice.account_id())).unwrap_json();
    assert_eq!(pool_token_balance, U128(seed_amount));

    let buy_args = json!({
        "function": "buy",
        "args": {
            "market_id": market_id,
            "outcome_target": 0,
            "min_shares_out": U128(0)
        }
    }).to_string();

    
    let buy_res = ft_transfer_call(&alice, buy_amount, buy_args.to_string());
    

    let seed_exit_res = call!(
        alice,
        amm.exit_pool(market_id, pool_token_balance),
        deposit = STORAGE_AMOUNT
    );

    assert!(seed_exit_res.is_ok());
}