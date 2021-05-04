use crate::test_utils::*;
use near_sdk::json_types::{U64, U128};
use near_sdk::serde_json::json;
use near_sdk_sim::{to_yocto, call, view, STORAGE_AMOUNT};

#[test]
fn swap_calc_buy_amount_test() {
    let (_master_account, amm, token, alice, _bob, _carol) = init("carol".to_string());
    let seed_amount = to_token_denom(10);
    let half = to_token_denom(5) / 10;
    let weights = Some(vec![U128(half), U128(half)]);
    let market_id: U64 = create_market(&alice, &amm, 2, Some(U128(0)));

    assert_eq!(market_id, U64(0));
    ft_transfer_call(&alice, seed_amount, compose_add_liquidity_args(market_id, weights));

    let buy_amt: U128 = view!(amm.calc_buy_amount(market_id, U128(to_token_denom(1)), 0)).unwrap_json();
    assert_eq!(u128::from(buy_amt), 1909090909090909090909091);
}

#[test]
fn swap_calc_sell_collateral_out_test() {
    let (_master_account, amm, token, alice, _bob, _carol) = init("carol".to_string());
    let seed_amount = to_token_denom(10);
    let half = to_token_denom(5) / 10;
    let weights = Some(vec![U128(half), U128(half)]);
    let market_id: U64 = create_market(&alice, &amm, 2, Some(U128(0)));

    assert_eq!(market_id, U64(0));

    ft_transfer_call(&alice, seed_amount, compose_add_liquidity_args(market_id, weights));
    let collat_out: U128 = view!(amm.calc_sell_collateral_out(market_id, U128(to_token_denom(1)), 0)).unwrap_json();
    assert_eq!(u128::from(collat_out), 2111111111111111111111111);
}

#[test]
fn swap_basic_buy_test() {
    let (_master_account, amm, token, alice, _bob, _carol) = init("carol".to_string());
    let weight = to_token_denom(1) / 2;
    let seed_amount = to_token_denom(10);
    let buy_amount = to_token_denom(1);
    let invariant = to_token_denom(100);

    let market_id: U64 = create_market(&alice, &amm, 2, Some(U128(0)));
    assert_eq!(market_id, U64(0));

    let weights = Some(vec![U128(weight), U128(weight)]);
 
    ft_transfer_call(&alice, seed_amount, compose_add_liquidity_args(market_id, weights));

    ft_transfer_call(&alice, buy_amount, compose_buy_args(market_id, 0, U128(to_token_denom(15) / 10)));

    let seeder_balance: u128 = ft_balance_of(&alice, &alice.account_id().to_string()).into();
    assert_eq!(seeder_balance, init_balance() - seed_amount - buy_amount);
    let amm_balance: u128 = ft_balance_of(&alice, &"amm".to_string()).into();
    assert_eq!(amm_balance, seed_amount + buy_amount);

    let pool_balances: Vec<U128> = view!(amm.get_pool_balances(market_id)).unwrap_json();

    let expected_target_pool_balance = invariant / 11;
    let expected_other_outcome_pool_balance = seed_amount + buy_amount;
    assert_eq!(pool_balances[0], U128(expected_target_pool_balance));
    assert_eq!(pool_balances[1], U128(expected_other_outcome_pool_balance));

    let expected_target_buyer_balance = seed_amount + buy_amount - expected_target_pool_balance;
    let expected_other_buyer_balance = 0;

    let target_buyer_balance: U128 = view!(amm.get_share_balance(&alice.account_id(), market_id, 0)).unwrap_json();
    let other_buyer_balance: U128 = view!(amm.get_share_balance(&alice.account_id(), market_id, 1)).unwrap_json();

    assert_eq!(expected_target_buyer_balance, u128::from(target_buyer_balance));
    assert_eq!(expected_other_buyer_balance, u128::from(other_buyer_balance));
}

#[test]
fn swap_basic_sell_test() {
    let (_master_account, amm, token, alice, _bob, _carol) = init("carol".to_string());
    let weight = to_token_denom(1) / 2;
    let seed_amount = to_token_denom(10);
    let buy_amount = to_token_denom(1);
    let invariant = to_token_denom(100);

    let market_id: U64 = create_market(&alice, &amm, 2, Some(U128(0)));

    assert_eq!(market_id, U64(0));

    let weights = Some(vec![U128(weight), U128(weight)]);
    ft_transfer_call(&alice, seed_amount, compose_add_liquidity_args(market_id, weights));
    ft_transfer_call(&alice, buy_amount, compose_buy_args(market_id, 0, U128(to_token_denom(15) / 10)));


    let seeder_balance: u128 = ft_balance_of(&alice, &alice.account_id().to_string()).into();
    assert_eq!(seeder_balance, init_balance() - seed_amount - buy_amount);
    let amm_balance: u128 = ft_balance_of(&alice, &"amm".to_string()).into();
    assert_eq!(amm_balance, seed_amount + buy_amount);

    let expected_target_pool_balance = invariant / 11;

    let expected_target_buyer_balance = seed_amount + buy_amount - expected_target_pool_balance;
    let expected_other_buyer_balance = 0;

    let target_buyer_balance: U128 = view!(amm.get_share_balance(&alice.account_id(), market_id, 0)).unwrap_json();
    let other_buyer_balance: U128 = view!(amm.get_share_balance(&alice.account_id(), market_id, 1)).unwrap_json();

    assert_eq!(expected_target_buyer_balance, u128::from(target_buyer_balance));
    assert_eq!(expected_other_buyer_balance, u128::from(other_buyer_balance));
    let seeder_balance: u128 = ft_balance_of(&alice, &alice.account_id().to_string()).into();

    let res = call!(
        alice,
        amm.sell(market_id, U128(to_token_denom(1)), 0, U128(expected_target_buyer_balance)),
        deposit = STORAGE_AMOUNT
    );

    assert!(res.is_ok(), "ERR_SELL_TX_FAILED");

    let pool_balances: Vec<U128> = view!(amm.get_pool_balances(market_id)).unwrap_json();
    assert_eq!(pool_balances[0], U128(seed_amount));
    assert_eq!(pool_balances[1], U128(seed_amount));

    let seeder_balance: u128 = ft_balance_of(&alice, &alice.account_id().to_string()).into();
    assert_eq!(seeder_balance, init_balance() - seed_amount);
    let amm_balance: u128 = ft_balance_of(&alice, &"amm".to_string()).into();
    assert_eq!(amm_balance, seed_amount);
}

// Check price after uneven swaps
#[test]
fn swap_complex_buy_test() {
    let (_master_account, amm, token, alice, bob, _carol) = init("carol".to_string());

    let seed_amount = to_token_denom(10);
    let buy_amount = to_token_denom(1);

    let market_id: U64 = create_market(&alice, &amm, 3, Some(U128(0)));

    let weights = calc_weights_from_price(
        vec![
            U128(to_token_denom(60)),
            U128(to_token_denom(30)),
            U128(to_token_denom(10))
        ]
    );

    assert_eq!(market_id, U64(0));

    ft_transfer_call(&alice, seed_amount, compose_add_liquidity_args(market_id, Some(weights)));


    let init_balances: Vec<U128> = view!(amm.get_pool_balances(market_id)).unwrap_json();

    let init_invariant = product_of(&init_balances);

    ft_transfer_call(&bob, buy_amount, compose_buy_args(market_id, 0, U128(to_token_denom(15) / 10)));

    let post_trade_balances: Vec<U128> = view!(amm.get_pool_balances(market_id)).unwrap_json();
    let post_trade_invariant = product_of(&post_trade_balances);
    assert!(init_invariant - post_trade_invariant <  1000);

    let target_pool_balance: U128 = view!(amm.get_share_balance(&"amm".to_string(), market_id, 0)).unwrap_json();
    let target_buyer_balance: U128 = view!(amm.get_share_balance(&bob.account_id(), market_id, 0)).unwrap_json();
    let inverse_balances: Vec<U128> = vec![post_trade_balances[1], post_trade_balances[2]];
    let product_of_inverse = product_of(&inverse_balances);

    let expected_pool_target_balance = math::complex_div_u128(token_denom(), post_trade_invariant, product_of_inverse);
    let expected_buyer_target_balance = u128::from(init_balances[0]) + buy_amount - expected_pool_target_balance;

    assert_eq!(U128(expected_buyer_target_balance), target_buyer_balance);
    assert_eq!(U128(expected_pool_target_balance), target_pool_balance);
}

#[test]
fn swap_multi_sell_test() {
    // Get accounts
    let (_master_account, amm, token, lp, trader1, trader2) = init("carol".to_string());
    
    let precision = to_token_denom(1) / 100; // 1 token_cent precision

    // Get initial balances
    let trader1_init_balance: u128 = ft_balance_of(&lp, &trader1.account_id()).into();

    // Expect trader1 to have ....
    let expected_trader1_share_bal = 1909090909090909090909091;
    // Expect trader2 to have ....
    let expected_trader2_share_bal = 1757575757575757575757576;
    let expected_trader2_final_balance = 999911500000000000000000000;

    // Seed / trade parameters
    let target_price = U128(to_token_denom(5) / 10);
    let seed_amount = to_token_denom(10);
    let buy_amt = to_token_denom(1);
    let weights = calc_weights_from_price(vec![target_price, target_price]);

    // Create market
    let market_id = create_market(&lp, &amm, 2, Some(U128(0)));

    // Seed market
    ft_transfer_call(&lp, seed_amount, compose_add_liquidity_args(market_id, Some(weights)));

    let amm_final_balance: u128 = ft_balance_of(&lp, &"amm".to_string()).into();
    assert_eq!(amm_final_balance, seed_amount);

    ft_transfer_call(&trader1, buy_amt, compose_buy_args(market_id, 0, U128(to_token_denom(8) / 10)));
    ft_transfer_call(&trader2, buy_amt, compose_buy_args(market_id, 0, U128(to_token_denom(8) / 10)));

    let trader1_share_balance: U128 = view!(amm.get_share_balance(&trader1.account_id(), market_id, 0)).unwrap_json();
    let trader2_share_balance: U128 = view!(amm.get_share_balance(&trader2.account_id(), market_id, 0)).unwrap_json();
    assert_eq!(trader1_share_balance, U128(expected_trader1_share_bal));
    assert_eq!(trader2_share_balance, U128(expected_trader2_share_bal));

    // Sell back from trader 1 and trader 2
    let sell_res_trader1 = call!(
        trader1,
        amm.sell(market_id, U128(buy_amt + buy_amt / 13), 0, U128(to_token_denom(10000))),
        deposit = STORAGE_AMOUNT
    );

    let sell_res_trader2 = call!(
        trader2,
        amm.sell(market_id, U128(to_token_denom(9115) / 10000), 0, U128(to_token_denom(10000))),
        deposit = STORAGE_AMOUNT
    );

    assert!(sell_res_trader1.is_ok(), "sell res trader 1 failed {:?}", sell_res_trader1);
    assert!(sell_res_trader2.is_ok(), "sell res trader 2 failed {:?}", sell_res_trader2);

    // Check balances with escrow both ways
    // Get updated balances
    let trader1_final_balance: u128 = ft_balance_of(&lp, &trader1.account_id()).into();
    let trader2_final_balance: u128 = ft_balance_of(&lp, &trader2.account_id()).into();

    // Assert balances
    assert!(trader1_init_balance - trader1_final_balance < precision);
    assert!(trader2_final_balance - expected_trader2_final_balance < precision);
}


#[test]
fn swap_complex_sell_with_fee_test() {
    // Get accounts
    let (_master_account, amm, token, lp, trader1, trader2) = init("carol".to_string());

    let precision = to_token_denom(1) / 100; // 1 token_cent precision

    // Get initial balances
    let trader1_init_balance: u128 = ft_balance_of(&lp, &trader1.account_id()).into();
    
    let expected_trader1_share_bal = 1872531876138433515482696;
    
    // Seed / trade parameters
    let target_price = U128(to_token_denom(5) / 10);
    let seed_amount = to_token_denom(10);
    let buy_amt = to_token_denom(1);
    let weights = calc_weights_from_price(vec![target_price, target_price]);

    // Create market
    let market_id = create_market(&lp, &amm, 2, Some(swap_fee()));

    // Seed market
    ft_transfer_call(&lp, seed_amount, compose_add_liquidity_args(market_id, Some(weights)));

    let amm_final_balance: u128 = ft_balance_of(&lp, &"amm".to_string()).into();
    assert_eq!(amm_final_balance, seed_amount);

    ft_transfer_call(&trader1, buy_amt, compose_buy_args(market_id, 0, U128(0)));

    let trader1_share_balance: U128 = view!(amm.get_share_balance(&trader1.account_id(), market_id, 0)).unwrap_json();
    assert_eq!(trader1_share_balance, U128(expected_trader1_share_bal));


    // Sell back from trader 1 and trader 2
    let sell_res_trader1 = call!(
        trader1,
        amm.sell(market_id, U128(959159302164807332), 0, U128(buy_amt * 25 / 10)),
        deposit = STORAGE_AMOUNT
    );
}


#[test]
fn swap_selling_uneven_lp_shares_binary_test() {
    // Get accounts
    let (_master_account, amm, token, lp, _trader1, _trader2) = init("carol".to_string());

    // Seed / trade parameters
    let seed_amount = to_token_denom(10);
    let amount_out_expected = to_token_denom(932) / 1000;
    let balance_after_seed = 3_333_333_333_333_333_333_333_333_333u128;
    let weights = calc_weights_from_price(vec![U128(to_token_denom(55) / 100), U128(to_token_denom(45) / 100)]);

    // Create market
    let market_id = create_market(&lp, &amm, 2, Some(swap_fee()));

    ft_transfer_call(&lp, seed_amount, compose_add_liquidity_args(market_id, Some(weights)));

    let outcome_balance_0: U128 = view!(amm.get_share_balance(&lp.account_id(), market_id, 0)).unwrap_json();
    let outcome_balance_1: U128 = view!(amm.get_share_balance(&lp.account_id(), market_id, 1)).unwrap_json();

    let sell_res_lp = call!(
        lp,
        amm.sell(market_id, U128(amount_out_expected), 0, U128(balance_after_seed)),
        deposit = STORAGE_AMOUNT
    );
    
    assert!(sell_res_lp.is_ok());

}

#[test]
fn swap_selling_uneven_lp_shares_categorical_test() {
    // Get accounts
    let (_master_account, amm, token, lp, trader1, trader2) = init("carol".to_string());

    // Seed / trade parameters
    let seed_amount = to_token_denom(10);
    let amount_out_expected = 838_054_961_715_504_818;
    let balance_after_seed = 3_333_333_333_333_333_333;
    let weights = vec![U128(12_000_000_000), U128(12_000_000_000), U128(18_000_000_000), U128(18_000_000_000)];

    // Create market
    let market_id = create_market(&lp, &amm, 4, Some(swap_fee()));

    ft_transfer_call(&lp, seed_amount, compose_add_liquidity_args(market_id, Some(weights)));


    let amm_final_balance: u128 = ft_balance_of(&lp, &"amm".to_string()).into();
    assert_eq!(amm_final_balance, seed_amount);

    let sell_res_lp = call!(
        lp,
        amm.sell(market_id, U128(amount_out_expected), 0, U128(balance_after_seed)),
        deposit = STORAGE_AMOUNT
    );

    assert!(sell_res_lp.is_ok());
}

fn redeem_collat_helper(target_price_a: U128, target_price_b: U128, token_value_80_20: u128) {
    let (master_account, amm, token, alice, bob, gov) = init("carol".to_string());
    let seed_amount = to_token_denom(10);
    let buy_amount = to_token_denom(1);

    let market_id: U64 = create_market(&alice, &amm, 2, Some(U128(0)));
    assert_eq!(market_id, U64(0));
    let weights = calc_weights_from_price(vec![target_price_a, target_price_b]);

    ft_transfer_call(&alice, seed_amount, compose_add_liquidity_args(market_id, Some(weights)));

    let buy_res = ft_transfer_call(&bob, buy_amount, compose_buy_args(market_id, 0, U128(0)));
    let expected_target_buyer_balance = token_value_80_20;
    let expected_other_buyer_balance = 0;

    let target_buyer_balance: U128 = view!(amm.get_share_balance(&bob.account_id(), market_id, 0)).unwrap_json();
    let other_buyer_balance: U128 = view!(amm.get_share_balance(&bob.account_id(), market_id, 1)).unwrap_json();

    assert_eq!(expected_target_buyer_balance, u128::from(target_buyer_balance));
    assert_eq!(expected_other_buyer_balance, u128::from(other_buyer_balance));

    // remove initial liquidity
    let liq_exit = call!(
        alice,
        amm.exit_pool(market_id, U128(seed_amount)),
        deposit = STORAGE_AMOUNT
    );
    assert!(liq_exit.is_ok());

    // add liquidity with unequal weights reversed
    let weights = calc_weights_from_price(vec![target_price_b, target_price_a]);
    ft_transfer_call(&alice, seed_amount, compose_add_liquidity_args(market_id, Some(weights)));

    let buy_res = ft_transfer_call(&bob, buy_amount, compose_buy_args(market_id, 1, U128(0)));
    let expected_target_buyer_balance = token_value_80_20;
    let expected_other_buyer_balance = token_value_80_20;

    let target_buyer_balance: U128 = view!(amm.get_share_balance(&bob.account_id(), market_id, 0)).unwrap_json();
    let other_buyer_balance: U128 = view!(amm.get_share_balance(&bob.account_id(), market_id, 1)).unwrap_json();

    assert_eq!(expected_target_buyer_balance, u128::from(target_buyer_balance));
    assert_eq!(expected_other_buyer_balance, u128::from(other_buyer_balance));

    let pre_redeem_balance = ft_balance_of(&bob, &bob.account_id());
    // Redeem liquidity
    let redeem_call = call!(
        bob,
        amm.burn_outcome_tokens_redeem_collateral(market_id, U128(token_value_80_20)),
        deposit = STORAGE_AMOUNT
    );
    if !redeem_call.is_ok() {
        panic!("redeem failed: {:?}", redeem_call);
    }

    // Assert collateral balance

    let expected_collateral_balance = std::cmp::min(999999999999999999999999998, u128::from(pre_redeem_balance)  + token_value_80_20);
    let collateral_balance: u128 = ft_balance_of(&alice, &bob.account_id()).into();
    assert_eq!(collateral_balance, expected_collateral_balance);

    // remove liquidity again
    let liq_exit = call!(
        alice,
        amm.exit_pool(market_id, U128(seed_amount)),
        deposit = STORAGE_AMOUNT
    );
    assert!(liq_exit.is_ok());

    // Resolute market
    let resolution_res = call!(
        gov,
        amm.resolute_market(market_id, None),
        deposit = STORAGE_AMOUNT
    );
    assert!(resolution_res.is_ok());
    
    // Claim earnings
    let alice_claim_res = call!(
        alice,
        amm.claim_earnings(market_id),
        deposit = STORAGE_AMOUNT
    );

    assert!(
        alice_claim_res.is_ok(), 
        "err: {:?}",
        alice_claim_res
    );
    
    let bob_claim_res = call!(
        bob,
        amm.claim_earnings(market_id),
        deposit = STORAGE_AMOUNT
    );

    assert!(
        bob_claim_res.is_ok(), 
        "err: {:?}",
        bob_claim_res
    );
}

#[test]
fn redeem_collat_with_bought_tokens_for_higher_price() {
    let token_value_80_20 = 1227272727272727272727273;
    let target_price_a = U128(to_token_denom(80) / 100);
    let target_price_b = U128(to_token_denom(20) / 100);
    // bob bought 2 times, and redeemed 1.22 again (loss of 0.8 tokens)
    redeem_collat_helper(target_price_a, target_price_b, token_value_80_20);
}