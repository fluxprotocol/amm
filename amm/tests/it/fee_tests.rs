use crate::test_utils::*;
use near_sdk::json_types::{U64, U128};
use near_sdk::serde_json::json;
use near_sdk_sim::{call, view, STORAGE_AMOUNT};

#[test]
fn fee_valid_market_lp_fee_test() {
    let (_master_account, amm, _token, funder, joiner, trader) = crate::test_utils::init("carol".to_string());

    let seed_amount = to_token_denom(1000);
    let buy_amt = to_token_denom(100);
    let target_price_a = U128(to_token_denom(5) / 10);
    let target_price_b = U128(to_token_denom(5) / 10);
    let weights = calc_weights_from_price(vec![target_price_a, target_price_b]);
    let swap_fee = to_token_denom(2) / 100;

    let market_id: U64 = create_market(&funder, &amm, 2, Some(U128(swap_fee)));

    assert_eq!(market_id, U64(0));

    ft_transfer_call(&funder, seed_amount, compose_add_liquidity_args(market_id, Some(weights)));

    let funder_pool_balance: U128 = view!(amm.get_pool_token_balance(market_id, &funder.account_id())).unwrap_json();

    let buy_a_args = compose_buy_args(market_id, 0, U128(to_token_denom(8) / 10));
    let buy_b_args = compose_buy_args(market_id, 1, U128(to_token_denom(8) / 10));

    ft_transfer_call(&trader, buy_amt, buy_a_args.to_string());
    ft_transfer_call(&trader, buy_amt, buy_b_args.to_string());
    ft_transfer_call(&trader, buy_amt, buy_a_args.to_string());
    ft_transfer_call(&trader, buy_amt, buy_b_args.to_string());
    ft_transfer_call(&trader, buy_amt, buy_a_args.to_string());
    ft_transfer_call(&trader, buy_amt, buy_b_args.to_string());
    ft_transfer_call(&trader, buy_amt, buy_a_args.to_string());
    ft_transfer_call(&trader, buy_amt, buy_b_args.to_string());
    ft_transfer_call(&trader, buy_amt, buy_a_args.to_string());
    ft_transfer_call(&trader, buy_amt, buy_b_args.to_string());

    // joiner
    ft_transfer_call(&joiner, seed_amount, compose_add_liquidity_args(market_id, None));

    let joiner_pool_balance: U128 = view!(amm.get_pool_token_balance(market_id, &joiner.account_id())).unwrap_json();

    
    let expected_claimable_by_funder = to_token_denom(20);
    let claimable_by_funder: U128 = view!(amm.get_fees_withdrawable(market_id, &funder.account_id())).unwrap_json();
    let claimable_by_joiner: U128 = view!(amm.get_fees_withdrawable(market_id, &joiner.account_id())).unwrap_json();
    assert_eq!(U128(expected_claimable_by_funder), claimable_by_funder);
    assert_eq!(claimable_by_joiner, U128(0));

    let funder_exit_res = call!(
        funder,
        amm.exit_pool(market_id, funder_pool_balance),
        deposit = STORAGE_AMOUNT
    );
    assert!(funder_exit_res.is_ok());

    let joiner_exit_res = call!(
        joiner,
        amm.exit_pool(market_id, joiner_pool_balance),
        deposit = STORAGE_AMOUNT
    );
    assert!(joiner_exit_res.is_ok());
    
    let funder_pool_token_balance_after_exit: U128 = view!(amm.get_pool_token_balance(market_id, &funder.account_id())).unwrap_json();
    let joiner_pool_token_balance_after_exit: U128 = view!(amm.get_pool_token_balance(market_id, &joiner.account_id())).unwrap_json();
    assert_eq!(funder_pool_token_balance_after_exit, U128(0));
    assert_eq!(joiner_pool_token_balance_after_exit, U128(0));
}

#[test]
fn fee_invalid_market_lp_fee_test() {
    let (_master_account, amm, _token, funder, joiner, trader) = crate::test_utils::init("carol".to_string());

    let joiner_trader_balances = init_balance();

    let funder_balance: u128 = ft_balance_of(&funder, &funder.account_id()).into();
    let seed_amount = to_token_denom(1000);
    let buy_amt = to_token_denom(100);
    let target_price_a = U128(to_token_denom(5) / 10);
    let target_price_b = U128(to_token_denom(5) / 10);
    let weights = calc_weights_from_price(vec![target_price_a, target_price_b]);
    let swap_fee = to_token_denom(2) / 100;

    let market_id: U64 = create_market(&funder, &amm, 2, Some(U128(swap_fee)));

    assert_eq!(market_id, U64(0));


    ft_transfer_call(&funder, seed_amount, compose_add_liquidity_args(market_id, Some(weights)));

    let funder_pool_balance: U128 = view!(amm.get_pool_token_balance(market_id, &funder.account_id())).unwrap_json();

    // $1000 in swaps at 2% fee
    let buy_a_args = compose_buy_args(market_id, 0, U128(to_token_denom(8) / 10));
    let buy_b_args = compose_buy_args(market_id, 1, U128(to_token_denom(8) / 10));

    ft_transfer_call(&trader, buy_amt, buy_a_args.to_string());
    ft_transfer_call(&trader, buy_amt, buy_b_args.to_string());
    ft_transfer_call(&trader, buy_amt, buy_a_args.to_string());
    ft_transfer_call(&trader, buy_amt, buy_b_args.to_string());
    ft_transfer_call(&trader, buy_amt, buy_a_args.to_string());
    ft_transfer_call(&trader, buy_amt, buy_b_args.to_string());
    ft_transfer_call(&trader, buy_amt, buy_a_args.to_string());
    ft_transfer_call(&trader, buy_amt, buy_b_args.to_string());
    ft_transfer_call(&trader, buy_amt, buy_a_args.to_string());
    ft_transfer_call(&trader, buy_amt, buy_b_args.to_string());
    
    // Sell back for buy amount
    let sell_res = call!(
        trader,
        amm.sell(market_id, U128(buy_amt), 0, U128(buy_amt * 25 / 10)),
        deposit = STORAGE_AMOUNT
    );
    assert!(sell_res.is_ok());


    // Sell back for buy amount
    let sell_res = call!(
        trader,
        amm.sell(market_id, U128(buy_amt), 0, U128(buy_amt * 45 / 10)),
        deposit = STORAGE_AMOUNT
    );
    assert!(sell_res.is_ok());

    ft_transfer_call(&joiner, seed_amount, compose_add_liquidity_args(market_id, None));
    
    let joiner_pool_balance: U128 = view!(amm.get_pool_token_balance(market_id, &joiner.account_id())).unwrap_json();

    let expected_claimable_by_funder = to_token_denom(24);
    let claimable_by_funder: U128 = view!(amm.get_fees_withdrawable(market_id, &funder.account_id())).unwrap_json();
    let claimable_by_joiner: U128 = view!(amm.get_fees_withdrawable(market_id, &joiner.account_id())).unwrap_json();
    assert_eq!(U128(expected_claimable_by_funder), claimable_by_funder);
    assert_eq!(claimable_by_joiner, U128(0));

    let funder_exit_res = call!(
        funder,
        amm.exit_pool(market_id, funder_pool_balance),
        deposit = STORAGE_AMOUNT
    );
    assert!(funder_exit_res.is_ok());

    let joiner_exit_res = call!(
        joiner,
        amm.exit_pool(market_id, joiner_pool_balance),
        deposit = STORAGE_AMOUNT
    );
    assert!(joiner_exit_res.is_ok(), "joiner exit res failed {:?}", joiner_exit_res);


    let funder_pool_token_balance_after_exit: U128 = view!(amm.get_pool_token_balance(market_id, &funder.account_id())).unwrap_json();
    let joiner_pool_token_balance_after_exit: U128 = view!(amm.get_pool_token_balance(market_id, &joiner.account_id())).unwrap_json();
    assert_eq!(funder_pool_token_balance_after_exit, U128(0));
    assert_eq!(joiner_pool_token_balance_after_exit, U128(0));


    // Resolute market
    let resolution_res = call!(
        trader,
        amm.resolute_market(market_id, None),
        deposit = STORAGE_AMOUNT
    );

    assert!(resolution_res.is_ok());
    
    // Claim earnings
    let joiner_claim_res = call!(
        joiner,
        amm.claim_earnings(market_id),
        deposit = STORAGE_AMOUNT
    );
    assert!(joiner_claim_res.is_ok());
    
    // Claim earnings
    let lp_claim_res = call!(
        funder,
        amm.claim_earnings(market_id),
        deposit = STORAGE_AMOUNT
    );
    assert!(lp_claim_res.is_ok());
    
    let trader_claim_res = call!(
        trader,
        amm.claim_earnings(market_id),
        deposit = STORAGE_AMOUNT
    );

    assert!(trader_claim_res.is_ok());

    // Get updated balances
    let lp_final_balance: u128 = ft_balance_of(&funder, &funder.account_id()).into();
    let joiner_final_balance: u128 = ft_balance_of(&funder, &joiner.account_id()).into();
    let trader_final_balance: u128 = ft_balance_of(&funder, &trader.account_id()).into();
    let amm_final_balance: u128 = ft_balance_of(&funder, &"amm".to_string()).into();
    
    // Assert balances
    let expected_lp_final_balance = funder_balance + u128::from(claimable_by_funder) - 1;
    let expected_joiner_final_balance = joiner_trader_balances + 1;
    let expected_trader_final_balance = joiner_trader_balances - u128::from(claimable_by_funder);

    assert_eq!(lp_final_balance, expected_lp_final_balance);
    assert_eq!(joiner_final_balance, expected_joiner_final_balance);
    assert_eq!(trader_final_balance, expected_trader_final_balance);
    assert_eq!(amm_final_balance, 0);
}

#[test]
fn test_specific_fee_scenario() {
    let (_master_account, amm, _token, trader1, trader2, seeder) = crate::test_utils::init("carol".to_string());

    let seeder_balance: u128 = ft_balance_of(&seeder, &seeder.account_id()).into();
    let trader1_balance: u128 = ft_balance_of(&trader1, &trader1.account_id()).into();
    let trader2_balance: u128 = ft_balance_of(&trader2, &trader2.account_id()).into();

    let fee_payed_t1 = to_token_denom(2) / 100 + to_token_denom(117) * 2 / 10000;
    let fee_payed_t2 = to_token_denom(6) / 100;

    let expected_trader1_balance = trader1_balance - fee_payed_t1;
    let expected_trader2_balance = trader2_balance - fee_payed_t2;
    let expected_seeder_balance = seeder_balance + fee_payed_t1 + fee_payed_t2;

    let seed_amount = to_token_denom(10);
    let buy_amt_t1 = to_token_denom(1);
    let buy_amt_t2 = to_token_denom(3);

    let target_price_a = U128(to_token_denom(5) / 10);
    let target_price_b = U128(to_token_denom(5) / 10);
    let weights = calc_weights_from_price(vec![target_price_a, target_price_b]);

    let swap_fee = to_token_denom(2) / 100;

    let market_id: U64 = create_market(&seeder, &amm, 2, Some(U128(swap_fee)));

    assert_eq!(market_id, U64(0));


    ft_transfer_call(&seeder, seed_amount, compose_add_liquidity_args(market_id, Some(weights)));
    let buy_a_args = compose_buy_args(market_id, 0, U128(to_token_denom(8) / 10));

    ft_transfer_call(&trader1, buy_amt_t1, buy_a_args.to_string());
    ft_transfer_call(&trader2, buy_amt_t2, buy_a_args);

    let sell_res_trader1 = call!(
        trader1,
        amm.sell(market_id, U128(to_token_denom(117) / 100), 0, U128(to_token_denom(10000))),
        deposit = STORAGE_AMOUNT
    );
    assert!(sell_res_trader1.is_ok());

    // Resolute market
    let resolute_market = call!(
        seeder,
        amm.resolute_market(market_id, None),
        deposit = STORAGE_AMOUNT
    );

    assert!(resolute_market.is_ok());

    // Claim earnings
    let claim_res_t1 = call!(
        trader1,
        amm.claim_earnings(market_id),
        deposit = STORAGE_AMOUNT
    );
    assert!(claim_res_t1.is_ok());
    
    // Claim earnings
    let claim_res_t2 = call!(
        trader2,
        amm.claim_earnings(market_id),
        deposit = STORAGE_AMOUNT
    );
    assert!(claim_res_t2.is_ok());
    
    // Claim earnings
    let claim_res_seeder = call!(
        seeder,
        amm.claim_earnings(market_id),
        deposit = STORAGE_AMOUNT
    );

    assert!(claim_res_seeder.is_ok());
    let amm_bal: u128 = ft_balance_of(&seeder, &"amm".to_string()).into();

    let seeder_balance_post: u128 = ft_balance_of(&seeder, &seeder.account_id()).into();
    let trader1_balance_post: u128 = ft_balance_of(&trader1, &trader1.account_id()).into();
    let trader2_balance_post: u128 = ft_balance_of(&trader2, &trader2.account_id()).into();

    assert_eq!(amm_bal, 0);
    assert_eq!(trader1_balance_post, expected_trader1_balance);
    assert_eq!(trader2_balance_post, expected_trader2_balance);
    assert_eq!(seeder_balance_post, expected_seeder_balance);
}