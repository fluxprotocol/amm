// mod test_utils;
use crate::test_utils::*;
use near_sdk::json_types::U128;
use near_sdk_sim::{to_yocto, call, STORAGE_AMOUNT};

#[test]
fn multi_lp_payout_no_exit() {
        // Get accounts
        let (master_account, amm, _token, lp, trader, gov) = init("carol".to_string());

        let buy_amount = to_yocto("1") / 10;
        
        // Calc expected balances after invalid resolution
        let expected_amm_final_balance = 0;
        
        // Seed / trade parameters
        let target_price_0 = U128(to_token_denom(9999) / 10000);
        let target_price_1 = U128(to_token_denom(1) / 100);
        let seed_amount_0 = 200000000000000000000000 ;
        let seed_amount_1 = to_token_denom(1) ;
        let weights = calc_weights_from_price(vec![target_price_1, target_price_0]);
        
        // Create market
        let market_id = create_market(&lp, &amm, 2, Some(swap_fee()));
        
        ft_transfer_call(&trader, 100 * token_denom(), compose_add_liquidity_args(market_id, Some(weights)));


        // Insert buys
        let buy_a_args = compose_buy_args(market_id, 0, U128(to_token_denom(8) / 10));
        // let buy_b_args = compose_buy_args(market_id, 1, U128(to_token_denom(8) / 10));

        ft_transfer_call(&trader, buy_amount, buy_a_args.to_string());
        ft_transfer_call(&trader, buy_amount, buy_a_args.to_string());
        ft_transfer_call(&trader, buy_amount, buy_a_args.to_string());

        ft_transfer_call(&lp, seed_amount_0, compose_add_liquidity_args(market_id, None));
        
        ft_transfer_call(&lp, buy_amount, buy_a_args.to_string());
        ft_transfer_call(&lp, seed_amount_1, compose_add_liquidity_args(market_id, None));
        ft_transfer_call(&lp, buy_amount, buy_a_args.to_string());

        // Resolute market
        call!(
            gov,
            amm.resolute_market(market_id, Some(vec![U128(0), U128(to_token_denom(1))])),
            deposit = STORAGE_AMOUNT
        );

        // Claim earnings
        let trader_claim_res = call!(
            trader,
            amm.claim_earnings(market_id),
            deposit = STORAGE_AMOUNT
        );

        assert!(trader_claim_res.is_ok());
        // Claim earnings
        let lp_claim_res = call!(
            lp,
            amm.claim_earnings(market_id),
            deposit = STORAGE_AMOUNT
        );

        assert!(lp_claim_res.is_ok());

        // Get updated balances
        let amm_final_balance: u128 = ft_balance_of(&master_account, &"amm".to_string()).into();
        
        // Assert balances`
        assert_eq!(amm_final_balance, expected_amm_final_balance);
}