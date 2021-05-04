use crate::test_utils::*;
use near_sdk::json_types::{U64, U128};
use near_sdk::serde_json::json;
use near_sdk_sim::{to_yocto, call, view, STORAGE_AMOUNT};

#[test]
fn test_uneven_lp_shares_solvency_tests() {
        // Init and get accounts
        let (_master_account, amm, token, lp, trader1, trader2) = init("carol".to_string());
        
        // Record balances before any trading happens
        let lp_init_balance: u128 = ft_balance_of(&lp, &lp.account_id()).into();
        let trader1_init_balance: u128 = ft_balance_of(&lp, &trader1.account_id()).into();
        let trader2_init_balance: u128 = ft_balance_of(&lp, &trader2.account_id()).into();
        
        // Seed / trade parameters
        let weights = vec![U128(to_token_denom(3) / 10), U128(to_token_denom(7) / 10)];
        let seed_amount = to_token_denom(10);
        let buy_amt = to_token_denom(1);

        
        // Create market
        let market_id = create_market(&lp, &amm, 2, Some(U128(0)));
        
        ft_transfer_call(&lp, seed_amount, compose_add_liquidity_args(market_id, Some(weights)));
        
        // assert expected price for 0 & 1 (70 | 30)
        let price_0: U128 = view!(amm.get_spot_price_sans_fee(market_id, 0)).unwrap_json();
        let price_1: U128 = view!(amm.get_spot_price_sans_fee(market_id, 1)).unwrap_json();
        assert_eq!(price_0, U128(to_token_denom(7) / 10));
        assert_eq!(price_1, U128(to_token_denom(3) / 10));


        // Buy `buy_amount` from trader1 buy `buy_amount` from trader2
        let buy_a_args = compose_buy_args(market_id, 0, U128(0));

        // Buy some extra shares from lp accounts
        ft_transfer_call(&lp, buy_amt, buy_a_args.to_string());

        // Increase price by buying from two subsequent accounts
        ft_transfer_call(&trader1, buy_amt, buy_a_args.to_string());
        ft_transfer_call(&trader2, buy_amt, buy_a_args.to_string());

        // Sell back into pool from LP
        let sell_res = call!(
            lp,
            amm.sell(market_id, U128(to_token_denom(25) / 10), 0, U128(buy_amt * 100)),
            deposit = STORAGE_AMOUNT
        );
        assert!(sell_res.is_ok());

        // Resolute and payout
        // Resolute market
        let resolution_res = call!(
            trader2,
            amm.resolute_market(market_id, None),
            deposit = STORAGE_AMOUNT
        );
        
        let trader1_claim_res = call!(
            trader1,
            amm.claim_earnings(market_id),
            deposit = STORAGE_AMOUNT
        );
        assert!(trader1_claim_res.is_ok());
        
        let trader2_claim_res = call!(
            trader2,
            amm.claim_earnings(market_id),
            deposit = STORAGE_AMOUNT
        );
        assert!(trader2_claim_res.is_ok());

        // Claim earnings
        let lp_claim_res = call!(
            lp,
            amm.claim_earnings(market_id),
            deposit = STORAGE_AMOUNT
        );

        assert!(lp_claim_res.is_ok());
        
        // Get updated balances
        let lp_final_balance: u128 = ft_balance_of(&lp, &lp.account_id()).into();
        let trader1_final_balance: u128 = ft_balance_of(&lp, &trader1.account_id()).into();
        let trader2_final_balance: u128 = ft_balance_of(&lp, &trader2.account_id()).into();
        let amm_final_balance: u128 = ft_balance_of(&lp, &"amm".to_string()).into();
        
        // Assert that all balances are back to where they started
        assert_eq!(lp_final_balance, lp_init_balance);
        assert_eq!(trader1_final_balance, trader1_init_balance);
        assert_eq!(trader2_final_balance, trader2_init_balance);
        assert_eq!(amm_final_balance, 0);
}