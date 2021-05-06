use crate::*;
use std::convert::TryInto;
use collateral_whitelist::Token;
use token::*;
use near_sdk::serde_json::json;

#[derive(BorshDeserialize, BorshSerialize)]
pub struct Market {
    pub end_time: u64, // Time when trading is halted
    pub resolution_time: u64, // Time when the market can be resoluted
    pub pool: Pool, // Implementation that manages the liquidity pool and swap
    pub payout_numerator: Option<Vec<U128>>, // Optional Vector that dictates how payout is done. Each payout numerator index corresponds to an outcome and shares the denomination of te collateral token for this market.
    pub finalized: bool, // If true the market has an outcome, if false the market it still undecided.
}

#[near_bindgen]
impl AMMContract {
    /**
     * @param market_id is the index of the market to retrieve data from
     * @returns the fee percentage denominated in 1e4 e.g. 1 = 0.01%
     */
    pub fn get_pool_swap_fee(&self, market_id: U64) -> U128 {
        let market = self.get_market_expect(market_id);
        U128(market.pool.get_swap_fee())
    }

    /**
     * @param market_id is the index of the market to retrieve data from
     * @returns the `fee_pool_weight` which dictates fee payouts
     */
    pub fn get_fee_pool_weight(&self, market_id: U64) -> U128 {
        let market = self.get_market_expect(market_id);
        U128(market.pool.fee_pool_weight)
    }

    /**
     * @param market_id is the index of the market to retrieve data from
     * @returns the LP token's total supply for a pool
     */
    pub fn get_pool_token_total_supply(&self, market_id: U64) -> U128 {
        let market = self.get_market_expect(market_id);
        U128(market.pool.pool_token.total_supply())
    }

    /**
     * @param market_id is the index of the market to retrieve data from
     * @returns all of the outcome balances for a specific pool
     */
    pub fn get_pool_balances(
        &self,
        market_id: U64
    ) -> Vec<U128>{
        let market = self.get_market_expect(market_id);
        market.pool.get_pool_balances().into_iter().map(|b| b.into()).collect()
    }

    /**
     * @param market_id is the index of the market to retrieve data from
     * @param account_id the `AccountId` to retrieve data from
     * @returns the LP token balance for `account_id`
     */
    pub fn get_pool_token_balance(
        &self, 
        market_id: U64, 
        owner_id: &AccountId
    ) -> U128 {
        let market = self.get_market_expect(market_id);
        U128(market.pool.get_pool_token_balance(owner_id))
    }

    /**
     * @notice returns the current spot price of an outcome without taking a fee into account
     * @param market_id is the index of the market to retrieve data from
     * @param outcome is the outcome to get the current spot price fpr
     * @returns a wrapped price of the outcome at current state
     */
    pub fn get_spot_price_sans_fee(
        &self,
        market_id: U64,
        outcome: u16
    ) -> U128 {
        let market = self.get_market_expect(market_id);
        market.pool.get_spot_price_sans_fee(outcome).into()
    }

    /**
     * @notice calculates the amount of shares of a certain outcome a user would get out for the collateral they provided
     * @param market_id is the index of the market to retrieve data from
     * @param collateral_in is the amount of collateral to be used to calculate amount of shares out
     * @param outcome_target is the outcome that is to be purchased 
     * @returns a wrapped number of `outcome_shares` a user would get in return for `collateral_in`
     */
    pub fn calc_buy_amount(
        &self,
        market_id: U64,
        collateral_in: U128,
        outcome_target: u16
    ) -> U128 {
        let market = self.get_market_expect(market_id);
        U128(market.pool.calc_buy_amount(collateral_in.into(), outcome_target))
    }

    /**
     * TODO: Rename to calc_sell_shares_in
     * @notice calculates the amount of shares a user has to put in in order to get `collateral_out`
     * @param market_id is the index of the market to retrieve data from
     * @param collateral_out is the amount of collateral that a user wants to get out of a position, it's used to calculate the amount of `outcome_shares` that need to be transferred in
     * @param outcome_target is the outcome that the amount of shares a user wants to sell
     * @returns a wrapped number of `outcome_shares` a user would have to transfer in in order to get `collateral_out`
     */
    pub fn calc_sell_collateral_out(
        &self,
        market_id: U64,
        collateral_out: U128,
        outcome_target: u16
    ) -> U128 {
        let market = self.get_market_expect(market_id);
        U128(market.pool.calc_sell_collateral_out(collateral_out.into(), outcome_target))
    }

    /**
     * @param account_id is the `AccountId` to retrieve the `outcome_shares` for
     * @param market_id is the index of the market to retrieve data from
     * @param outcome is the `outcome_shares` to get the balance from
     * @returns wrapped balance of `outcome_shares`
     */
    pub fn get_share_balance(
        &self, 
        account_id: &AccountId, 
        market_id: U64, 
        outcome: u16
    ) -> U128 {
        let market = self.get_market_expect(market_id);
        U128(market.pool.get_share_balance(account_id, outcome))
    }

    /**
     * @param market_id is the index of the market to retrieve data from
     * @param account_id is the account id to retrieve the accrued fees for
     * @returns wrapped amount of fees withdrawable for `account_id`
     */
    pub fn get_fees_withdrawable(
        &self, 
        market_id: U64, 
        account_id: &AccountId
    ) -> U128 {
        let market = self.get_market_expect(market_id);
        U128(market.pool.get_fees_withdrawable(account_id))
    }

    /**
     * @notice allows users to create new markets
     * @param description is a detailed description of the market
     * @param extra_info extra information on how the market should be resoluted
     * @param outcomes the number of possible outcomes for the market
     * @param outcome_tags is a list of outcomes where the index is the `outcome_id`
     * @param categories is a list of categories to filter the market by
     * @param end_time when the trading should stop
     * @param resolution_time when the market can be resolved
     * @param collateral_token_id the `account_id` of the whitelisted token that is used as collateral for trading
     * @param swap_fee the fee that's taken from every swap and paid out to LPs
     * @param is_scalar if the market is a scalar market (range)
     * @returns wrapped `market_id` 
     */
    #[payable]
    pub fn create_market(
        &mut self,
        description: String,
        extra_info: String,
        outcomes: u16,
        outcome_tags: Vec<String>,
        categories: Vec<String>,
        end_time: U64,
        resolution_time: U64,
        collateral_token_id: AccountId,
        swap_fee: U128,
        is_scalar: Option<bool>,
    ) -> U64 {
        self.assert_unpaused();
        let end_time: u64 = end_time.into();
        let resolution_time: u64 = resolution_time.into();
        let swap_fee: u128 = swap_fee.into();
        let market_id = self.markets.len();
        let token_decimals = self.collateral_whitelist.0.get(&collateral_token_id);
        assert!(token_decimals.is_some(), "ERR_INVALID_COLLATERAL");
        assert!(outcome_tags.len() as u16 == outcomes, "ERR_INVALID_TAG_LENGTH");
        assert!(end_time > ns_to_ms(env::block_timestamp()), "ERR_INVALID_END_TIME");
        assert!(resolution_time >= end_time, "ERR_INVALID_RESOLUTION_TIME");
        let initial_storage = env::storage_usage();

        let pool = pool_factory::new_pool(
            market_id,
            outcomes,
            collateral_token_id,
            token_decimals.unwrap(),
            swap_fee
        );

        logger::log_pool(&pool);

        let market = Market {
            end_time,
            resolution_time,
            pool,
            payout_numerator: None,
            finalized: false
        };

        logger::log_create_market(&market, description, extra_info, outcome_tags, categories, is_scalar);
        logger::log_market_status(&market);
        
        self.markets.push(&market);
        self.refund_storage(initial_storage, env::predecessor_account_id());
        market_id.into()
    }

    /**
     * @notice sell `outcome_shares` for collateral
     * @param market_id references the market to sell shares from 
     * @param collateral_out is the amount of collateral that is expected to be transferred to the sender after selling
     * @param outcome_target is which `outcome_share` to sell
     * @param max_shares_in is the maximum amount of `outcome_shares` to transfer in, in return for `collateral_out` this is prevent sandwich attacks and unwanted `slippage`
     * @returns a promise referencing the collateral token transaction
     */
    #[payable]
    pub fn sell(
        &mut self,
        market_id: U64,
        collateral_out: U128,
        outcome_target: u16,
        max_shares_in: U128
    ) -> Promise {
        self.assert_unpaused();
        let initial_storage = env::storage_usage();
        let collateral_out: u128 = collateral_out.into();
        let mut market = self.markets.get(market_id.into()).expect("ERR_NO_MARKET");
        assert!(!market.finalized, "ERR_FINALIZED_MARKET");
        assert!(market.end_time > ns_to_ms(env::block_timestamp()), "ERR_MARKET_ENDED");
        let escrowed = market.pool.sell(
            &env::predecessor_account_id(),
            collateral_out,
            outcome_target,
            max_shares_in.into()
        );

        self.markets.replace(market_id.into(), &market);
        self.refund_storage(initial_storage, env::predecessor_account_id());

        collateral_token::ft_transfer(
            env::predecessor_account_id(), 
            U128(collateral_out - escrowed),
            None,
            &market.pool.collateral_token_id,
            1,
            GAS_BASE_COMPUTE
        )
    }

    /**
     * @notice Allows senders who hold tokens in all outcomes to redeem the lowest common denominator of shares for an equal amount of collateral
     * @param market_id references the market to redeem
     * @param total_in is the amount outcome tokens to redeem
     * @returns a transfer `Promise` or a boolean representing a collateral transfer
     */
    #[payable]
    pub fn burn_outcome_tokens_redeem_collateral(
        &mut self,
        market_id: U64,
        to_burn: U128
    ) -> Promise {
        self.assert_unpaused();
        let initial_storage = env::storage_usage();

        let mut market = self.markets.get(market_id.into()).expect("ERR_NO_MARKET");
        assert!(!market.finalized, "ERR_MARKET_FINALIZED");

        let escrowed = market.pool.burn_outcome_tokens_redeem_collateral(
            &env::predecessor_account_id(),
            to_burn.into()
        );

        self.markets.replace(market_id.into(), &market);

        self.refund_storage(initial_storage, env::predecessor_account_id());

        let payout = u128::from(to_burn) - escrowed;

        logger::log_transaction(&logger::TransactionType::Redeem, &env::predecessor_account_id(), to_burn.into(), payout, market_id, None);

        collateral_token::ft_transfer(
            env::predecessor_account_id(),
            payout.into(),
            None,
            &market.pool.collateral_token_id,
            1,
            GAS_BASE_COMPUTE
        )
    }

    /**
     * @notice removes liquidity from a pool
     * @param market_id references the market to remove liquidity from 
     * @param total_in is the amount of LP tokens to redeem
     * @returns a transfer `Promise` or a boolean representing a successful exit
     */
    #[payable]
    pub fn exit_pool(
        &mut self,
        market_id: U64,
        total_in: U128,
    ) -> PromiseOrValue<bool> {
        self.assert_unpaused();
        let initial_storage = env::storage_usage();

        let mut market = self.markets.get(market_id.into()).expect("ERR_NO_MARKET");
        let fees_earned = market.pool.exit_pool(
            &env::predecessor_account_id(),
            total_in.into()
        );
        
        self.markets.replace(market_id.into(), &market);

        self.refund_storage(initial_storage, env::predecessor_account_id());

        if fees_earned > 0 {
            PromiseOrValue::Promise(
                collateral_token::ft_transfer(
                    env::predecessor_account_id(), 
                    fees_earned.into(),
                    None,
                    &market.pool.collateral_token_id,
                    1,
                    GAS_BASE_COMPUTE
                )
            )
        } else {
            PromiseOrValue::Value(true)
        }
    }

    /**
     * @notice sets the resolution and finalizes a market
     * @param market_id references the market to resolute 
     * @param payout_numerator optional list of numeric values that represent the relative payout value for owners of matching outcome shares
     *      share denomination with collateral token. E.g. Collateral token denomination is 1e18 means that if payout_numerators are [5e17, 5e17] 
     *      it's a 50/50 split if the payout_numerator is None it means that the market is invalid
     */
    #[payable]
    pub fn resolute_market(
        &mut self,
        market_id: U64,
        payout_numerator: Option<Vec<U128>>
    ) {
        self.assert_gov();
        // let initial_storage = env::storage_usage();
        let mut market = self.markets.get(market_id.into()).expect("ERR_NO_MARKET");
        assert!(!market.finalized, "ERR_IS_FINALIZED");
        assert!(market.resolution_time <= ns_to_ms(env::block_timestamp()), "ERR_RESOLUTION_TIME_NOT_REACHED");
        match &payout_numerator {
            Some(v) => {
                let sum = v.iter().fold(0, |s, &n| s + u128::from(n));
                assert_eq!(sum, market.pool.collateral_denomination, "ERR_INVALID_PAYOUT_SUM");
                assert_eq!(v.len(), market.pool.outcomes as usize, "ERR_INVALID_NUMERATOR");
            },
            None => ()
        };

        market.payout_numerator = payout_numerator;
        market.finalized = true;
        self.markets.replace(market_id.into(), &market);
        // self.refund_storage(initial_storage, env::predecessor_account_id());

        logger::log_market_status(&market);
    }

    /**
     * @notice claims earnings for the sender 
     * @param market_id references the resoluted market to claim earnings for
     */
    #[payable]
    pub fn claim_earnings(
        &mut self,
        market_id: U64
    ) -> Promise { 
        self.assert_unpaused();
        let initial_storage = env::storage_usage();
        let mut market = self.markets.get(market_id.into()).expect("ERR_NO_MARKET");
        assert!(market.finalized, "ERR_NOT_FINALIZED");

        let payout = market.pool.payout(&env::predecessor_account_id(), &market.payout_numerator);
        self.markets.replace(market_id.into(), &market);

        self.refund_storage(initial_storage, env::predecessor_account_id());

        logger::log_claim_earnings(
            market_id,
            env::predecessor_account_id(),
            payout
        );

        if payout > 0 {
                collateral_token::ft_transfer(
                    env::predecessor_account_id(), 
                    payout.into(),
                    None,
                    &market.pool.collateral_token_id,
                    1,
                    GAS_BASE_COMPUTE
                )
        } else {
            panic!("ERR_NO_PAYOUT");
        }
    }
}

impl AMMContract {
    /**
     * @notice get and return a certain market, panics if the market doesn't exist
     * @returns the market
     */
    pub fn get_market_expect(&self, market_id: U64) -> Market {
        self.markets.get(market_id.into()).expect("ERR_NO_MARKET")
    }

    /**
     * @notice add liquidity to a pool
     * @param sender the sender of the original transfer_call
     * @param total_in total amount of collateral to add to the market
     * @param json string of `AddLiquidity` args
     */
    pub fn add_liquidity(
        &mut self,
        sender: &AccountId,
        total_in: u128,
        args: AddLiquidityArgs,
    ) {
        let weights_u128: Option<Vec<u128>> = match args.weight_indication {
            Some(weight_indication) => {
                Some(weight_indication
                    .iter()
                    .map(|weight| { u128::from(*weight) })
                    .collect()
                )
            },
            None => None
        };
           
        let mut market = self.markets.get(args.market_id.into()).expect("ERR_NO_MARKET");
        assert!(!market.finalized, "ERR_FINALIZED_MARKET");
        assert!(market.end_time > ns_to_ms(env::block_timestamp()), "ERR_MARKET_ENDED");
        assert_collateral_token(&market.pool.collateral_token_id);
        
        market.pool.add_liquidity(
            &sender,
            total_in,
            weights_u128
        );
        self.markets.replace(args.market_id.into(), &market);
    }


    /**
     * @notice buy an outcome token
     * @param sender the sender of the original transfer_call
     * @param total_in total amount of collateral to use for purchasing
     * @param json string of `AddLiquidity` args
     */
    pub fn buy(
        &mut self,
        sender: &AccountId,
        collateral_in: u128, 
        args: BuyArgs,
    ) {
        let mut market = self.markets.get(args.market_id.into()).expect("ERR_NO_MARKET");
        assert!(!market.finalized, "ERR_FINALIZED_MARKET");
        assert!(market.end_time > ns_to_ms(env::block_timestamp()), "ERR_MARKET_ENDED");
        assert_collateral_token(&market.pool.collateral_token_id);
        
        market.pool.buy(
            &sender,
            collateral_in,
            args.outcome_target,
            args.min_shares_out.into()
        );

        self.markets.replace(args.market_id.into(), &market);
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[cfg(test)]
mod market_basic_tests {
    use near_sdk::{ MockedBlockchain };
    use near_sdk::{ testing_env, VMContext };
    use crate::helper::{ alice, bob, token, empty_string, empty_string_vec };
    use super::*;

    fn get_context(predecessor_account_id: AccountId, timestamp: u64) -> VMContext {
        VMContext {
            current_account_id: alice(),
            signer_account_id: alice(),
            signer_account_pk: vec![0, 1, 2],
            predecessor_account_id,
            input: vec![],
            block_index: 0,
            block_timestamp: timestamp,
            account_balance: 1000 * 10u128.pow(24),
            account_locked_balance: 0,
            storage_usage: 10u64.pow(6),
            attached_deposit: 32900000000000000000000,
            prepaid_gas: 10u64.pow(18),
            random_seed: vec![0, 1, 2],
            is_view: false,
            output_data_receivers: vec![],
            epoch_height: 0,
        }
    }

    #[test]
    fn basic_create_market() {
        testing_env!(get_context(alice(), 0));

        let mut contract = AMMContract::init(
            bob().try_into().unwrap(),
            vec![collateral_whitelist::Token{account_id: token(), decimals: 24}]
        );

        contract.create_market(
            empty_string(), // market description
            empty_string(), // extra info
            2, // outcomes
            empty_string_vec(2), // outcome tags
            empty_string_vec(2), // categories
            1609951265967.into(), // end_time
            1619882574000.into(), // resolution_time (~1 day after end_time)
            token(), // collateral_token_id
            (10_u128.pow(24) / 50).into(), // swap fee, 2%
            None // is_scalar
        );
    }

    #[test]
    #[should_panic(expected = "ERR_MARKET_ENDED")]
    fn add_liquidity_after_resolution() {
        testing_env!(get_context(alice(), 0));

        let mut contract = AMMContract::init(
            bob().try_into().unwrap(),
            vec![collateral_whitelist::Token{account_id: token(), decimals: 24}]
        );

        let market_id = contract.create_market(
            empty_string(), // market description
            empty_string(), // extra info
            2, // outcomes
            empty_string_vec(2), // outcome tags
            empty_string_vec(2), // categories
            1609951265967.into(), // end_time
            1619882574000.into(), // resolution_time (~1 day after end_time)
            token(), // collateral_token_id
            (10_u128.pow(24) / 50).into(), // swap fee, 2%
            None // is_scalar
        );

        testing_env!(get_context(token(), ms_to_ns(1619882574000)));

        let add_liquidity_args = AddLiquidityArgs {
            market_id,
            weight_indication: Some(vec![U128(2), U128(1)])
        };

        contract.add_liquidity(
            &alice(), // sender
            10000000000000000000, // total_in
            add_liquidity_args
        );
    }

    #[test]
    #[should_panic(expected = "ERR_INVALID_RESOLUTION_TIME")]
    fn invalid_resolution_time() {
        testing_env!(get_context(alice(), 0));

        let mut contract = AMMContract::init(
            bob().try_into().unwrap(),
            vec![collateral_whitelist::Token{account_id: token(), decimals: 24}]
        );

        let market_id = contract.create_market(
            empty_string(), // market description
            empty_string(), // extra info
            2, // outcomes
            empty_string_vec(2), // outcome tags
            empty_string_vec(2), // categories
            1609951265967.into(), // end_time
            1609951265965.into(), // resolution_time (less than end_time for err)
            token(), // collateral_token_id
            (10_u128.pow(24) / 50).into(), // swap fee, 2%
            None // is_scalar
        );
    }

    #[test]
    #[should_panic(expected = "ERR_RESOLUTION_TIME_NOT_REACHED")]
    fn resolute_before_resolution_time() {
        testing_env!(get_context(alice(), 0));

        let mut contract = AMMContract::init(
            bob().try_into().unwrap(),
            vec![collateral_whitelist::Token{account_id: token(), decimals: 24}]
        );

        let market_id = contract.create_market(
            empty_string(), // market description
            empty_string(), // extra info
            2, // outcomes
            empty_string_vec(2), // outcome tags
            empty_string_vec(2), // categories
            1609951265967.into(), // end_time
            1619882574000.into(), // resolution_time (~1 day after end_time)
            token(), // collateral_token_id
            (10_u128.pow(24) / 50).into(), // swap fee, 2%
            None // is_scalar
        );

        testing_env!(get_context(token(), 0));

        let add_liquidity_args = AddLiquidityArgs {
            market_id,
            weight_indication: Some(vec![U128(2), U128(1)])
        };

        contract.add_liquidity(
            &alice(), // sender
            10000000000000000000, // total_in
            add_liquidity_args
        );

        testing_env!(get_context(bob(), 0));

        contract.resolute_market(
            market_id,
            Some(vec![U128(0), U128(1)]) // payout_numerator
        );
    }

}
