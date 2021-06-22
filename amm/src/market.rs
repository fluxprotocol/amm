use crate::*;

#[derive(BorshDeserialize, BorshSerialize)]
pub struct Market {
    pub end_time: Timestamp, // Time when trading is halted
    pub resolution_time: Timestamp, // Time when the market can be resoluted
    pub pool: Pool, // Implementation that manages the liquidity pool and swap
    pub outcome_tags: Vec<String>,
    pub payout_numerator: Option<Vec<U128>>, // Optional Vector that dictates how payout is done. Each payout numerator index corresponds to an outcome and shares the denomination of te collateral token for this market.
    pub finalized: bool, // If true the market has an outcome, if false the market it still undecided.
    pub enabled: bool, // If false the market is disabled for interaction.
    pub is_scalar: bool, // If true the market is scalar, false for categorical
    pub scalar_multiplier: Option<U128>, // multiplier used for float numbers
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
    pub fn get_pool_token_total_supply(&self, market_id: U64) -> WrappedBalance {
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
    ) -> Vec<WrappedBalance>{
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
        account_id: &AccountId
    ) -> WrappedBalance {
        let market = self.get_market_expect(market_id);
        U128(market.pool.get_pool_token_balance(account_id))
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
    ) -> WrappedBalance {
        let market = self.get_market_expect(market_id);
        market.pool.get_spot_price_sans_fee(outcome).into()
    }

    /**
     * @notice returns the current spot price of an outcome without taking a fee into account
     * @param market_id is the index of the market to retrieve data from
     * @param outcome is the outcome to get the current spot price fpr
     * @returns a wrapped price of the outcome at current state
     */
    pub fn get_spot_price(
        &self,
        market_id: U64,
        outcome: u16
    ) -> WrappedBalance {
        let market = self.get_market_expect(market_id);
        market.pool.get_spot_price(outcome).into()
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
        collateral_in: WrappedBalance,
        outcome_target: u16
    ) -> WrappedBalance {
        let market = self.get_market_expect(market_id);
        U128(market.pool.calc_buy_amount(collateral_in.into(), outcome_target))
    }

    /**
     * @notice calculates the amount of shares a user has to put in in order to get `collateral_out`
     * @param market_id is the index of the market to retrieve data from
     * @param collateral_out is the amount of collateral that a user wants to get out of a position, it's used to calculate the amount of `outcome_shares` that need to be transferred in
     * @param outcome_target is the outcome that the amount of shares a user wants to sell
     * @returns a wrapped number of `outcome_shares` a user would have to transfer in in order to get `collateral_out`
     */
    pub fn calc_sell_collateral_out(
        &self,
        market_id: U64,
        collateral_out: WrappedBalance,
        outcome_target: u16
    ) -> WrappedBalance {
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
    ) -> WrappedBalance {
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
    ) -> WrappedBalance {
        let market = self.get_market_expect(market_id);
        U128(market.pool.get_fees_withdrawable(account_id))
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
        collateral_out: WrappedBalance,
        outcome_target: u16,
        max_shares_in: WrappedBalance
    ) -> Promise {
        self.assert_unpaused();
        let initial_storage = env::storage_usage();
        let collateral_out: u128 = collateral_out.into();
        let mut market = self.markets.get(market_id.into()).expect("ERR_NO_MARKET");
        assert!(market.enabled, "ERR_DISABLED_MARKET");
        assert!(!market.finalized, "ERR_FINALIZED_MARKET");
        assert!(market.end_time > ns_to_ms(env::block_timestamp()), "ERR_MARKET_ENDED");
        let escrowed = market.pool.sell(
            &env::predecessor_account_id(),
            collateral_out,
            outcome_target,
            max_shares_in.into()
        );

        self.markets.replace(market_id.into(), &market);
        helper::refund_storage(initial_storage, env::predecessor_account_id());

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
        to_burn: WrappedBalance
    ) -> Promise {
        self.assert_unpaused();
        let initial_storage = env::storage_usage();

        let mut market = self.markets.get(market_id.into()).expect("ERR_NO_MARKET");
        assert!(market.enabled, "ERR_DISABLED_MARKET");
        assert!(!market.finalized, "ERR_MARKET_FINALIZED");

        let escrowed = market.pool.burn_outcome_tokens_redeem_collateral(
            &env::predecessor_account_id(),
            to_burn.into()
        );

        self.markets.replace(market_id.into(), &market);

        helper::refund_storage(initial_storage, env::predecessor_account_id());

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
        total_in: WrappedBalance,
    ) -> PromiseOrValue<bool> {
        self.assert_unpaused();
        let initial_storage = env::storage_usage();

        let mut market = self.markets.get(market_id.into()).expect("ERR_NO_MARKET");
        assert!(market.enabled, "ERR_DISABLED_MARKET");

        let fees_earned = market.pool.exit_pool(
            &env::predecessor_account_id(),
            total_in.into()
        );
        
        self.markets.replace(market_id.into(), &market);

        helper::refund_storage(initial_storage, env::predecessor_account_id());

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
        assert!(market.enabled, "ERR_DISABLED_MARKET");
        assert!(!market.finalized, "ERR_IS_FINALIZED");
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
        // helper::refund_storage(initial_storage, env::predecessor_account_id());

        logger::log_market_status(&market);
    }

    pub fn set_outcome(&mut self, requestor: AccountId, outcome: Outcome, tags: Option<Vec<U64>>) {
        self.assert_oracle();
        assert_eq!(requestor, env::current_account_id(), "ERR_WRONG_REQUESTOR");

        // First item in the tag is our market id as defined in market_creation.rs
        let parsed_tags = tags.unwrap();
        let market_id = parsed_tags.get(0).unwrap();
        let mut market = self.get_market_expect(*market_id);

        match outcome {
            Outcome::Answer(answer) => {
                if market.is_scalar {
                    let lower_bound: u128 = market.outcome_tags.get(0).unwrap().parse().unwrap();
                    let upper_bound: u128 = market.outcome_tags.get(1).unwrap().parse().unwrap();

                    let answer_number = match answer {
                        AnswerType::Number(number) => number,
                        AnswerType::String(_) => panic!("ERR_NUMBER_EXPECTED"),
                    };

                    // TODO: Support negative numbers 
                    assert!(!answer_number.negative, "ERR_NO_NEGATIVE_NUMBERS");

                    let pointer_value = clamp_u128(answer_number.value.into(), lower_bound, upper_bound);
                    let range = upper_bound - lower_bound;
                    // TODO: Discus whether we want to use the collateral denom as our base for decimals or our multiplier from the outcome
                    let percentage_upper_bound = math::complex_div_u128(market.pool.collateral_denomination, upper_bound - pointer_value, range);
                    let payout_short = math::complex_mul_u128(market.pool.collateral_denomination, percentage_upper_bound, market.pool.collateral_denomination);

                    market.payout_numerator = Some(vec![
                        U128(payout_short),
                        U128(market.pool.collateral_denomination - payout_short),
                    ]);
                } else {
                    let answer_string = match answer {
                        AnswerType::Number(_) => panic!("ERR_STRING_EXPECTED"),
                        AnswerType::String(str) => str,
                    };

                    // Categorical market where only 1 outcome can be the winner
                    let index = market.outcome_tags.iter().position(|tag| tag == &answer_string).expect("ERR_OUTCOME_NOT_IN_TAGS");
                    let mut payout_numerator = vec![U128(0); market.outcome_tags.len()];

                    payout_numerator[index] = U128(market.pool.collateral_denomination);
                    market.payout_numerator = Some(payout_numerator);
                }
            },
            Outcome::Invalid => market.payout_numerator = None,
        }

        market.finalized = true;
        self.markets.replace(market_id.0, &market);
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
        assert!(market.enabled, "ERR_DISABLED_MARKET");
        assert!(market.finalized, "ERR_NOT_FINALIZED");

        let payout = market.pool.payout(&env::predecessor_account_id(), &market.payout_numerator);
        self.markets.replace(market_id.into(), &market);

        helper::refund_storage(initial_storage, env::predecessor_account_id());

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
    ) -> PromiseOrValue<U128> {
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
        assert!(market.enabled, "ERR_DISABLED_MARKET");
        assert!(!market.finalized, "ERR_FINALIZED_MARKET");
        assert!(market.end_time > ns_to_ms(env::block_timestamp()), "ERR_MARKET_ENDED");
        assert_collateral_token(&market.pool.collateral_token_id);
        
        market.pool.add_liquidity(
            &sender,
            total_in,
            weights_u128
        );
        self.markets.replace(args.market_id.into(), &market);
        PromiseOrValue::Value(0.into())
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
    ) -> PromiseOrValue<U128> {
        let mut market = self.markets.get(args.market_id.into()).expect("ERR_NO_MARKET");
        assert!(market.enabled, "ERR_DISABLED_MARKET");
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
        PromiseOrValue::Value(0.into())
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[cfg(test)]
mod market_basic_tests {
    use std::convert::TryInto;
    use near_sdk::{ MockedBlockchain };
    use near_sdk::{ testing_env, VMContext };
    use super::*;

    fn alice() -> AccountId {
        "alice.near".to_string()
    }

    fn bob() -> AccountId {
        "bob.near".to_string()
    }

    fn token() -> AccountId {
        "token.near".to_string()
    }

    fn oracle() -> AccountId {
        "oracle.near".to_string()
    }

    fn empty_string() -> String {
        "".to_string()
    }

    fn empty_string_vec(len: u16) -> Vec<String> {
        let mut tags: Vec<String> = vec![];
        for _i in 0..len {
            tags.push(empty_string());
        }
        tags
    }

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
            attached_deposit: 33400000000000000000000,
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
            vec![collateral_whitelist::Token{account_id: token(), decimals: 24}],
            oracle().try_into().unwrap()
        );

        contract.create_market(
            &CreateMarketArgs {
                description: empty_string(), // market description
                extra_info: empty_string(), // extra info
                outcomes: 2, // outcomes
                outcome_tags: empty_string_vec(2), // outcome tags
                categories: empty_string_vec(2), // categories
                end_time: 1609951265967.into(), // end_time
                resolution_time: 1619882574000.into(), // resolution_time (~1 day after end_time)
                sources: vec![Source{end_point: "test".to_string(), source_path: "test".to_string()}],
                collateral_token_id: token(), // collateral_token_id
                swap_fee: (10_u128.pow(24) / 50).into(), // swap fee, 2%
                challenge_period: U64(1),
                is_scalar: false, // is_scalar,
                scalar_multiplier: None,
            }
        );
    }

    #[test]
    #[should_panic(expected = "ERR_MARKET_ENDED")]
    fn add_liquidity_after_resolution() {
        testing_env!(get_context(alice(), 0));

        let mut contract = AMMContract::init(
            bob().try_into().unwrap(),
            vec![collateral_whitelist::Token{account_id: token(), decimals: 24}],
            oracle().try_into().unwrap()
        );

        let market_id = contract.create_market(
            &CreateMarketArgs {
                description: empty_string(), // market description
                extra_info: empty_string(), // extra info
                outcomes: 2, // outcomes
                outcome_tags: empty_string_vec(2), // outcome tags
                categories: empty_string_vec(2), // categories
                sources: vec![Source{end_point: "test".to_string(), source_path: "test".to_string()}],
                end_time: 1609951265967.into(), // end_time
                resolution_time: 1619882574000.into(), // resolution_time (~1 day after end_time)
                collateral_token_id: token(), // collateral_token_id
                swap_fee: (10_u128.pow(24) / 50).into(), // swap fee, 2%
                challenge_period: U64(1),
                is_scalar: false, // is_scalar
                scalar_multiplier: None,
            }
        );

        let mut market = contract.get_market_expect(U64(0));
        market.enabled = true;
        contract.markets.replace(0, &market);

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
            vec![collateral_whitelist::Token{account_id: token(), decimals: 24}],
            oracle().try_into().unwrap()
        );

        contract.create_market(
            &CreateMarketArgs {
                description: empty_string(), // market description
                extra_info: empty_string(), // extra info
                outcomes: 2, // outcomes
                outcome_tags: empty_string_vec(2), // outcome tags
                categories: empty_string_vec(2), // categories
                end_time: 1609951265967.into(), // end_time
                sources: vec![Source{end_point: "test".to_string(), source_path: "test".to_string()}],
                resolution_time: 1609951265965.into(), // resolution_time (~1 day after end_time)
                collateral_token_id: token(), // collateral_token_id
                swap_fee: (10_u128.pow(24) / 50).into(), // swap fee, 2%
                challenge_period: U64(1),
                is_scalar: false, // is_scalar
                scalar_multiplier: None,
            }
        );
    }

    #[test]
    fn invalid_outcome() {
        testing_env!(get_context(oracle(), 0));

        let mut contract = AMMContract::init(
            bob().try_into().unwrap(),
            vec![collateral_whitelist::Token{account_id: token(), decimals: 24}],
            oracle().try_into().unwrap()
        );
        
        contract.create_market(
            &CreateMarketArgs {
                description: empty_string(), // market description
                extra_info: empty_string(), // extra info
                outcomes: 2, // outcomes
                outcome_tags: empty_string_vec(2), // outcome tags
                categories: empty_string_vec(2), // categories
                end_time: 1609951265967.into(), // end_time
                resolution_time: 1619882574000.into(), // resolution_time (~1 day after end_time)
                sources: vec![Source{end_point: "test".to_string(), source_path: "test".to_string()}],
                collateral_token_id: token(), // collateral_token_id
                swap_fee: (10_u128.pow(24) / 50).into(), // swap fee, 2%
                challenge_period: U64(1),
                is_scalar: false, // is_scalar,
                scalar_multiplier: None,
            }
        );

        contract.set_outcome(alice(), Outcome::Invalid, Some(vec![U64(0)]));

        let market = contract.get_market_expect(U64(0));

        assert!(market.finalized, "Market should be finalized");
        assert_eq!(market.payout_numerator, None, "Numerator should be None");
    }

    #[test]
    fn valid_categorical_outcome() {
        testing_env!(get_context(oracle(), 0));

        let mut contract = AMMContract::init(
            bob().try_into().unwrap(),
            vec![collateral_whitelist::Token{account_id: token(), decimals: 24}],
            oracle().try_into().unwrap()
        );
        
        contract.create_market(
            &CreateMarketArgs {
                description: empty_string(), // market description
                extra_info: empty_string(), // extra info
                outcomes: 2, // outcomes
                outcome_tags: vec!["YES".to_string(), "NO".to_string()], // outcome tags
                categories: empty_string_vec(2), // categories
                end_time: 1609951265967.into(), // end_time
                resolution_time: 1619882574000.into(), // resolution_time (~1 day after end_time)
                sources: vec![Source{end_point: "test".to_string(), source_path: "test".to_string()}],
                collateral_token_id: token(), // collateral_token_id
                swap_fee: (10_u128.pow(24) / 50).into(), // swap fee, 2%
                challenge_period: U64(1),
                is_scalar: false, // is_scalar,
                scalar_multiplier: None,
            }
        );

        contract.set_outcome(alice(), Outcome::Answer(AnswerType::String("NO".to_string())), Some(vec![U64(0)]));

        let market = contract.get_market_expect(U64(0));
        assert!(market.finalized, "Market should be finalized");
        assert_eq!(market.payout_numerator, Some(vec![U128(0), U128(1000000000000000000000000)]), "Numerator should be set");
    }

    #[test]
    fn valid_scalar_large_range() {
        testing_env!(get_context(oracle(), 0));

        let mut contract = AMMContract::init(
            bob().try_into().unwrap(),
            vec![collateral_whitelist::Token{account_id: token(), decimals: 24}],
            oracle().try_into().unwrap()
        );
        
        contract.create_market(
            &CreateMarketArgs {
                description: empty_string(), // market description
                extra_info: empty_string(), // extra info
                outcomes: 2, // outcomes
                outcome_tags: vec!["50000000000".to_string(), "150000000000".to_string()], // outcome tags
                categories: empty_string_vec(2), // categories
                end_time: 1609951265967.into(), // end_time
                resolution_time: 1619882574000.into(), // resolution_time (~1 day after end_time)
                sources: vec![Source{end_point: "test".to_string(), source_path: "test".to_string()}],
                collateral_token_id: token(), // collateral_token_id
                swap_fee: (10_u128.pow(24) / 50).into(), // swap fee, 2%
                challenge_period: U64(1),
                is_scalar: true, // is_scalar,
                scalar_multiplier: Some(U128(100000000000)),
            }
        );

        let answer_number = AnswerNumberType {
            multiplier: U128(100000000000),
            negative: false,
            value: U128(70369216342),
        };

        contract.set_outcome(alice(), Outcome::Answer(AnswerType::Number(answer_number)), Some(vec![U64(0)]));

        let market = contract.get_market_expect(U64(0));
        assert!(market.finalized, "Market should be finalized");
        assert_eq!(market.payout_numerator, Some(vec![U128(796307836580000000000000), U128(203692163420000000000000)]), "Numerator should be set");
    }

    #[test]
    fn valid_scalar_complex_floating_answer() {
        testing_env!(get_context(oracle(), 0));

        let mut contract = AMMContract::init(
            bob().try_into().unwrap(),
            vec![collateral_whitelist::Token{account_id: token(), decimals: 24}],
            oracle().try_into().unwrap()
        );
        
        contract.create_market(
            &CreateMarketArgs {
                description: empty_string(), // market description
                extra_info: empty_string(), // extra info
                outcomes: 2, // outcomes
                outcome_tags: vec!["0".to_string(), "1000".to_string()], // outcome tags
                categories: empty_string_vec(2), // categories
                end_time: 1609951265967.into(), // end_time
                resolution_time: 1619882574000.into(), // resolution_time (~1 day after end_time)
                sources: vec![Source{end_point: "test".to_string(), source_path: "test".to_string()}],
                collateral_token_id: token(), // collateral_token_id
                swap_fee: (10_u128.pow(24) / 50).into(), // swap fee, 2%
                challenge_period: U64(1),
                is_scalar: true, // is_scalar,
                scalar_multiplier: Some(U128(1000)),
            }
        );

        let answer_number = AnswerNumberType {
            multiplier: U128(1000),
            negative: false,
            value: U128(268),
        };

        contract.set_outcome(alice(), Outcome::Answer(AnswerType::Number(answer_number)), Some(vec![U64(0)]));

        let market = contract.get_market_expect(U64(0));
        assert!(market.finalized, "Market should be finalized");
        assert_eq!(market.payout_numerator, Some(vec![U128(732000000000000000000000), U128(268000000000000000000000)]), "Numerator should be set");
    }

    #[test]
    fn valid_scalar_floating_answer() {
        testing_env!(get_context(oracle(), 0));

        let mut contract = AMMContract::init(
            bob().try_into().unwrap(),
            vec![collateral_whitelist::Token{account_id: token(), decimals: 24}],
            oracle().try_into().unwrap()
        );
        
        contract.create_market(
            &CreateMarketArgs {
                description: empty_string(), // market description
                extra_info: empty_string(), // extra info
                outcomes: 2, // outcomes
                outcome_tags: vec!["0".to_string(), "500".to_string()], // outcome tags
                categories: empty_string_vec(2), // categories
                end_time: 1609951265967.into(), // end_time
                resolution_time: 1619882574000.into(), // resolution_time (~1 day after end_time)
                sources: vec![Source{end_point: "test".to_string(), source_path: "test".to_string()}],
                collateral_token_id: token(), // collateral_token_id
                swap_fee: (10_u128.pow(24) / 50).into(), // swap fee, 2%
                challenge_period: U64(1),
                is_scalar: true, // is_scalar,
                scalar_multiplier: Some(U128(100)),
            }
        );

        let answer_number = AnswerNumberType {
            multiplier: U128(100),
            negative: false,
            value: U128(250),
        };

        contract.set_outcome(alice(), Outcome::Answer(AnswerType::Number(answer_number)), Some(vec![U64(0)]));

        let market = contract.get_market_expect(U64(0));
        assert!(market.finalized, "Market should be finalized");
        assert_eq!(market.payout_numerator, Some(vec![U128(500000000000000000000000), U128(500000000000000000000000)]), "Numerator should be set");
    }

    #[test]
    fn valid_scalar_outcome_price_over_lower_bound() {
        testing_env!(get_context(oracle(), 0));

        let mut contract = AMMContract::init(
            bob().try_into().unwrap(),
            vec![collateral_whitelist::Token{account_id: token(), decimals: 24}],
            oracle().try_into().unwrap()
        );
        
        contract.create_market(
            &CreateMarketArgs {
                description: empty_string(), // market description
                extra_info: empty_string(), // extra info
                outcomes: 2, // outcomes
                outcome_tags: vec!["25".to_string(), "50".to_string()], // outcome tags
                categories: empty_string_vec(2), // categories
                end_time: 1609951265967.into(), // end_time
                resolution_time: 1619882574000.into(), // resolution_time (~1 day after end_time)
                sources: vec![Source{end_point: "test".to_string(), source_path: "test".to_string()}],
                collateral_token_id: token(), // collateral_token_id
                swap_fee: (10_u128.pow(24) / 50).into(), // swap fee, 2%
                challenge_period: U64(1),
                is_scalar: true, // is_scalar,
                scalar_multiplier: Some(U128(1)),
            }
        );

        let answer_number = AnswerNumberType {
            multiplier: U128(1),
            negative: false,
            value: U128(24),
        };

        contract.set_outcome(alice(), Outcome::Answer(AnswerType::Number(answer_number)), Some(vec![U64(0)]));

        let market = contract.get_market_expect(U64(0));
        assert!(market.finalized, "Market should be finalized");
        assert_eq!(market.payout_numerator, Some(vec![U128(1000000000000000000000000), U128(0)]), "Numerator should be set");
    }

    #[test]
    fn valid_scalar_outcome_price_over_upper_bound() {
        testing_env!(get_context(oracle(), 0));

        let mut contract = AMMContract::init(
            bob().try_into().unwrap(),
            vec![collateral_whitelist::Token{account_id: token(), decimals: 24}],
            oracle().try_into().unwrap()
        );
        
        contract.create_market(
            &CreateMarketArgs {
                description: empty_string(), // market description
                extra_info: empty_string(), // extra info
                outcomes: 2, // outcomes
                outcome_tags: vec!["0".to_string(), "50".to_string()], // outcome tags
                categories: empty_string_vec(2), // categories
                end_time: 1609951265967.into(), // end_time
                resolution_time: 1619882574000.into(), // resolution_time (~1 day after end_time)
                sources: vec![Source{end_point: "test".to_string(), source_path: "test".to_string()}],
                collateral_token_id: token(), // collateral_token_id
                swap_fee: (10_u128.pow(24) / 50).into(), // swap fee, 2%
                challenge_period: U64(1),
                is_scalar: true, // is_scalar,
                scalar_multiplier: Some(U128(1)),
            }
        );

        let answer_number = AnswerNumberType {
            multiplier: U128(1),
            negative: false,
            value: U128(55),
        };

        contract.set_outcome(alice(), Outcome::Answer(AnswerType::Number(answer_number)), Some(vec![U64(0)]));

        let market = contract.get_market_expect(U64(0));
        assert!(market.finalized, "Market should be finalized");
        assert_eq!(market.payout_numerator, Some(vec![U128(0), U128(1000000000000000000000000)]), "Numerator should be set");
    }

    // TODO: should be changed with oracle integration
    // #[test]
    // #[should_panic(expected = "ERR_RESOLUTION_TIME_NOT_REACHED")]
    // fn resolute_before_resolution_time() {
    //     testing_env!(get_context(alice(), 0));

    //     let mut contract = AMMContract::init(
    //         bob().try_into().unwrap(),
    //         vec![collateral_whitelist::Token{account_id: token(), decimals: 24}],
    //         oracle().try_into().unwrap()
    //     );

    //     let market_id = contract.create_market(
    //         &CreateMarketArgs {
    //             description: empty_string(), // market description
    //             extra_info: empty_string(), // extra info
    //             outcomes: 2, // outcomes
    //             outcome_tags: empty_string_vec(2), // outcome tags
    //             categories: empty_string_vec(2), // categories
    //             end_time: 1609951265967.into(), // end_time
    //             resolution_time: 1619882574000.into(), // resolution_time (~1 day after end_time)
    //             collateral_token_id: token(), // collateral_token_id
    //             swap_fee: (10_u128.pow(24) / 50).into(), // swap fee, 2%
    //             is_scalar: None // is_scalar
    //         }
    //     );

    //     testing_env!(get_context(token(), 0));

    //     let mut market = contract.get_market_expect(U64(0));
    //     market.enabled = true;
    //     contract.markets.replace(0, &market);

    //     let add_liquidity_args = AddLiquidityArgs {
    //         market_id,
    //         weight_indication: Some(vec![U128(2), U128(1)])
    //     };

    //     contract.add_liquidity(
    //         &alice(), // sender
    //         10000000000000000000, // total_in
    //         add_liquidity_args
    //     );

    //     testing_env!(get_context(bob(), 0));

    //     contract.resolute_market(
    //         market_id,
    //         Some(vec![U128(1000000000000000000000000), U128(0)]) // payout_numerator
    //     );
    // }

    #[test]
    fn resolute_after_resolution_time() {
        testing_env!(get_context(alice(), 0));

        let mut contract = AMMContract::init(
            bob().try_into().unwrap(),
            vec![collateral_whitelist::Token{account_id: token(), decimals: 24}],
            oracle().try_into().unwrap()
        );

        let market_id = contract.create_market(
            &CreateMarketArgs {
                description: empty_string(), // market description
                extra_info: empty_string(), // extra info
                sources: vec![Source{end_point: "test".to_string(), source_path: "test".to_string()}],
                outcomes: 2, // outcomes
                outcome_tags: empty_string_vec(2), // outcome tags
                categories: empty_string_vec(2), // categories
                end_time: 1609951265967.into(), // end_time
                resolution_time: 1619882574000.into(), // resolution_time (~1 day after end_time)
                collateral_token_id: token(), // collateral_token_id
                swap_fee: (10_u128.pow(24) / 50).into(), // swap fee, 2%
                challenge_period: U64(1),
                is_scalar: false, // is_scalar
                scalar_multiplier: None,
            }
        );

        testing_env!(get_context(token(), 0));

        let mut market = contract.get_market_expect(U64(0));
        market.enabled = true;
        contract.markets.replace(0, &market);

        let add_liquidity_args = AddLiquidityArgs {
            market_id,
            weight_indication: Some(vec![U128(2), U128(1)])
        };

        contract.add_liquidity(
            &alice(), // sender
            10000000000000000000, // total_in
            add_liquidity_args
        );

        testing_env!(get_context(bob(), ms_to_ns(1619882574000)));

        contract.resolute_market(
            market_id,
            Some(vec![U128(1000000000000000000000000), U128(0)]) // payout_numerator
        );
    }

}
