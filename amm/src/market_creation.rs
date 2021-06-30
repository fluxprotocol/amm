use crate::*;
use near_sdk::{ PromiseResult, serde_json };
use near_sdk::serde::{ Serialize, Deserialize };
use crate::oracle::{ DataRequestArgs, DataRequestDataType };
use crate::market::{ OutcomeTag, NumberOutcomeTag };
use crate::helper::flatten_outcome_tags;

#[ext_contract(ext_self)]
trait ProtocolResolver {
    fn proceed_market_enabling(market_id: U64) -> Promise;
    fn proceed_datarequest_creation(&mut self, sender: AccountId, bond_token: AccountId, bond_in: WrappedBalance, market_id: U64, market_args: CreateMarketArgs) -> Promise;
}

#[derive(Serialize, Deserialize)]
pub struct OracleConfig {
    pub bond_token: AccountId, // bond token from the oracle config
    pub validity_bond: U128 // validity bond amount
}

#[near_bindgen]
impl AMMContract {
    pub fn proceed_datarequest_creation(&mut self, sender: AccountId, bond_token: AccountId, bond_in: WrappedBalance, market_id: U64, market_args: CreateMarketArgs) -> Promise {
        assert_self();
        assert_prev_promise_successful();

        // Maybe we don't need to check. We could also assume that
        // the oracle promise handles the validation..
        let oracle_config = match env::promise_result(0) {
            PromiseResult::NotReady => unreachable!(),
            PromiseResult::Successful(value) => {
                match serde_json::from_slice::<OracleConfig>(&value) {
                    Ok(value) => value,
                    Err(_e) => panic!("ERR_INVALID_ORACLE_CONFIG"),
                }
            },
            PromiseResult::Failed => panic!("ERR_FAILED_ORACLE_CONFIG_FETCH"),
        };
        
        let validity_bond: u128 = oracle_config.validity_bond.into();
        let bond_in: u128 = bond_in.into();

        assert_eq!(oracle_config.bond_token, bond_token, "ERR_INVALID_BOND_TOKEN");
        assert!(validity_bond <= bond_in, "ERR_NOT_ENOUGH_BOND");

        let outcomes: Option<Vec<String>> = if market_args.is_scalar {
            None
        } else {
            Some(flatten_outcome_tags(&market_args.outcome_tags))
        };

        let data_type: DataRequestDataType = if market_args.is_scalar {
            DataRequestDataType::Number(market_args.scalar_multiplier.unwrap())
        } else {
            DataRequestDataType::String
        };

        let remaining_bond: u128 = bond_in - validity_bond;
        let create_promise = self.create_data_request(&bond_token, validity_bond, DataRequestArgs {
            description: format!("{} - {}", market_args.description, market_args.extra_info),
            outcomes,
            settlement_time: ms_to_ns(market_args.resolution_time.into()),
            tags: vec![market_id.0.to_string()],
            sources: market_args.sources,
            challenge_period: market_args.challenge_period,
            data_type,
            creator: sender.to_string(),
        });
        
        // Refund the remaining tokens
        if remaining_bond > 0 {
            create_promise
                .then(fungible_token::fungible_token_transfer(&bond_token, sender, remaining_bond))
                // We trigger the proceeding last so we can check the promise for failures
                .then(ext_self::proceed_market_enabling(market_id, &env::current_account_id(), 0, 25_000_000_000_000))
        } else {
            create_promise
                .then(ext_self::proceed_market_enabling(market_id, &env::current_account_id(), 0, 25_000_000_000_000))
        }
    }

    pub fn proceed_market_enabling(&mut self, market_id: U64) {
        assert_self();
        assert_prev_promise_successful();

        match env::promise_result(0) {
            PromiseResult::NotReady => unreachable!(),
            PromiseResult::Successful(value) => {
                match serde_json::from_slice::<U128>(&value) {
                    Ok(value) => assert_ne!(value.0, 0, "ERR_DATA_REQUEST_FAILED"),
                    Err(_e) => panic!("ERR_DATA_REQUEST_FAILED"),
                }
            },
            PromiseResult::Failed => panic!("ERR_DATA_REQUEST_FAILED"),
        };
        
        let mut market = self.get_market_expect(market_id);
        market.enabled = true;
        self.markets.replace(market_id.into(), &market);
        logger::log_market_status(&market);
    }
}


impl AMMContract {
    /**
     * @notice allows users to create new markets, can only be called internally
     * This function assumes the market data has been validated beforehand (ft_create_market_callback)
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
    pub fn create_market(&mut self, payload: &CreateMarketArgs) -> U64 {
        self.assert_unpaused();
        let swap_fee: u128 = payload.swap_fee.into();
        let market_id = self.markets.len();
        let token_decimals = self.collateral_whitelist.0.get(&payload.collateral_token_id);
        let end_time: u64 = payload.end_time.into();
        let resolution_time: u64 = payload.resolution_time.into();

        assert!(token_decimals.is_some(), "ERR_INVALID_COLLATERAL");
        assert!(payload.outcome_tags.len() as u16 == payload.outcomes, "ERR_INVALID_TAG_LENGTH");
        assert!(end_time > ns_to_ms(env::block_timestamp()), "ERR_INVALID_END_TIME");
        assert!(resolution_time >= end_time, "ERR_INVALID_RESOLUTION_TIME");

        if payload.is_scalar {
            assert!(payload.scalar_multiplier.is_some(), "ERR_NO_MULTIPLIER");
            assert!(payload.outcome_tags.len() == 2, "ERR_MAX_2_OUTCOMES");

            // Check if numbers are not a string and are in range
            let lower_bound_tag: &NumberOutcomeTag = match payload.outcome_tags.get(0).unwrap() {
                OutcomeTag::Number(num) => num,
                _ => panic!("ERR_NON_NUMBER"),
            };

            let upper_bound_tag: &NumberOutcomeTag = match payload.outcome_tags.get(1).unwrap() {
                OutcomeTag::Number(num) => num,
                _ => panic!("ERR_NON_NUMBER"),
            };

            let lower_bound: u128 = lower_bound_tag.value.into();
            let upper_bound: u128 = upper_bound_tag.value.into();

            assert!(!(lower_bound_tag.negative && lower_bound == 0), "ERR_NEGATIVE_ZERO");
            assert!(!(upper_bound_tag.negative && upper_bound == 0), "ERR_NEGATIVE_ZERO");

            // Make sure no negative zeros are used
            if !lower_bound_tag.negative && !upper_bound_tag.negative {
                assert!(lower_bound < upper_bound, "ERR_WRONG_BOUNDS");
            } else if !lower_bound_tag.negative && upper_bound_tag.negative {
                panic!("ERR_WRONG_BOUNDS");
            } else if lower_bound_tag.negative && upper_bound_tag.negative {
                assert!(lower_bound > upper_bound, "ERR_WRONG_BOUNDS");
            }
        }

        let pool = pool_factory::new_pool(
            market_id,
            payload.outcomes,
            payload.collateral_token_id.to_string(),
            token_decimals.unwrap(),
            swap_fee
        );

        logger::log_pool(&pool);

        let market = Market {
            end_time: payload.end_time.into(),
            resolution_time: payload.resolution_time.into(),
            pool,
            payout_numerator: None,
            finalized: false,
            // Disable this market until the oracle request has been made
            enabled: false,
            is_scalar: payload.is_scalar,
            outcome_tags: payload.outcome_tags.clone(),
            scalar_multiplier: payload.scalar_multiplier,
        };

        logger::log_create_market(&market, &payload.description, &payload.extra_info, &payload.categories);
        logger::log_market_status(&market);

        self.markets.push(&market);
        market_id.into()
    }

    pub fn ft_create_market_callback(
        &mut self, 
        sender: &AccountId, 
        bond_in: Balance, 
        payload: CreateMarketArgs
    ) -> Promise {
        self.assert_unpaused();
        let market_id = self.create_market(&payload);
        oracle::fetch_oracle_config(&self.oracle)
            .then(
                ext_self::proceed_datarequest_creation(
                sender.to_string(), 
                env::predecessor_account_id(), 
                U128(bond_in), 
                market_id,
                payload, 
                &env::current_account_id(), 
                0, 
                150_000_000_000_000
            )
        )
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

    fn empty_string_outcomes(len: u16) -> Vec<OutcomeTag> {
        let mut tags: Vec<OutcomeTag> = vec![];
        for _i in 0..len {
            tags.push(OutcomeTag::String(empty_string()));
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
    #[should_panic(expected = "ERR_MAX_2_OUTCOMES")]
    fn market_too_many_outcomes() {
        testing_env!(get_context(alice(), 0));

        let mut contract = AMMContract::init(
            bob().try_into().unwrap(),
            vec![collateral_whitelist::Token{account_id: token(), decimals: 24}],
            oracle().try_into().unwrap()
        );

        let tags = vec![
            OutcomeTag::Number(NumberOutcomeTag { value: U128(200), multiplier: U128(1), negative: false }),
            OutcomeTag::Number(NumberOutcomeTag { value: U128(300), multiplier: U128(1), negative: false }),
            OutcomeTag::Number(NumberOutcomeTag { value: U128(400), multiplier: U128(1), negative: false }),
        ];

        contract.create_market(
            &CreateMarketArgs {
                description: empty_string(), // market description
                extra_info: empty_string(), // extra info
                outcomes: 3, // outcomes
                outcome_tags: tags, // outcome tags
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
    }

    #[test]
    #[should_panic(expected = "ERR_NEGATIVE_ZERO")]
    fn market_negative_zero_upper_bound() {
        testing_env!(get_context(alice(), 0));

        let mut contract = AMMContract::init(
            bob().try_into().unwrap(),
            vec![collateral_whitelist::Token{account_id: token(), decimals: 24}],
            oracle().try_into().unwrap()
        );

        let tags = vec![
            OutcomeTag::Number(NumberOutcomeTag { value: U128(1), multiplier: U128(1), negative: true }),
            OutcomeTag::Number(NumberOutcomeTag { value: U128(0), multiplier: U128(1), negative: true }),
        ];

        contract.create_market(
            &CreateMarketArgs {
                description: empty_string(), // market description
                extra_info: empty_string(), // extra info
                outcomes: 2, // outcomes
                outcome_tags: tags, // outcome tags
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
    }

    #[test]
    #[should_panic(expected = "ERR_NEGATIVE_ZERO")]
    fn market_negative_zero_lower_bound() {
        testing_env!(get_context(alice(), 0));

        let mut contract = AMMContract::init(
            bob().try_into().unwrap(),
            vec![collateral_whitelist::Token{account_id: token(), decimals: 24}],
            oracle().try_into().unwrap()
        );

        let tags = vec![
            OutcomeTag::Number(NumberOutcomeTag { value: U128(0), multiplier: U128(1), negative: true }),
            OutcomeTag::Number(NumberOutcomeTag { value: U128(10), multiplier: U128(1), negative: false }),
        ];

        contract.create_market(
            &CreateMarketArgs {
                description: empty_string(), // market description
                extra_info: empty_string(), // extra info
                outcomes: 2, // outcomes
                outcome_tags: tags, // outcome tags
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
    }

    #[test]
    #[should_panic(expected = "ERR_NON_NUMBER")]
    fn market_wrong_outcome_type() {
        testing_env!(get_context(alice(), 0));

        let mut contract = AMMContract::init(
            bob().try_into().unwrap(),
            vec![collateral_whitelist::Token{account_id: token(), decimals: 24}],
            oracle().try_into().unwrap()
        );

        let tags = vec![
            OutcomeTag::Number(NumberOutcomeTag { value: U128(200), multiplier: U128(1), negative: false }),
            OutcomeTag::String("test".to_string())
        ];

        contract.create_market(
            &CreateMarketArgs {
                description: empty_string(), // market description
                extra_info: empty_string(), // extra info
                outcomes: 2, // outcomes
                outcome_tags: tags, // outcome tags
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
    }

    #[test]
    #[should_panic(expected = "ERR_WRONG_BOUNDS")]
    fn create_scalar_market_out_of_bounds() {
        testing_env!(get_context(alice(), 0));

        let mut contract = AMMContract::init(
            bob().try_into().unwrap(),
            vec![collateral_whitelist::Token{account_id: token(), decimals: 24}],
            oracle().try_into().unwrap()
        );

        let tags = vec![
            OutcomeTag::Number(NumberOutcomeTag { value: U128(200), multiplier: U128(1), negative: false }),
            OutcomeTag::Number(NumberOutcomeTag { value: U128(100), multiplier: U128(1), negative: false })
        ];

        contract.create_market(
            &CreateMarketArgs {
                description: empty_string(), // market description
                extra_info: empty_string(), // extra info
                outcomes: 2, // outcomes
                outcome_tags: tags, // outcome tags
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
    }

    #[test]
    #[should_panic(expected = "ERR_WRONG_BOUNDS")]
    fn market_out_of_bounds_upper_bound_is_negative() {
        testing_env!(get_context(alice(), 0));

        let mut contract = AMMContract::init(
            bob().try_into().unwrap(),
            vec![collateral_whitelist::Token{account_id: token(), decimals: 24}],
            oracle().try_into().unwrap()
        );

        let tags = vec![
            OutcomeTag::Number(NumberOutcomeTag { value: U128(200), multiplier: U128(1), negative: false }),
            OutcomeTag::Number(NumberOutcomeTag { value: U128(100), multiplier: U128(1), negative: true })
        ];

        contract.create_market(
            &CreateMarketArgs {
                description: empty_string(), // market description
                extra_info: empty_string(), // extra info
                outcomes: 2, // outcomes
                outcome_tags: tags, // outcome tags
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
    }

    #[test]
    #[should_panic(expected = "ERR_WRONG_BOUNDS")]
    fn market_out_of_bounds_upper_and_lower_bound_is_negative() {
        testing_env!(get_context(alice(), 0));

        let mut contract = AMMContract::init(
            bob().try_into().unwrap(),
            vec![collateral_whitelist::Token{account_id: token(), decimals: 24}],
            oracle().try_into().unwrap()
        );

        let tags = vec![
            OutcomeTag::Number(NumberOutcomeTag { value: U128(100), multiplier: U128(1), negative: true }),
            OutcomeTag::Number(NumberOutcomeTag { value: U128(200), multiplier: U128(1), negative: true })
        ];

        contract.create_market(
            &CreateMarketArgs {
                description: empty_string(), // market description
                extra_info: empty_string(), // extra info
                outcomes: 2, // outcomes
                outcome_tags: tags, // outcome tags
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
    }

    #[test]
    #[should_panic(expected = "ERR_WRONG_BOUNDS")]
    fn market_out_of_bounds_upper_and_lower_bound_is_same_negative() {
        testing_env!(get_context(alice(), 0));

        let mut contract = AMMContract::init(
            bob().try_into().unwrap(),
            vec![collateral_whitelist::Token{account_id: token(), decimals: 24}],
            oracle().try_into().unwrap()
        );

        let tags = vec![
            OutcomeTag::Number(NumberOutcomeTag { value: U128(100), multiplier: U128(1), negative: true }),
            OutcomeTag::Number(NumberOutcomeTag { value: U128(100), multiplier: U128(1), negative: true })
        ];

        contract.create_market(
            &CreateMarketArgs {
                description: empty_string(), // market description
                extra_info: empty_string(), // extra info
                outcomes: 2, // outcomes
                outcome_tags: tags, // outcome tags
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
    }

    #[test]
    #[should_panic(expected = "ERR_WRONG_BOUNDS")]
    fn market_out_of_bounds_upper_and_lower_bound_is_same_positive() {
        testing_env!(get_context(alice(), 0));

        let mut contract = AMMContract::init(
            bob().try_into().unwrap(),
            vec![collateral_whitelist::Token{account_id: token(), decimals: 24}],
            oracle().try_into().unwrap()
        );

        let tags = vec![
            OutcomeTag::Number(NumberOutcomeTag { value: U128(100), multiplier: U128(1), negative: false }),
            OutcomeTag::Number(NumberOutcomeTag { value: U128(100), multiplier: U128(1), negative: false })
        ];

        contract.create_market(
            &CreateMarketArgs {
                description: empty_string(), // market description
                extra_info: empty_string(), // extra info
                outcomes: 2, // outcomes
                outcome_tags: tags, // outcome tags
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
    }

    #[test]
    fn valid_positive_market() {
        testing_env!(get_context(alice(), 0));

        let mut contract = AMMContract::init(
            bob().try_into().unwrap(),
            vec![collateral_whitelist::Token{account_id: token(), decimals: 24}],
            oracle().try_into().unwrap()
        );

        let tags = vec![
            OutcomeTag::Number(NumberOutcomeTag { value: U128(50), multiplier: U128(1), negative: false }),
            OutcomeTag::Number(NumberOutcomeTag { value: U128(100), multiplier: U128(1), negative: false })
        ];

        contract.create_market(
            &CreateMarketArgs {
                description: empty_string(), // market description
                extra_info: empty_string(), // extra info
                outcomes: 2, // outcomes
                outcome_tags: tags, // outcome tags
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
    }

    #[test]
    fn valid_negative_market() {
        testing_env!(get_context(alice(), 0));

        let mut contract = AMMContract::init(
            bob().try_into().unwrap(),
            vec![collateral_whitelist::Token{account_id: token(), decimals: 24}],
            oracle().try_into().unwrap()
        );

        let tags = vec![
            OutcomeTag::Number(NumberOutcomeTag { value: U128(100), multiplier: U128(1), negative: true }),
            OutcomeTag::Number(NumberOutcomeTag { value: U128(50), multiplier: U128(1), negative: true })
        ];

        contract.create_market(
            &CreateMarketArgs {
                description: empty_string(), // market description
                extra_info: empty_string(), // extra info
                outcomes: 2, // outcomes
                outcome_tags: tags, // outcome tags
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
    }

    #[test]
    fn valid_half_negative_market() {
        testing_env!(get_context(alice(), 0));

        let mut contract = AMMContract::init(
            bob().try_into().unwrap(),
            vec![collateral_whitelist::Token{account_id: token(), decimals: 24}],
            oracle().try_into().unwrap()
        );

        let tags = vec![
            OutcomeTag::Number(NumberOutcomeTag { value: U128(100), multiplier: U128(1), negative: true }),
            OutcomeTag::Number(NumberOutcomeTag { value: U128(50), multiplier: U128(1), negative: false })
        ];

        contract.create_market(
            &CreateMarketArgs {
                description: empty_string(), // market description
                extra_info: empty_string(), // extra info
                outcomes: 2, // outcomes
                outcome_tags: tags, // outcome tags
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
    }
}