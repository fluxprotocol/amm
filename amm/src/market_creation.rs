use crate::*;
use near_sdk::{ PromiseResult, serde_json };
use near_sdk::serde::{ Serialize, Deserialize };
use crate::oracle::{ DataRequestArgs };

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
            Some(market_args.outcome_tags.clone())
        };

        let remaining_bond: u128 = bond_in - validity_bond;
        let create_promise = self.create_data_request(&bond_token, validity_bond, DataRequestArgs {
            description: format!("{} - {}", market_args.description, market_args.extra_info),
            outcomes,
            settlement_time: ms_to_ns(market_args.resolution_time.into()),
            tags: vec![market_id.0.to_string()],
            sources: market_args.sources,
            challenge_period: market_args.challenge_period,
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
