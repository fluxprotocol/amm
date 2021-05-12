use crate::*;
use near_sdk::{ PromiseResult, serde_json };
use near_sdk::serde::{ Serialize, Deserialize };

#[ext_contract(ext_self)]
trait ProtocolResolver {
    fn proceed_market_creation_step2(market_args: CreateMarketArgs) -> Promise;
    fn proceed_market_creation(&mut self, bond_token: AccountId, bond_in: Balance, market_args: CreateMarketArgs) -> PromiseOrValue<u8>;
}

#[derive(Serialize, Deserialize)]
pub struct OracleConfig {
    pub bond_token: AccountId, // bond token from the oracle config
    pub validity_bond: U128 // validity bond amount
}


#[near_bindgen]
impl AMMContract {
    pub fn proceed_market_creation(&mut self, bond_token: AccountId, bond_in: Balance, market_args: CreateMarketArgs) -> Promise {
        assert_self();
        assert_eq!(env::promise_results_count(), 1, "ERR_PROMISE_INVALID");

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

        assert_eq!(oracle_config.bond_token, bond_token, "ERR_INVALID_BOND_TOKEN");
        assert!(validity_bond < bond_in, "ERR_NOT_ENOUGH_BOND");

        env::log(format!("Gas ug{} pg{} left{}", env::used_gas(), env::prepaid_gas(), env::prepaid_gas() - env::used_gas()).as_bytes());

        self.create_data_request(bond_token, validity_bond, &market_args)        
        .then(
            ext_self::proceed_market_creation_step2(market_args, &env::current_account_id(), 0, 25_000_000_000_000)
        )

        // TODO: We need a storage manager

        // Create market
        // self.create_market(payload);

        // TODO: Refund what is left over of token
        // TODO: Refund storage

        // PromiseOrValue::Value(bond_in - validity_bond)
    }

    pub fn proceed_market_creation_step2(&mut self, market_args: CreateMarketArgs) {
        assert_prev_promise_successful();

        env::log(format!("Gas ug{} pg{} left{}", env::used_gas(), env::prepaid_gas(), env::prepaid_gas() - env::used_gas()).as_bytes());
        self.create_market(market_args);
    }
}


impl AMMContract {
    pub fn create_market(&mut self, payload: CreateMarketArgs) -> U64 {
        self.assert_unpaused();
        let swap_fee: u128 = payload.swap_fee.into();
        let market_id = self.markets.len();
        let token_decimals = self.collateral_whitelist.0.get(&payload.collateral_token_id);

        let pool = pool_factory::new_pool(
            market_id,
            payload.outcomes,
            payload.collateral_token_id,
            token_decimals.unwrap(),
            swap_fee
        );

        logger::log_pool(&pool);

        let market = Market {
            end_time: payload.end_time.into(),
            resolution_time: payload.resolution_time.into(),
            pool,
            payout_numerator: None,
            finalized: false
        };

        logger::log_create_market(&market, payload.description, payload.extra_info, payload.outcome_tags, payload.categories, payload.is_scalar);
        logger::log_market_status(&market);

        self.markets.push(&market);

        (self.markets.len() - 1).into()
    }

    pub fn ft_create_market_callback(
        &mut self, 
        sender: &AccountId, 
        bond_in: Balance, 
        payload: CreateMarketArgs
    ) -> Promise {
        self.assert_unpaused();

        let end_time: u64 = payload.end_time.into();
        let resolution_time: u64 = payload.resolution_time.into();
        let token_decimals = self.collateral_whitelist.0.get(&payload.collateral_token_id);

        assert!(token_decimals.is_some(), "ERR_INVALID_COLLATERAL");
        assert!(payload.outcome_tags.len() as u16 == payload.outcomes, "ERR_INVALID_TAG_LENGTH");
        assert!(end_time > ns_to_ms(env::block_timestamp()), "ERR_INVALID_END_TIME");
        assert!(resolution_time >= end_time, "ERR_INVALID_RESOLUTION_TIME");

        // TODO: Check storage before starting the promise chain

        let bond_token_id = env::predecessor_account_id();

        // TODO: Use sender

        // TODO: We should double check the transfering process
        // Need to investigate the refunding "Refund 1 from pulse.franklinwaller2.testnet to franklinwaller2.testnet"

        oracle::fetch_oracle_config(&self.oracle)
            .then(ext_self::proceed_market_creation(bond_token_id, bond_in, payload, &env::current_account_id(), 0, 200_000_000_000_000))
    }
}