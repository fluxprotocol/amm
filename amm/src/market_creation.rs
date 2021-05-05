use crate::*;
use near_sdk::{ PromiseResult, serde_json };
use near_sdk::serde::{ Serialize, Deserialize };

#[ext_contract(ext_self)]
trait ProtocolResolver {
    fn proceed_blah() -> Promise;
    fn proceed_market_creation(&mut self, bond_token: AccountId, bond_in: Balance, args: msg_structs::CreateMarket) -> PromiseOrValue<u8>;
}

#[derive(Serialize, Deserialize)]
pub struct OracleConfig {
    pub bond_token: AccountId, // bond token from the oracle config
    pub validity_bond: U128 // validity bond amount
}


#[near_bindgen]
impl AMMContract {
    pub fn proceed_blah(&mut self) {
        assert_prev_promise_successful();

        env::log("Tralalala".as_bytes());
    }

    pub fn proceed_market_creation(&mut self, bond_token: AccountId, bond_in: Balance, args: msg_structs::CreateMarket) -> Promise {
        assert_self();
        assert_eq!(env::promise_results_count(), 1, "ERR_PROMISE_INVALID");
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

        assert_eq!(oracle_config.bond_token, bond_token, "ERR_INVALID_BOND_TOKEN");
        assert!(validity_bond < bond_in, "ERR_NOT_ENOUGH_BOND");

        // TODO: Create a delayed data request
        self.create_data_request(bond_token, validity_bond).then(
            ext_self::proceed_blah(&env::current_account_id(), 0, 3_000_000_000_000)
        )

        // TODO: We need a storage manager

        // Create market
        // self.create_market(args);

        // TODO: Refund what is left over of token
        // TODO: Refund storage

        // PromiseOrValue::Value(bond_in - validity_bond)
    }
}


impl AMMContract {
    pub fn create_market(&mut self, args: msg_structs::CreateMarket) {
        let end_time: u64 = args.end_time.into();
        let swap_fee: u128 = args.swap_fee.into();
        let market_id = self.markets.len();
        let token_decimals = self.collateral_whitelist.0.get(&args.collateral_token_id);

        assert!(token_decimals.is_some(), "ERR_INVALID_COLLATERAL");
        assert!(args.outcome_tags.len() as u16 == args.outcomes, "ERR_INVALID_TAG_LENGTH");
        assert!(end_time > ns_to_ms(env::block_timestamp()), "ERR_INVALID_END_TIME");
        let initial_storage = env::storage_usage();

        let pool = pool_factory::new_pool(
            market_id,
            args.outcomes,
            args.collateral_token_id,
            token_decimals.unwrap(),
            swap_fee
        );

        logger::log_pool(&pool);

        let market = Market {
            end_time: args.end_time.into(),
            pool,
            payout_numerator: None,
            finalized: false
        };

        logger::log_create_market(&market, args.description, args.extra_info, args.outcome_tags, args.categories, args.is_scalar);
        logger::log_market_status(&market);

        self.markets.push(&market);

        self.refund_storage(initial_storage, env::predecessor_account_id());
    }

    pub fn ft_create_market_callback(
        &mut self, 
        sender: &AccountId, 
        bond_in: Balance, 
        args: serde_json::Value,
        initial_storage_usage: StorageUsage, 
        initial_user_balance: Balance,
    ) -> Promise {
        self.assert_unpaused();

        // TODO: Check storage before starting the promise chain
        // Maybe also pre validate the args

        let parsed_args: msg_structs::CreateMarket = msg_structs::from_args(args);
        let bond_token_id = env::predecessor_account_id();

        // TODO: We should double check the transfering process
        // Need to investigate the refunding "Refund 1 from pulse.franklinwaller2.testnet to franklinwaller2.testnet"

        oracle::fetch_oracle_config("oracle.franklinwaller2.testnet")
            .then(ext_self::proceed_market_creation(bond_token_id, bond_in, parsed_args, &env::current_account_id(), 0, 50_000_000_000_000))
    }
}