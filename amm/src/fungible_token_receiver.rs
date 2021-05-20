use crate::*;
use near_sdk::serde::{ Serialize, Deserialize };
use near_sdk::serde_json;
use crate::types::{ WrappedBalance };
use storage_manager::{ STORAGE_PRICE_PER_BYTE };

/**
 * @notice `create_market` args
 */
#[derive(Serialize, Deserialize)]
pub struct CreateMarketArgs {
    pub description: String, // Description of market
    pub extra_info: String, // Details that help with market resolution
    pub outcomes: u16, // Number of possible outcomes for the market
    pub outcome_tags: Vec<String>, // Tags describing outcomes
    pub categories: Vec<String>, // Categories for filtering and curation
    pub challenge_period: U64,
    pub end_time: WrappedTimestamp, // Time when trading is halted
    pub resolution_time: WrappedTimestamp, // Time when resolution is possible
    pub collateral_token_id: AccountId, // `AccountId` of collateral that traded in the market
    pub swap_fee: U128, // Swap fee denominated as ration in same denomination as the collateral
    pub is_scalar: bool, // Wether market is scalar market or not
}

/**
 * @notice `add_liquidity` args
 */
#[derive(Serialize, Deserialize)]
pub struct AddLiquidityArgs {
    pub market_id: U64, // id of the market to add liquidity to
    pub weight_indication: Option<Vec<U128>> // token weights that dictate the initial odd price distribution
}

/**
 * @notice `buy` args
 */
#[derive(Serialize, Deserialize)]
pub struct BuyArgs {
    pub market_id: U64, // id of the market that shares are to be purchased from
    pub outcome_target: u16, // outcome that the sender buys shares in
    pub min_shares_out: WrappedBalance // the minimum amount of share tokens the user expects out, this is to prevent slippage
}

#[derive(Serialize, Deserialize)]
pub enum Payload {
    BuyArgs(BuyArgs),
    AddLiquidityArgs(AddLiquidityArgs),
    CreateMarketArgs(CreateMarketArgs)
}

pub trait FungibleTokenReceiver {
    // @returns amount of unused tokens
    fn ft_on_transfer(&mut self, sender_id: AccountId, amount: WrappedBalance, msg: String) -> WrappedBalance;
}

#[near_bindgen]
impl FungibleTokenReceiver for AMMContract {
    /**
     * @notice a callback function only callable by the collateral token for this market
     * @param sender_id the sender of the original transaction
     * @param amount of tokens attached to this callback call
     * @param msg can be a string of any type, in this case we expect a stringified json object
     * @returns the amount of tokens that were not spent
     */
    #[payable]
    fn ft_on_transfer(
        &mut self,
        sender_id: AccountId,
        amount: WrappedBalance,
        msg: String,
    ) -> WrappedBalance {
        self.assert_unpaused();

        let amount: u128 = amount.into();
        assert!(amount > 0, "ERR_ZERO_AMOUNT");
        let initial_storage_usage = env::storage_usage();
        let account = self.get_storage_account(&sender_id);

        let payload: Payload = serde_json::from_str(&msg).expect("Failed to parse the payload, invalid `msg` format");
        match payload {
            Payload::BuyArgs(payload) => self.buy(&sender_id, amount, payload), 
            Payload::AddLiquidityArgs(payload) => self.add_liquidity(&sender_id, amount, payload),
            Payload::CreateMarketArgs(payload) => self.ft_create_market_callback(&sender_id, amount, payload).into()
        };

        self.use_storage(&sender_id, initial_storage_usage, account.available);

        0.into()
    }
}

#[cfg(not(target_arch = "wasm32"))]
#[cfg(test)]
mod mock_token_basic_tests {
    use super::*;
    use std::convert::TryInto;

    use near_sdk::{ MockedBlockchain };
    use near_sdk::{ testing_env, VMContext };
    use crate::storage_manager::StorageManager;

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
        for i in 0..len {
            tags.push(empty_string());
        }
        tags
    }

    fn to_valid(account: AccountId) -> ValidAccountId {
        account.try_into().expect("invalid account")
    }

    fn get_context(predecessor_account_id: AccountId) -> VMContext {
        VMContext {
            current_account_id: token(),
            signer_account_id: bob(),
            signer_account_pk: vec![0, 1, 2],
            predecessor_account_id,
            input: vec![],
            block_index: 0,
            block_timestamp: 0,
            account_balance: 1000 * 10u128.pow(24),
            account_locked_balance: 0,
            storage_usage: 10u64.pow(6),
            attached_deposit: 1000 * 10u128.pow(24),
            prepaid_gas: 10u64.pow(18),
            random_seed: vec![0, 1, 2],
            is_view: false,
            output_data_receivers: vec![],
            epoch_height: 0,
        }
    }

    #[test]
    #[should_panic(expected = "attempt to subtract with overflow")]
    fn transfer_storage_no_funds() {
        testing_env!(get_context(token()));
        let mut contract = AMMContract::init(
            bob().try_into().unwrap(),
            vec![collateral_whitelist::Token{account_id: token(), decimals: 24}],
            oracle().try_into().unwrap()
        );

        contract.create_market(
            &CreateMarketArgs {
                description: empty_string(),
                extra_info: empty_string(),
                outcomes: 2,
                outcome_tags: empty_string_vec(2),
                categories: empty_string_vec(2),
                end_time: 1609951265967.into(),
                resolution_time: 1619882574000.into(), // (~1 day after end_time)
                collateral_token_id: token(),
                swap_fee: (10_u128.pow(24) / 50).into(), // 2%
                challenge_period: U64(1),
                is_scalar: false
            }
        );

        let msg = serde_json::json!({
            "AddLiquidityArgs": {
                "market_id": "0",
                "weight_indication": Some(vec![U128(2), U128(1)])
            }
        });
        contract.ft_on_transfer(alice(), U128(10000000000000000000), msg.to_string());
    }

    #[test]
    fn transfer_storage_funds() {
        testing_env!(get_context(token()));
        let mut contract = AMMContract::init(
            bob().try_into().unwrap(),
            vec![collateral_whitelist::Token{account_id: token(), decimals: 24}],
            oracle().try_into().unwrap()
        );

        contract.create_market(
            &&CreateMarketArgs {
                description: empty_string(),
                extra_info: empty_string(),
                outcomes: 2,
                outcome_tags: empty_string_vec(2),
                categories: empty_string_vec(2),
                end_time: 1609951265967.into(),
                resolution_time: 1619882574000.into(), // (~1 day after end_time)
                collateral_token_id: token(),
                swap_fee: (10_u128.pow(24) / 50).into(), // 2%
                challenge_period: U64(1),
                is_scalar: false
            }
        );

        let storage_start = 10u128.pow(24);

        let mut c : VMContext = get_context(alice());
        c.attached_deposit = storage_start;
        testing_env!(c);
        contract.storage_deposit(Some(to_valid(alice())));

        testing_env!(get_context(token()));
        let msg = serde_json::json!({
            "AddLiquidityArgs": {
                "market_id": "0",
                "weight_indication": Some(vec![U128(2), U128(1)])
            }
        });
        contract.ft_on_transfer(alice(), U128(10000000000000000000), msg.to_string());

        let b = contract.accounts.get(&alice());
        // assert!(b.unwrap() < storage_start); // TODO
    }
}
