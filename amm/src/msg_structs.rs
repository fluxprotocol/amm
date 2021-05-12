use near_sdk::{
    json_types::{
        U128, 
        U64
    },
    AccountId,
    serde_json,
    serde_json::Value,
};

use near_sdk::serde::{
    Serialize, 
    Deserialize,
    de::{
        DeserializeOwned
    }
};

/**
 * @notice initial struct that's used to decide what function to call
 */
#[derive(Serialize, Deserialize)]
pub struct InitStruct {
    pub function: String, // which private function to call
    pub args: Value // json `Value` that corresponds to arguments expected by `function`
}

/**
 * @notice `add_liquidity` args
 */
#[derive(Serialize, Deserialize)]
pub struct AddLiquidity {
    pub market_id: U64, // id of the market to add liquidity to
    pub weight_indication: Option<Vec<U128>> // token weights that dictate the initial odd price distribution
}

/**
 * @notice `buy` args
 */
#[derive(Serialize, Deserialize)]
pub struct Buy {
    pub market_id: U64, // id of the market that shares are to be purchased from
    pub outcome_target: u16, // outcome that the sender buys shares in
    pub min_shares_out: U128 // the minimum amount of share tokens the user expects out, this is to prevent slippage
}

/**
 * @notice `create_market` args
 */
#[derive(Serialize, Deserialize)]
pub struct CreateMarket {
    pub description: String,
    pub extra_info: String,
    pub outcomes: u16,
    pub outcome_tags: Vec<String>,
    pub categories: Vec<String>,
    pub end_time: U64,
    pub collateral_token_id: AccountId,
    pub swap_fee: U128,
    pub is_scalar: Option<bool>,
}

/**
 * @notice parse json `Value` into generic function struct
 * @returns a generic type which will be a struct containing the args of a certain function
 */
pub fn from_args<T: DeserializeOwned>(args: Value) -> T {
    serde_json::from_value(args).expect("ERR_INVALID_ARGS")
}