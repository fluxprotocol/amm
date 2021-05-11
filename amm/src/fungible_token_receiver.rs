use crate::*;
use near_sdk::serde::{ Serialize, Deserialize };
use near_sdk::serde_json;
use crate::types::{ WrappedBalance };

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
    pub end_time: WrappedTimestamp, // Time when trading is halted
    pub resolution_time: WrappedTimestamp, // Time when resolution is possible
    pub collateral_token_id: AccountId, // `AccountId` of collateral that traded in the market
    pub swap_fee: U128, // Swap fee denominated as ration in same denomination as the collateral
    pub is_scalar: Option<bool>, // Wether market is scalar market or not
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
        let payload: Payload =  serde_json::from_str(&msg).expect("Failed to parse the payload, invalid `msg` format");

        match payload{
            Payload::BuyArgs(payload) => self.buy(&sender_id, amount, payload), 
            Payload::AddLiquidityArgs(payload) => self.add_liquidity(&sender_id, amount, payload),
            Payload::CreateMarketArgs(payload) => self.ft_create_market_callback(&sender_id, amount, payload).into()
        };

        0.into()
    }
}
