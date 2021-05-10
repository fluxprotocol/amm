use crate::*;
use near_sdk::serde::{ Serialize, Deserialize };
use near_sdk::serde_json;
use crate::types::{ WrappedBalance };

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
    AddLiquidityArgs(AddLiquidityArgs)
}

pub trait FungibleTokenReceiver {
    // @returns amount of unused tokens
    fn ft_on_transfer(&mut self, sender_id: AccountId, amount: WrappedBalance, msg: String) -> U128;
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
            Payload::AddLiquidityArgs(payload) => self.add_liquidity(&sender_id, amount, payload)
        };

        0.into()
    }
}
