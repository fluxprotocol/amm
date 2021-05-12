use near_sdk::{
    AccountId,
    Gas,
    Promise,
    json_types::{
        U128,
    },
    ext_contract,
};

#[ext_contract]
pub trait FungibleToken {
    fn ft_transfer_call(&mut self, receiver_id: AccountId, amount: U128, msg: String, memo: Option<String>);
}

const GAS_BASE_TRANSFER: Gas = 35_000_000_000_000;

pub fn fungible_token_transfer(token_account_id: AccountId, receiver_id: AccountId, value: u128, msg: String, gas: Option<Gas>) -> Promise {
    fungible_token::ft_transfer_call(
        receiver_id,
        U128(value),
        msg,
        None,
        // Near params
        &token_account_id,
        1,
        gas.unwrap_or(GAS_BASE_TRANSFER)
    )
}