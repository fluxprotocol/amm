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
    fn ft_transfer(&mut self, receiver_id: AccountId, amount: U128, msg: Option<String>);
}

const GAS_BASE_TRANSFER: Gas = 5_000_000_000_000;

pub fn fungible_token_transfer(token_account_id: AccountId, receiver_id: AccountId, value: u128, msg: Option<String>) -> Promise {
    fungible_token::ft_transfer(
        receiver_id,
        U128(value),
        msg,

        // Near params
        &token_account_id,
        1,
        GAS_BASE_TRANSFER
    )
}