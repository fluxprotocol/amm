#![allow(clippy::needless_pass_by_value)]
use std::convert::TryInto;
use near_sdk::{
    PendingContractTx,
    AccountId,
    json_types::{
        U64,
        U128,
        ValidAccountId
    },
    serde_json::json,
    serde_json
};

use near_sdk_sim::{
    ExecutionResult,
    call,
    view,
    deploy, 
    init_simulator, 
    to_yocto, 
    ContractAccount, 
    UserAccount, 
    STORAGE_AMOUNT,
    DEFAULT_GAS
};

extern crate amm;

pub use amm::*;
use token::*;
use amm::protocol::ProtocolContract;

const REGISTRY_STORAGE: u128 = 8_300_000_000_000_000_000_000;
const TOKEN_CONTRACT_ID: &str = "token";
const AMM_CONTRACT_ID: &str = "amm";

// Load in contract bytes
near_sdk_sim::lazy_static_include::lazy_static_include_bytes! {
    AMM_WASM_BYTES => "../../../res/amm.wasm",
    TOKEN_WASM_BYTES => "../../../res/token.wasm",
}

pub fn init(
    gov_id: AccountId
) -> (UserAccount, UserAccount, AccountId, UserAccount, UserAccount, UserAccount) {
    let master_account = init_simulator(None);

    let amm_contract = master_account.deploy_and_init(
        &AMM_WASM_BYTES, 
        AMM_CONTRACT_ID.to_string(), 
        "init", 
        json!({
            "gov": gov_id.try_into().unwrap(),
            "tokens":  vec!["token".try_into().unwrap()],
            "decimals": [24],
        }).to_string().as_bytes(), 
        to_yocto("1000"), 
        DEFAULT_GAS
    );

    // // deploy amm
    // let amm_contract = master_account.deploy_and_init(
    //     // Contract Proxy
    //     contract: ProtocolContract,
    //     // Contract account id
    //     contract_id: AMM_CONTRACT_ID,
    //     // Bytes of contract
    //     bytes: &AMM_WASM_BYTES,
    //     // User deploying the contract,
    //     signer_account: master_account,
    //     deposit: to_yocto("1000"),
    //     // init method
    //     init_method: init(
    //         gov_id.try_into().unwrap(),
    //         vec!["token".try_into().unwrap()],
    //         vec![24]
    //     )
    // );

    let token_contract = master_account.deploy_and_init(
        &TOKEN_WASM_BYTES, 
        TOKEN_CONTRACT_ID.to_string(), 
        "new", 
        json!({}).to_string().as_bytes(), 
        to_yocto("1000"), 
        DEFAULT_GAS
    );

    // deploy token
    // let token_contract = master_account.deploy(
    //     // Contract Proxy
    //     contract: ContractContract,
    //     // Contract account id
    //     contract_id: TOKEN_CONTRACT_ID,
    //     // Bytes of contract
    //     bytes: &TOKEN_WASM_BYTES,
    //     // User deploying the contract,
    //     signer_account: master_account,
    //     deposit: to_yocto("1000"),
    //     // init method
    //     init_method: new()
    // );

    let storage_amount = get_storage_amount(&master_account);
    storage_deposit(&master_account, storage_amount.into(), Some(AMM_CONTRACT_ID.to_string()));
    
    let alice = master_account.create_user("alice".to_string(), to_yocto("10000"));
    storage_deposit(&alice, storage_amount.into(), None);
    near_deposit(&alice, init_balance());
    let bob = master_account.create_user("bob".to_string(), to_yocto("10000"));
    storage_deposit(&bob, storage_amount.into(), None);
    near_deposit(&bob, init_balance());
    let carol = master_account.create_user("carol".to_string(), to_yocto("10000"));
    storage_deposit(&carol, storage_amount.into(), None);
    near_deposit(&carol, init_balance());

    (master_account, amm_contract, TOKEN_CONTRACT_ID.to_string(), alice, bob, carol)
}

pub fn get_storage_amount(sender: &UserAccount) -> U128 {
    sender.view(
        TOKEN_CONTRACT_ID.to_string(), 
        "storage_minimum_balance", 
        json!({})
        .to_string()
        .as_bytes(), 
    ).unwrap_json()
}

pub fn token_denom() -> u128 {
    to_yocto("1")
}

pub fn init_balance() -> u128 {
    to_yocto("1000")
}

pub fn storage_deposit(sender: &UserAccount, deposit: u128, to_register: Option<AccountId>) {
    let res = sender.call(
        TOKEN_CONTRACT_ID.to_string(),
        "storage_deposit",
        json!({
            "account_id": to_register
        })
        .to_string()
        .as_bytes(),
        DEFAULT_GAS,
        deposit,
    );
    assert!(res.is_ok(), "storage deposit failed with res: {:?}", res);
}

pub fn near_deposit(sender: &UserAccount, deposit: u128) {
    let res = sender.call(
        TOKEN_CONTRACT_ID.to_string(),
        "near_deposit",
        json!({})
        .to_string()
        .as_bytes(),
        DEFAULT_GAS,
        deposit,
    );
    assert!(res.is_ok(), "wnear deposit failed with res: {:?}", res);
}

pub fn ft_balance_of(sender: &UserAccount, account_id: &AccountId) -> U128 {
    sender.view(
        TOKEN_CONTRACT_ID.to_string(), 
        "ft_balance_of", 
        json!({
            "account_id": account_id.to_string()
        })
        .to_string()
        .as_bytes(), 
    ).unwrap_json()
}

pub fn transfer_unsafe(
    sender: &UserAccount,
    receiver_id: &AccountId,
    amount: u128,
) {
    let res = sender.call(
        TOKEN_CONTRACT_ID.to_string(), 
        "ft_transfer", 
        json!({
            "receiver_id": receiver_id,
            "amount": U128::from(amount),
            "memo": "".to_string()
        })
        .to_string()
        .as_bytes(), 
            // true said it was view ??
        DEFAULT_GAS,
        1,
    );

    assert!(res.is_ok(), "ft_transfer_call failed with res: {:?}", res);
}
pub fn ft_transfer_call(
    sender: &UserAccount, 
    amount: u128,
    msg: String
) {
    let res = sender.call(
        TOKEN_CONTRACT_ID.to_string(), 
        "ft_transfer_call", 
        json!({
            "receiver_id": AMM_CONTRACT_ID.to_string(),
            "amount": U128::from(amount),
            "msg": msg,
            "memo": "".to_string()
        })
        .to_string()
        .as_bytes(), 
        // true
        DEFAULT_GAS,
        1,
    );

    assert!(res.is_ok(), "ft_transfer_call failed with res: {:?}", res);
}

pub fn empty_string() -> String { "".to_string() }

pub fn empty_string_vec(len: u16) -> Vec<String> { 
    let mut tags: Vec<String> = vec![];
    for i in 0..len {
        tags.push(empty_string());
    }
    
    tags
}

pub fn env_time() -> U64{ 
    1609951265967.into()
}
pub fn fee() -> U128 {
    (10_u128.pow(24) / 50).into() // 2%
}

pub fn create_market(creator: &UserAccount, amm: &ContractAccount<ProtocolContract>, outcomes: u16, fee_opt: Option<U128>) -> U64 {
    call!(
        creator,
        amm.create_market(empty_string(), empty_string(), outcomes, empty_string_vec(outcomes), empty_string_vec(2), env_time(), "token".to_string(), fee_opt.unwrap_or(fee()), None),
        deposit = STORAGE_AMOUNT
    ).unwrap_json()
}

pub fn to_token_denom(amt: u128) -> u128 {
    amt * 10_u128.pow(24)
}

pub fn swap_fee() -> U128 {
    U128(to_token_denom(2) / 100)
}

pub fn product_of(nums: &Vec<U128>) -> u128 {
    assert!(nums.len() > 1, "ERR_INVALID_NUMS");
    nums.iter().fold(token_denom(), |prod, &num| {
        let num_u128: u128 = num.into();
        math::complex_mul_u128(token_denom(), prod, num_u128)
    })
}

pub fn calc_weights_from_price(prices: Vec<U128>) -> Vec<U128> {
    let product = product_of(&prices);
    
    prices.iter().map(|price| {
       U128(math::complex_div_u128(token_denom(), u128::from(product), u128::from(*price)))
    }).collect()
}

pub fn unwrap_u128_vec(vec_in: &Vec<U128>) -> Vec<u128> {
    vec_in.iter().map(|n| { u128::from(*n) }).collect()
}

pub fn wrap_u128_vec(vec_in: &Vec<u128>) -> Vec<U128> {
    vec_in.iter().map(|n| { U128(*n) }).collect()
}