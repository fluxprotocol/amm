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

use oracle::{oracle_config::OracleConfig, ContractContract};
use token::TokenContractContract;
use amm::AMMContractContract;


const REGISTRY_STORAGE: u128 = 8_300_000_000_000_000_000_000;
const TOKEN_CONTRACT_ID: &str = "token";
const AMM_CONTRACT_ID: &str = "amm";
const ORACLE_CONTRACT_ID: &str = "oracle";

// Load in contract bytes
near_sdk_sim::lazy_static! {
    static ref ORACLE_WASM_BYTES: &'static [u8] = include_bytes!("../../../res/oracle.wasm").as_ref();
    static ref AMM_WASM_BYTES: &'static [u8] = include_bytes!("../../../res/amm.wasm").as_ref();
    static ref TOKEN_WASM_BYTES: &'static [u8] = include_bytes!("../../../res/token.wasm").as_ref();
}

pub struct InitRes {
    pub master_account: UserAccount,
    pub amm_contract: ContractAccount<AMMContractContract>,
    pub oracle_contract: ContractAccount<ContractContract>,
    pub token_account_id: AccountId,
    pub alice: UserAccount,
    pub bob: UserAccount,
    pub carol: UserAccount
}

pub fn init(
    gov_id: AccountId
) -> InitRes {
    let master_account = init_simulator(None);

    // deploy amm
    let amm_contract = deploy!(
        // Contract Proxy
        contract: AMMContractContract,
        // Contract account id
        contract_id: AMM_CONTRACT_ID,
        // Bytes of contract
        bytes: &AMM_WASM_BYTES,
        // User deploying the contract,
        signer_account: master_account,
        deposit: to_yocto("1000"),
        // init method
        init_method: init(
            gov_id.try_into().unwrap(),
            vec![amm::collateral_whitelist::Token{account_id: "token".to_string(), decimals: 24}]
        )
    );

    // deploy token
    let token_contract = deploy!(
        // Contract Proxy
        contract: TokenContractContract,
        // Contract account id
        contract_id: TOKEN_CONTRACT_ID,
        // Bytes of contract
        bytes: &TOKEN_WASM_BYTES,
        // User deploying the contract,
        signer_account: master_account,
        deposit: to_yocto("1000"),
        // init method
        init_method: new()
    );

    let config = OracleConfig {
        gov: "alice".to_string(),
        final_arbitrator: "alice".to_string(),
        bond_token: TOKEN_CONTRACT_ID.to_string(),
        stake_token: TOKEN_CONTRACT_ID.to_string(),
        validity_bond: U128(100),
        max_outcomes: 8,
        default_challenge_window_duration: U64(1000),
        min_initial_challenge_window_duration: U64(1000),
        final_arbitrator_invoke_amount: U128(250),
        resolution_fee_percentage: 10_000,
    };

    // deploy token
    let oracle_contract = deploy!(
        // Contract Proxy
        contract: ContractContract,
        // Contract account id
        contract_id: ORACLE_CONTRACT_ID,
        // Bytes of contract
        bytes: &ORACLE_WASM_BYTES,
        // User deploying the contract,
        signer_account: master_account,
        deposit: to_yocto("1000"),
        // init method
        init_method: new(Some(vec!["amm".to_string().try_into().expect("invalid acc id"), "alice".to_string().try_into().expect("invalid acc id")]), config)
    );

    let ft_storage_amount = get_storage_amount(&master_account);
    let oracle_storage_amount = 180000000000000000000000_u128;
    storage_deposit(TOKEN_CONTRACT_ID, &master_account, ft_storage_amount.into(), Some(AMM_CONTRACT_ID.to_string()));
    storage_deposit(ORACLE_CONTRACT_ID, &master_account, oracle_storage_amount, Some(AMM_CONTRACT_ID.to_string()));
    storage_deposit(TOKEN_CONTRACT_ID, &master_account, ft_storage_amount.into(), Some(ORACLE_CONTRACT_ID.to_string()));
    storage_deposit(ORACLE_CONTRACT_ID, &master_account, oracle_storage_amount, Some(ORACLE_CONTRACT_ID.to_string()));
    
    let alice = master_account.create_user("alice".to_string(), to_yocto("10000"));

    storage_deposit(TOKEN_CONTRACT_ID, &alice, ft_storage_amount.into(), None);
    storage_deposit(ORACLE_CONTRACT_ID, &alice, oracle_storage_amount, None);
    near_deposit(&alice, init_balance());
    let bob = master_account.create_user("bob".to_string(), to_yocto("10000"));

    storage_deposit(TOKEN_CONTRACT_ID, &bob, ft_storage_amount.into(), None);
    storage_deposit(ORACLE_CONTRACT_ID, &bob, oracle_storage_amount, None);
    near_deposit(&bob, init_balance());

    let carol = master_account.create_user("carol".to_string(), to_yocto("10000"));

    storage_deposit(TOKEN_CONTRACT_ID, &carol, ft_storage_amount.into(), None);
    storage_deposit(ORACLE_CONTRACT_ID, &carol, oracle_storage_amount, None);
    near_deposit(&carol, init_balance());

    InitRes {
        master_account: master_account, 
        amm_contract,
        oracle_contract,
        token_account_id: TOKEN_CONTRACT_ID.to_string(), 
        alice: alice, 
        bob: bob, 
        carol: carol
    }
}

pub fn get_storage_amount(sender: &UserAccount) -> U128 {
    sender.view(
        PendingContractTx::new(
            TOKEN_CONTRACT_ID, 
            "storage_minimum_balance", 
            json!({}), 
            true
        )
    ).unwrap_json()
}

pub fn token_denom() -> u128 {
    to_yocto("1")
}

pub fn init_balance() -> u128 {
    to_yocto("1000")
}

pub fn compose_add_liquidity_args(market_id: U64, weights: Option<Vec<U128>>) -> String{
    json!({
        "AddLiquidityArgs": {
            "market_id": market_id,
            "weight_indication": weights
        }
    }).to_string()
}

pub fn compose_buy_args(market_id: U64, outcome: u16, min_shares_out: U128) -> String{
    json!({
        "BuyArgs": {
            "market_id": market_id,
            "outcome_target": outcome,
            "min_shares_out": min_shares_out
        }
    }).to_string()
}

pub fn storage_deposit(receiver: &str, sender: &UserAccount, deposit: u128, to_register: Option<AccountId>) {
    let res = sender.call(
        PendingContractTx::new(
            receiver,
            "storage_deposit",
            json!({
                "account_id": to_register
            }),
            false
        ),
        deposit,
        DEFAULT_GAS
    );
    assert!(res.is_ok(), "storage deposit failed with res: {:?}", res);
}

pub fn near_deposit(sender: &UserAccount, deposit: u128) {
    let res = sender.call(
        PendingContractTx::new(
            TOKEN_CONTRACT_ID,
            "near_deposit",
            json!({}),
            false
        ),
        deposit,
        DEFAULT_GAS
    );
    assert!(res.is_ok(), "wnear deposit failed with res: {:?}", res);
}

pub fn dr_new(sender: &UserAccount) {
    let msg = json!({
        "NewDataRequest": {
            // 12 hour challenge period,
            "challenge_period": U64(2999),
            "settlement_time": U64(2999),
            "target_contract": "oracle".to_string(),
            "sources": [], 
            "description": "test description"
        }
    }).to_string();
    ft_transfer_call(sender, to_token_denom(100), msg, ORACLE_CONTRACT_ID.to_string());
}

pub fn ft_balance_of(sender: &UserAccount, account_id: &AccountId) -> U128 {
    sender.view(
        PendingContractTx::new(
            TOKEN_CONTRACT_ID, 
            "ft_balance_of", 
            json!({
                "account_id": account_id.to_string()
            }), 
            true
        )
    ).unwrap_json()
}

pub fn transfer_unsafe(
    sender: &UserAccount,
    receiver_id: &AccountId,
    amount: u128,
) {
    let res = sender.call(
        PendingContractTx::new(
            TOKEN_CONTRACT_ID, 
            "ft_transfer", 
            json!({
                "receiver_id": receiver_id,
                "amount": U128::from(amount),
                "memo": "".to_string()
            }), 
            true
        ),
        1,
        DEFAULT_GAS
    );

    assert!(res.is_ok(), "ft_transfer_call failed with res: {:?}", res);
}

pub fn ft_transfer_call(
    sender: &UserAccount, 
    amount: u128,
    msg: String,
    receiver: String
) -> ExecutionResult {
    let res = sender.call(
        PendingContractTx::new(
            TOKEN_CONTRACT_ID, 
            "ft_transfer_call", 
            json!({
                "receiver_id": receiver,
                "amount": U128::from(amount),
                "msg": msg,
                "memo": "".to_string()
            }), 
            true
        ),
        1,
        DEFAULT_GAS
    );

    assert!(res.is_ok(), "ft_transfer_call failed with res: {:?}", res);
    res
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

pub fn create_market(creator: &UserAccount, amm: &ContractAccount<AMMContractContract>, outcomes: u16, fee_opt: Option<U128>) -> ExecutionResult {
    let msg = json!({
        "args": {
            "description": "bla",
            "extra_info": "bla",
            "outcomes": outcomes,
            "outcome_tags": ["0", "1"],
            "categories": ["0"],
            "end_time": "1630137884716",
            "collateral_token_id": TOKEN_CONTRACT_ID,
            "swap_fee": fee_opt,
            "is_scalar": false
        },
        "function": "create_market"
    }).to_string();
    ft_transfer_call(creator, to_token_denom(100), msg, AMM_CONTRACT_ID.to_string())
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
