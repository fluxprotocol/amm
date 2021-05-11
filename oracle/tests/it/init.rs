// #![allow(clippy::unused_imports)]

// use near_sdk_sim::{
//     ExecutionResult,
//     call,
//     view,
//     deploy, 
//     init_simulator, 
//     to_yocto, 
//     ContractAccount, 
//     UserAccount, 
//     STORAGE_AMOUNT,
//     DEFAULT_GAS
// };

// // extern crate oracle;
// // use oracle::*;
// use token::*;

// pub const TOKEN_CONTRACT_ID: &str = "token";
// pub const ORACLE_CONTRACT_ID: &str = "oracle";

// // Load in contract bytes
// near_sdk_sim::lazy_static! {
//     static ref ORACLE_WASM_BYTES: &'static [u8] = include_bytes!("./wasm/oracle.wasm").as_ref();
//     static ref TOKEN_WASM_BYTES: &'static [u8] = include_bytes!("./wasm/token.wasm").as_ref();
// }

// pub fn init_balance() -> u128 {
//     to_yocto("1000")
// }

// pub fn init() {
//     // let master_account = init_simulator(None);
//     // let storage_amount = get_storage_amount(&master_account);

//     // let alice = master_account.create_user("alice".to_string(), to_yocto("10000"));
//     // storage_deposit(&alice, storage_amount.into(), None);

//     // let bob = master_account.create_user("bob".to_string(), to_yocto("10000"));
//     // storage_deposit(&bob, storage_amount.into(), None);

//     // let carol = master_account.create_user("carol".to_string(), to_yocto("10000"));
//     // storage_deposit(&carol, storage_amount.into(), None);

//     // deploy token
//     // let token_contract = deploy!(
//     //     contract: Contract,
//     //     contract_id: TOKEN_CONTRACT_ID,
//     //     bytes: &TOKEN_WASM_BYTES,
//     //     signer_account: master_account,
//     //     deposit: to_yocto("1000"),
//     //     init_method: new_default_meta("alice", 1_000_000_000_000_000)
//     // );
// }