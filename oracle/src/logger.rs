use near_sdk::{
    env,
    AccountId,
    Balance,
	json_types::{
        U64,
        U128,
    },
    serde_json::json,
};

use crate::{ 
    data_request::{
        DataRequest,
        ResolutionWindow,
        Outcome,
    },
    oracle_config::{
        OracleConfig
    },
    helpers::{
        ns_to_ms,
    }
};

pub fn log_new_data_request(request: &DataRequest) {
    env::log(
        json!({
            "type": "data_requests",
            "action": "update",
            "cap_id": format!("dr_{}", request.id),
            "params": {
                "id": U64(request.id),
                "sources": request.sources,
                "outcomes": request.outcomes,
                "requestor": request.requestor.0,
                "finalized_outcome": request.finalized_outcome,
                "initial_challenge_period": U64(request.initial_challenge_period),
                "settlement_time": U64(request.settlement_time),
                "final_arbitrator_triggered": request.final_arbitrator_triggered,
                "target_contract": request.target_contract.0,
                "global_config_id": U64(request.global_config_id),

                "date": U64(ns_to_ms(env::block_timestamp())),
                "block_height": U64(env::block_index()),
            }
        })
        .to_string()
        .as_bytes()
    );
}

pub fn log_update_data_request(request: &DataRequest) {
    env::log(
        json!({
            "type": "data_requests",
            "action": "update",
            "cap_id": format!("dr_{}", request.id),
            "params": {
                "id": U64(request.id),
                "sources": request.sources,
                "outcomes": request.outcomes,
                "requestor": request.requestor.0,
                "finalized_outcome": request.finalized_outcome,
                "initial_challenge_period": U64(request.initial_challenge_period),
                "settlement_time": U64(request.settlement_time),
                "final_arbitrator_triggered": request.final_arbitrator_triggered,
                "target_contract": request.target_contract.0,
            }
        })
        .to_string()
        .as_bytes()
    );
}

pub fn log_oracle_config(config: &OracleConfig, id: u64) {
    env::log(
        json!({
            "type": "oracle_configs",
            "action": "update",
            "cap_id": format!("oc_{}", id),
            "params": {
                "id": U64(id),
                "gov": config.gov,
                "final_arbitrator": config.final_arbitrator,
                "stake_token": config.stake_token,
                "bond_token": config.bond_token,
                "validity_bond": config.validity_bond,
                "max_outcomes": config.max_outcomes,
                "default_challenge_window_duration": U64(config.default_challenge_window_duration),
                "min_initial_challenge_window_duration": U64(config.min_initial_challenge_window_duration),
                "final_arbitrator_invoke_amount": config.final_arbitrator_invoke_amount,
                "resolution_fee_percentage": config.resolution_fee_percentage,
                
                "date": U64(ns_to_ms(env::block_timestamp())),
                "block_height": U64(env::block_index()),
            }
        })
        .to_string()
        .as_bytes()
    );
}

pub fn log_resolution_window(window: &ResolutionWindow) {
    env::log(
        json!({
            "type": "resolution_windows",
            "action": "update",
            "cap_id": format!("rw_{}_{}", window.dr_id, window.round),
            "params": {
                "id": format!("rw_{}_{}", window.dr_id, window.round),
                "dr_id": U64(window.dr_id),
                "round": window.round,
                "start_time": U64(window.start_time),
                "end_time": U64(window.end_time),
                "bond_size": U128(window.bond_size),
                "bonded_outcome": window.bonded_outcome,

                "date": U64(ns_to_ms(env::block_timestamp())),
                "block_height": U64(env::block_index()),
            }
        })
        .to_string()
        .as_bytes()
    );
}

fn outcome_to_id(outcome: &Outcome) -> String {
    // We append ans_ infront of an answer to avoid malicous fake invalids
    // that would overwrite a real invalid outcome
    match outcome {
        Outcome::Answer(a) => format!("ans_{}", a),
        Outcome::Invalid => "invalid".to_string()
    }
}

pub fn log_outcome_to_stake(data_request_id: u64, round: u16, outcome: &Outcome, total_stake: Balance) {
    let outcome_id = outcome_to_id(outcome);
    
    env::log(
        json!({
            "type": "outcome_stakes",
            "action": "update",
            "cap_id": format!("ots_{}_{}_{}", data_request_id, round, outcome_id),
            "params": {
                "id": format!("ots_{}_{}_{}", data_request_id, round, outcome_id),
                "data_request_id": U64(data_request_id),
                "round": round,
                "outcome": outcome,
                "total_stake": U128(total_stake),
            }
        })
        .to_string()
        .as_bytes()
    );
}

pub fn log_user_stake(data_request_id: u64, round: u16, account_id: &AccountId, outcome: &Outcome, total_stake: Balance) {
    let outcome_id = outcome_to_id(outcome);
    
    env::log(
        json!({
            "type": "user_stakes",
            "action": "update",
            "cap_id": format!("ots_{}_{}_{}", data_request_id, round, outcome_id),
            "params": {
                "id": format!("ots_{}_{}_{}", data_request_id, round, outcome_id),
                "data_request_id": U64(data_request_id),
                "round": round,
                "outcome": outcome,
                "account_id": account_id,
                "total_stake": U128(total_stake),
            }
        })
        .to_string()
        .as_bytes()
    );
}

pub fn log_claim(
    account_id: &AccountId, 
    data_request_id: u64, 
    total_correct_bonded_staked: u128, 
    total_incorrect_staked: u128, 
    user_correct_stake: u128, 
    payout: u128
) {
    env::log(
        json!({
            "type": "claims",
            "action": "update",
            "cap_id": format!("c_{}_{}", account_id, data_request_id),
            "params": {
                "id": format!("c_{}_{}", account_id, data_request_id),
                "account_id": account_id,
                "data_request_id": U64(data_request_id),
                "total_correct_bonded_staked": U128(total_correct_bonded_staked),
                "total_incorrect_staked": U128(total_incorrect_staked),
                "user_correct_stake": U128(user_correct_stake),
                "payout": U128(payout),
                "date": U64(ns_to_ms(env::block_timestamp())),
                "block_height": U64(env::block_index()),
            }
        })
        .to_string()
        .as_bytes()
    );
}

pub fn log_whitelist(account_id: &AccountId, active: bool) {
    env::log(
        json!({
            "type": "whitelist",
            "action": "update",
            "cap_id": format!("wl_{}", account_id),
            "params": {
                "id": format!("wl_{}", account_id),
                "account_id": account_id,
                "active": active,
                "date": U64(ns_to_ms(env::block_timestamp())),
                "block_height": U64(env::block_index()),
            }
        })
        .to_string()
        .as_bytes()
    );
}

#[derive(serde::Serialize)]
pub enum TransactionType {
    Stake,
    Unstake,
}

pub fn log_transaction(
    tx_type: TransactionType, 
    account_id: &AccountId, 
    data_request_id: u64, 
    round: Option<u16>, 
    input: u128, 
    output: u128,
    extra_info: Option<String>,
) {
    env::log(
        json!({
            "type": "transactions",
            "params": {
                "account_id": account_id,
                "input": U128(input),
                "output": U128(output),
                "data_request_id": U64(data_request_id),
                "round": round,
                "date": U64(ns_to_ms(env::block_timestamp())),
                "block_height": U64(env::block_index()),
                "extra_info": extra_info,
                "type": tx_type,
            }
        })
        .to_string()
        .as_bytes()
    );
}

pub fn log_stake_transaction(
    account_id: &AccountId, 
    window: &ResolutionWindow, 
    amount_in: Balance, 
    amount_out: Balance,
    outcome: &Outcome
) {
    log_transaction(
        TransactionType::Stake, 
        account_id, 
        window.dr_id, 
        Some(window.round), 
        amount_in,
        amount_out, 
        Some(outcome_to_id(outcome))
    );
}

pub fn log_unstake_transaction(
    account_id: &AccountId, 
    window: &ResolutionWindow, 
    amount_out: Balance,
    outcome: &Outcome
) {
    log_transaction(
        TransactionType::Unstake, 
        account_id, 
        window.dr_id, 
        Some(window.round), 
        0,
        amount_out, 
        Some(outcome_to_id(outcome))
    );
}
