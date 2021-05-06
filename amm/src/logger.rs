use crate:: *;
use near_sdk::serde_json::json;
use outcome_token::MintableToken;

#[derive(serde::Serialize)]
pub enum TransactionType {
    Buy,
    Sell,
    Redeem,
    ClaimEarnings,
    AddLiquidity,
    RemoveLiquidity,
}

pub fn log_transaction(tx_type: &TransactionType, account_id: &AccountId, input: u128, output: u128, market_id: U64, outcome_id: Option<u16>) {
    env::log(
        json!({
            "type": "transactions",
            "params": {
                "account_id": account_id,
                "input": U128(input),
                "output": U128(output),
                "market_id": market_id,
                "outcome_id": outcome_id.unwrap_or(0),
                "date": U64(ns_to_ms(env::block_timestamp())),
                "type": tx_type,
            }
        })
        .to_string()
        .as_bytes()
    );
}

// NEW_POOL env log
pub fn log_pool(pool: &Pool) {
	env::log(
		json!({
            "type": "pools".to_string(),
            "action": "update",
            "cap_id": format!("p_{}", pool.id),
			"params": {
                "id": U64(pool.id),
                "outcomes": pool.outcomes,
                "swap_fee": U128(pool.swap_fee),
                "collateral_token_id": pool.collateral_token_id,
                "collateral_denomination": U128(pool.collateral_denomination),
                "total_withdrawn_fees": U128(pool.total_withdrawn_fees),
                "fee_pool_weight": U128(pool.fee_pool_weight),
                "block_height": U64(env::block_index()),
			}
		})
		.to_string()
		.as_bytes()
	);
}

pub fn log_whitelist(whitelist: &Whitelist) {
    env::log(
		json!({
            "type": "token_whitelist".to_string(),
            "action": "update",
            "cap_id": "wl",
			"params": {
                "whitelist": whitelist.0.to_vec()
			}
		})
		.to_string()
		.as_bytes()
	);
}

pub fn log_token_status(token: &MintableToken) {
    env::log(
		json!({
            "type": "token_statuses".to_string(),
            "cap_id": format!("ts_{}_{}", token.pool_id, token.outcome_id),
            "action": "update",
			"params": {
                "pool_id": U64(token.pool_id),
                "outcome_id": token.outcome_id,
                "total_supply": U128(token.total_supply),
                "block_height": U64(env::block_index()),
			}
		})
		.to_string()
		.as_bytes()
	);
}

pub fn log_user_pool_status(pool: &Pool, account_id: &AccountId, total_in: u128) {
    env::log(
		json!({
            "type": "user_pool_statuses".to_string(),
            "cap_id": format!("ups_{}_{}", account_id, pool.id),
            "action": "update",
			"params": {
                "id": format!("ups_{}_{}", account_id, pool.id),
                "pool_id": U64(pool.id),
                "account_id": account_id,
                "total_in": U128(total_in),
                "block_height": U64(env::block_index()),
			}
		})
		.to_string()
		.as_bytes()
	);
}


pub fn log_exit_pool(pool: &Pool, account_id: &AccountId, pool_tokens_in: u128, fees_earned: u128) {
    log_transaction(&TransactionType::RemoveLiquidity, account_id, pool_tokens_in, fees_earned, U64(pool.id), None);
    env::log(
		json!({
			"type": "pool_exits".to_string(),
			"params": {
                "pool_id": U64(pool.id),
                "account_id": account_id,
                "pool_tokens_in": U128(pool_tokens_in),
                "block_height": U64(env::block_index()),
                "fees_earned": U128(fees_earned),
			}
		})
		.to_string()
		.as_bytes()
	);
}

enum SwapType {
    Sell,
    Buy,
}

fn log_swap(pool: &Pool, account_id: &AccountId, outcome: u16, input: u128, output: u128, fee: u128, swap_type: &SwapType) {
    let swap_type_str = match swap_type {
        SwapType::Buy => "buy",
        SwapType::Sell => "sell",
    };
    
    env::log(
		json!({
			"type": "swaps".to_string(),
			"params": {
                "pool_id": U64(pool.id),
                "block_height": U64(env::block_index()),
                "account_id": account_id,
                "outcome_id": outcome,
                "input": U128(input),
                "output": U128(output),
                "fee": U128(fee),
                "collateral_token_id": pool.collateral_token_id,
                "type": swap_type_str,
			}
		})
		.to_string()
		.as_bytes()
	);
}

pub fn log_buy(pool: &Pool, account_id: &AccountId, outcome: u16, amount_in: u128, shares_out: u128, fee: u128) {
    log_swap(pool, account_id, outcome, amount_in, shares_out, fee, &SwapType::Buy);
    log_transaction(&TransactionType::Buy, account_id, amount_in, shares_out, U64(pool.id), Some(outcome));
}

pub fn log_sell(pool: &Pool, account_id: &AccountId, outcome: u16, shares_in: u128, amount_out: u128, fee: u128, to_escrow: u128) {
    log_swap(pool, account_id, outcome, shares_in, amount_out - to_escrow, fee, &SwapType::Sell);
    log_transaction(&TransactionType::Sell, account_id, shares_in, amount_out - to_escrow, U64(pool.id), Some(outcome));
}

pub fn log_user_balance(token: &MintableToken, account_id: &AccountId, new_balance: u128) {
    env::log(
		json!({
            "type": "user_balances".to_string(),
            "action": "update",
            "cap_id": format!("ub_{}_{}_{}_{}", account_id, token.pool_id, token.outcome_id, env::block_index()),
			"params": {
                "id": format!("ub_{}_{}_{}", account_id, token.pool_id, token.outcome_id),
                "pool_id": U64(token.pool_id),
                "outcome_id": token.outcome_id,
                "account_id": account_id,
                "balance": U128(new_balance),
                "block_height": U64(env::block_index()),
                "creation_date": U64(ns_to_ms(env::block_timestamp())),
			}
		})
		.to_string()
		.as_bytes()
	);
}



// NEW_MARKET env log
pub fn log_create_market(
    market: &Market,
    description: String,  
    extra_info: String,  
    outcome_tags: Vec<String>,
    categories: Vec<String>,
    is_scalar: Option<bool>,
) {
	env::log(
		json!({
            "type": "markets".to_string(),
            "action": "update",
            "cap_id": format!("m_{}", market.pool.id),
			"params": {
                "id": U64(market.pool.id),
                "description": description,
                "extra_info": extra_info,
                "outcome_tags": outcome_tags,
                "end_time": U64(market.end_time),
                "resolution_time": U64(market.resolution_time),
                "finalized": market.finalized,
                "payout_numerator": market.payout_numerator,
                "categories": categories,
                "creation_date": U64(ns_to_ms(env::block_timestamp())),
                "is_scalar": is_scalar.unwrap_or(false),
			}
		})
		.to_string()
		.as_bytes()
	);
}

pub fn log_market_status(market: &Market) {
    env::log(
		json!({
            "type": "markets".to_string(),
            "action": "update",
            "cap_id": format!("m_{}", market.pool.id),
			"params": {
                "payout_numerator": market.payout_numerator,
                "finalized": market.finalized
			}
		})
		.to_string()
		.as_bytes()
	);
}

// NEW_OWNER

// LOG_JOIN
// LOG_EXIT



fn log_to_escrow(escrow_type: String, market_id: u64, sender: &AccountId, amount: u128){ 
    env::log(
        json!({
            "type": "escrow_statuses",
            "action": "update",
            "cap_id": format!("es_{}_{}", market_id, sender),
            "params": {
                "market_id": U64(market_id),
                "account_id": sender,
                "total_amount": U128(amount),
                "type": escrow_type,
            }
        })
        .to_string()
        .as_bytes()
    );
}

pub fn log_to_invalid_escrow(market_id: u64, sender: &AccountId, amount: u128){ 
    log_to_escrow("invalid_escrow".to_string(), market_id, sender, amount);
}

pub fn log_to_valid_escrow(market_id: u64, sender: &AccountId, amount: u128){ 
    log_to_escrow("valid_escrow".to_string(), market_id, sender, amount);
}

pub fn log_claim_earnings(
    market_id: U64,
    claimer: AccountId,
    payout: u128
) {
    log_transaction(&TransactionType::ClaimEarnings, &claimer, 0, payout, market_id, None);
    env::log(
		json!({
			"type": "claims".to_string(),
			"params": {
                "market_id": market_id,
                "claimer": claimer,
                "payout": U128(payout),
			}
		})
		.to_string()
		.as_bytes()
	);
}

pub fn log_withdrawn_fees(pool_token: &MintableToken, account_id: &AccountId, withdrawn_amount: u128) {
    env::log(
		json!({
			"type": "withdrawn_fees".to_string(),
			"params": {
                "id": format!("wf_{}_{}_{}", pool_token.pool_id, pool_token.outcome_id, account_id),
                "pool_id": U64(pool_token.pool_id),
                "outcome_id": pool_token.outcome_id,
                "account_id": account_id,
                "withdrawn_amount": U128(withdrawn_amount),
                "block_height": U64(env::block_index()),
			}
		})
		.to_string()
		.as_bytes()
	);
}

pub fn log_account_outcome_spent(pool: &Pool, account_id: &AccountId, outcome_id: u16, spent: u128) {
    env::log(
		json!({
			"type": "account_spent".to_string(),
            "action": "update",
            "cap_id": format!("as_{}_{}_{}", pool.id, account_id, outcome_id),
			"params": {
                "id": format!("as_{}_{}", pool.id, account_id),
                "market_id": U64(pool.id),
                "account_id": account_id,
                "outcome_id": outcome_id,
                "spent": U128(spent),
                "block_height": U64(env::block_index()),
			}
		})
		.to_string()
		.as_bytes()
	);
}
