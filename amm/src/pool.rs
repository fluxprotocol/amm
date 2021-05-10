use std::cmp::Ordering;
use crate::*;
use crate::resolution_escrow::ResolutionEscrows;
use crate::outcome_token::MintableFungibleToken;
use near_sdk::Balance;

#[derive(BorshDeserialize, BorshSerialize)]
pub struct Pool {
    pub id: u64, // unique identifier - used for storage pointers
    pub collateral_token_id: AccountId, // account id of the token that's used as collateral for this market
    pub collateral_denomination: u128, // the denomination of the collateral token
    pub outcomes: u16, // the number of outcomes tokens in this pool
    pub outcome_tokens: UnorderedMap<u16, MintableFungibleToken>, // maps outcome => outcome token implementation
    pub pool_token: MintableFungibleToken, // the token representing LP positions
    pub swap_fee: Balance, // the fee paid to LPs on every swap, denominated in 1e4, meaning that 1 = 0.01% and 10000 = 100%
    pub withdrawn_fees: LookupMap<AccountId, Balance>, // amount of accumulated fees an account is (no longer) ineligable to claim
    pub total_withdrawn_fees: Balance, // total withdrawn fees
    pub fee_pool_weight: u128, // weighted fee pool used to calculate fees owed to accounts based on LP token share
    pub resolution_escrow: ResolutionEscrows // maps account_id => Resolution Escrow scruct
}

impl Pool {

    /**
     * @notice create new pool instance
     * @param pool_id is the unique identifier used for unique storage pointers
     * @param collateral_token_id is the `account_id` of the whitelisted token that is to be used as collateral
     * @param collateral_decimals is the amount of decimals the corresponding collateral token has
     * @param outcomes is the number outcomes in the pool
     * @param swap_fee is the fee paid out to LPs on every swap (buy or sell) denominated in 1e4
     * @returns a new `Pool` instance
     */
    pub fn new(
        pool_id: u64,
        collateral_token_id: AccountId,
        collateral_decimals: u32,
        outcomes: u16,
        swap_fee: Balance
    ) -> Self {
        assert!(outcomes >= constants::MIN_OUTCOMES, "ERR_MIN_OUTCOMES");
        assert!(outcomes <= constants::MAX_OUTCOMES, "ERR_MAX_OUTCOMES");
        let collateral_denomination = 10_u128.pow(collateral_decimals);
        assert!(swap_fee == 0 || (swap_fee <= collateral_denomination / 20 && swap_fee >= collateral_denomination / 10_000), "ERR_INVALID_FEE");

        Self {
            id: pool_id,
            collateral_token_id,
            collateral_denomination,
            outcomes,
            outcome_tokens: UnorderedMap::new(format!("p{}ot", pool_id).as_bytes().to_vec()),
            pool_token: MintableFungibleToken::new(pool_id, outcomes, 0),
            swap_fee,
            withdrawn_fees: LookupMap::new(format!("p{}wf", pool_id).as_bytes().to_vec()),
            total_withdrawn_fees: 0,
            fee_pool_weight: 0,
            resolution_escrow: ResolutionEscrows::new(pool_id)
        }
    }

    /**
     * @returns the pool's swap fee
     */
    pub fn get_swap_fee(&self) -> Balance {
        self.swap_fee
    }

    /**
     * @param account_id to return the share balance of
     * @param outcome for which the `account_id`'s balance should be returned
     * @returns the `account_id`s balance of a share within this `Pool`
     */
    pub fn get_share_balance(
        &self,
        account_id: &AccountId, 
        outcome: u16
    ) -> Balance {
        self.outcome_tokens
            .get(&outcome)
            .expect("ERR_NO_OUTCOME")
            .get_balance(account_id)
    }

    /**
     * TODO: improve consistency of argument naming
     * @param owner_id the owner for whom to return the pool token balance
     * @returns pool token balance of owner
     */
    pub fn get_pool_token_balance(&self, owner_id: &AccountId) -> Balance {
        self.pool_token.get_balance(owner_id)
    }

    pub fn get_pool_balances(&self) -> Vec<Balance> {
        self.outcome_tokens.iter().map(|(_outcome, token)| {
            token.get_balance(&env::current_account_id())
        }).collect()
    }

    pub fn add_liquidity(
        &mut self,
        sender: &AccountId,
        total_in: Balance,
        weight_indication: Option<Vec<u128>>
    ) {
        assert!(total_in >= self.min_liquidity_amount(), "ERR_MIN_LIQUIDITY_AMOUNT");
        let mut outcome_tokens_to_return: Vec<u128> = vec![];

        let to_mint = if self.pool_token.total_supply() == 0 {
            assert!(weight_indication.is_some(), "ERR_EXPECTED_WEIGHT_INDICATION");
            let weights = weight_indication.unwrap();
            assert!(weights.len() as u16 == self.outcomes, "ERR_INVALID_WEIGHTS");
            let max_weight = weights.iter().max().unwrap();

            for (i, weight) in weights.iter().enumerate() {
                let remaining = math::complex_div_u128(self.collateral_denomination, math::complex_mul_u128(self.collateral_denomination, total_in, *weight), *max_weight);
                outcome_tokens_to_return.insert(i, total_in - remaining);
            }

            total_in
        } else {
            assert!(weight_indication.is_none(), "ERR_UNEXPECTED_WEIGHT_INDICATION");

            let pool_balances = self.get_pool_balances();
            let max_balance = pool_balances.iter().max().unwrap(); // max_balance = cheapest outcome
            let pool_supply = self.pool_token.total_supply();

            for (i, balance) in pool_balances.iter().enumerate() {
                let remaining = math::complex_div_u128(self.collateral_denomination, math::complex_mul_u128(self.collateral_denomination, total_in, *balance), *max_balance); // remaining = amt_in * balance / max_balance
                outcome_tokens_to_return.insert(i, total_in - remaining);
            }

            math::complex_div_u128(self.collateral_denomination, math::complex_mul_u128(self.collateral_denomination, total_in, pool_supply), *max_balance)
        };

        self.mint_and_transfer_outcome_tokens(
            sender.to_string(),
            total_in,
            &outcome_tokens_to_return
        );

        self.mint_internal(sender, to_mint);

        logger::log_pool(&self);
        logger::log_transaction(&logger::TransactionType::AddLiquidity, &sender, total_in, to_mint, U64(self.id), None);
        logger::log_user_pool_status(&self, &env::predecessor_account_id(), total_in);
    }

    fn mint_and_transfer_outcome_tokens(
        &mut self,
        sender: AccountId,
        total_in: Balance,
        outcome_tokens_to_return: &Vec<Balance>
    ) {
        let mut escrow_account = self.resolution_escrow.get_or_new(sender.to_string());

        for (i, amount) in outcome_tokens_to_return.iter().enumerate() {
            let outcome = i as u16;

            // Since at LP stage we need to consider that they spent equal amount of money on each outcome (since if they'd immediately exit they'd have `total_in` of each outcome)
            // we calculate spent_on_outcome as such: total collateral in / total outcomes. E.g. if there's 10 token_x provided to mint 10 YES and 10 NO tokens the LP spent 5 x on YES and 5 x on NO
            // this is all to ensure the principle can be refunded in case of an invalid outcome
            let spent_on_outcome = total_in / self.outcomes as u128;

            // The amount spent by the sender on amount the shares that are paid out at during liquidity provision needs to be accounted for.
            // We calculate the amount spent on the outcome_tokens that are immediately returned to the user as follows: shares to transfer / total in * spent on shares
            // e.g. if Alice spends 10 token_x to to mint 10 YES and 10 NO and in return they get 8 YES back they spent: 8 / 10 * 5 = 4x on those 8 YES tokens
            let spent_on_amount_out = if amount > &0 {
                math::complex_mul_u128(self.collateral_denomination, spent_on_outcome, math::complex_div_u128(self.collateral_denomination, *amount, total_in))
            } else {
                0
            };

            // Account for this new LP position on the LPs escrow account
            let account_spent = escrow_account.lp_on_join(outcome, spent_on_outcome, spent_on_amount_out);
            logger::log_account_outcome_spent(&self, &sender, outcome, account_spent);

            // Get the outcome token or else create one for this outcome
            let mut outcome_token = self.outcome_tokens
                .get(&(outcome as u16))
                .unwrap_or_else(|| { MintableFungibleToken::new(self.id, outcome as u16, 0) });
            
            // Mint the amount of newly created shares
            outcome_token.mint(& env::current_account_id(), total_in);

            if *amount > 0 {
                outcome_token.safe_transfer_internal(&env::current_account_id(), &sender, *amount);
            }

            self.outcome_tokens.insert(&(outcome as u16), &outcome_token);
        }

        self.resolution_escrow.insert(&sender, &escrow_account);
    }

    pub fn exit_pool(
        &mut self,
        sender: &AccountId,
        total_in: Balance
    ) ->  Balance {

        let balances = self.get_pool_balances();
        let pool_token_supply = self.pool_token.total_supply();
        let sender_pool_token_balance = self.pool_token.get_balance(sender);

        assert!(total_in <= sender_pool_token_balance, "sender only has {} lp tokens which is insufficient", sender_pool_token_balance);

        let mut escrow_account = self.resolution_escrow.get_expect(sender);

        // TODO: redo to exit_divisor sender_pool_token_balance / total_in
        // Calculate the relative amount of tokens sender is exiting. 
        // e.g. if collateral has 18 decimals and sender has 10 LP tokens and is exiting 5: 5e18 / 10e18 = 5e17 (0.5) 
        let lp_token_exit_ratio = math::complex_div_u128(self.collateral_denomination, total_in, sender_pool_token_balance);

        for (i, balance) in balances.iter().enumerate() {
            let outcome = i as u16;

            // Account for LP position exit
            let current_lp_spent = escrow_account.get_lp_spent(outcome);
            // Calculate how much the user spent on shares that are taken out of pool: lp_token_exit_ratio * current_lp_spent
            let spent_on_exit_shares = math::complex_mul_u128(self.collateral_denomination, lp_token_exit_ratio, current_lp_spent);
            // Account for lp exit 
            let new_account_spent = escrow_account.lp_on_exit(outcome, spent_on_exit_shares);
            logger::log_account_outcome_spent(&self, sender, outcome, new_account_spent);

            // The amount of shares to return to the user are calculated as follows: pool tokens in / total pool token supply * contract balance of pool token
            let send_out = math::complex_mul_u128(self.collateral_denomination, math::complex_div_u128(self.collateral_denomination, total_in, pool_token_supply), *balance);
            let mut token = self.outcome_tokens.get(&outcome).unwrap();
            token.safe_transfer_internal(&env::current_account_id(), sender, send_out);
            self.outcome_tokens.insert(&outcome, &token);
        }

        self.resolution_escrow.insert(&sender, &escrow_account);
        let fees = self.burn_internal(sender, total_in);
        logger::log_exit_pool(&self, sender, total_in, fees);
        fees
    }

    pub fn burn_outcome_tokens_redeem_collateral(
        &mut self,
        sender: &AccountId,
        to_burn: Balance
    ) -> Balance {
        let mut escrow_account = self.resolution_escrow.get_expect(sender);

        let avg_price_paid = self.outcome_tokens.iter().fold(0, |sum, (outcome, mut token)| {

            let outcome_balance = token.get_balance(sender);
            let outcome_spent = escrow_account.get_spent(outcome);
            assert!(outcome_balance > 0, "sender doesn't have any shares for outcome with index {}", outcome);

            // Avg price paid is calculated as follows: total spent / total balance
            // e.g. if sender has 5 shares and spent 10 used paid: 5 / 10 = 0.5 per share
            let avg_price_paid = math::complex_div_u128(self.collateral_denomination, outcome_spent, outcome_balance); // TODO: also work with divisors over ratio

            // TODO: once again divisors over ratio
            // Calculate how much should be subtracted from spent for this redemption, calculated as follows: outcome tokens to burn / balance of outcome tokens * spent on outcome
            // e.g. if sender has spent 15 collateral(x) on 5 shares of each outcome and is burning 4: 4 / 5 * 15 = 12
            let spent_on_redeemed_shares = math::complex_mul_u128(self.collateral_denomination, math::complex_div_u128(self.collateral_denomination, to_burn, outcome_balance), outcome_spent);

            let new_spent = escrow_account.sub_from_spent(outcome, spent_on_redeemed_shares);
            logger::log_account_outcome_spent(&self, sender, outcome, new_spent);

            // Burn outcome tokens accordingly 
            token.burn(sender, to_burn);

            sum + avg_price_paid
        });

        // If the user paid less than 1 they have the right to claim the difference if the market turns out valid
        // If the users paid more than 1 they will have the right to claim the difference if the market turns out invalid
        let in_escrow = match avg_price_paid.cmp(&self.collateral_denomination) {
            std::cmp::Ordering::Greater => {
                let loss_per_share = avg_price_paid - self.collateral_denomination;
                // Escrow loss_per_share * shares to burn. this will be claimable if the market is invalid
                escrow_account.add_to_escrow_invalid(math::complex_mul_u128(self.collateral_denomination, loss_per_share, to_burn) - 1); // TODO: remove need for -1
                0
            },
            std::cmp::Ordering::Less => {
                let profit_per_share = self.collateral_denomination - avg_price_paid;
                // Escrow loss_per_share * shares to burn - this will be claimable if the market is invalid
                let to_escrow =math::complex_mul_u128(self.collateral_denomination, profit_per_share, to_burn) - 1; // TODO: remove need for -1
                escrow_account.add_to_escrow_valid(to_escrow); 
                to_escrow + 1 // TODO: remove need for +1
            }, 
            std::cmp::Ordering::Equal => 0
        };

        // Store updated account
        self.resolution_escrow.insert(sender, &escrow_account);

        in_escrow
    }

    // move to view impl

    fn get_and_clear_balances(
        &mut self,
        account_id: &AccountId
    ) -> Vec<Balance> {
        self.outcome_tokens.iter().map(|(_outcome, mut token)| {
            token.remove_account(account_id).unwrap_or(0)
        }).collect()
    }

    fn mint_internal(
        &mut self,
        to: &AccountId,
        amount: Balance
    ) {
        self.before_pool_token_transfer(None, Some(to), amount);
        self.pool_token.mint(to, amount)
    }

    fn burn_internal(
        &mut self,
        from: &AccountId,
        amount: Balance
    ) -> Balance {
        let fees = self.before_pool_token_transfer(Some(from), None, amount);
        self.pool_token.burn(from, amount);
        fees
    }

    fn before_pool_token_transfer(
        &mut self,
        from: Option<&AccountId>,
        to: Option<&AccountId>,
        amount: Balance
    ) -> Balance {
        let mut fees = 0;
        if let Some(account_id) = from {
            fees = self.withdraw_fees(account_id);
        }

        let total_supply = self.pool_token.total_supply();
        let ineligible_fee_amount = match total_supply {
            0 => amount,
            _ => math::simple_mul_u128(total_supply, self.fee_pool_weight, amount)
        };

        // On transfer or burn
        if let Some(account_id) = from {
            let withdrawn_fees = self.withdrawn_fees.get(account_id).expect("ERR_NO_BAL");
            self.withdrawn_fees.insert(account_id, &(withdrawn_fees - ineligible_fee_amount));

            logger::log_withdrawn_fees(&self.pool_token.token, account_id, withdrawn_fees - ineligible_fee_amount);

            self.total_withdrawn_fees -= ineligible_fee_amount;
        } else { // On mint
            self.fee_pool_weight += ineligible_fee_amount;
        }

        // On transfer or mint
        if let Some(account_id) = to {
            let withdrawn_fees = self.withdrawn_fees.get(account_id).unwrap_or(0);
            self.withdrawn_fees.insert(account_id, &(withdrawn_fees + ineligible_fee_amount));

            logger::log_withdrawn_fees(&self.pool_token.token, account_id, withdrawn_fees + ineligible_fee_amount);

            self.total_withdrawn_fees += ineligible_fee_amount;
        } else { // On burn
            self.fee_pool_weight -= ineligible_fee_amount;
        }

        logger::log_pool(self);

        fees
    }

    pub fn get_fees_withdrawable(&self, account_id: &AccountId) -> Balance {
        let pool_token_bal = self.pool_token.get_balance(account_id);
        let pool_token_total_supply = self.pool_token.total_supply();
        let raw_amount = math::complex_div_u128(self.collateral_denomination, math::complex_mul_u128(self.collateral_denomination, self.fee_pool_weight, pool_token_bal), pool_token_total_supply);
        let ineligible_fee_amount = self.withdrawn_fees.get(account_id).unwrap_or(0);
        raw_amount - ineligible_fee_amount
    }

    pub fn withdraw_fees(
        &mut self,
        account_id: &AccountId
    ) -> Balance {
        let pool_token_bal = self.pool_token.get_balance(account_id);
        let pool_token_total_supply = self.pool_token.total_supply();
        let raw_amount = math::simple_mul_u128(pool_token_total_supply, self.fee_pool_weight, pool_token_bal);
        let withdrawn_fees = self.withdrawn_fees.get(account_id).unwrap_or(0);
        let withdrawable_amount = raw_amount - withdrawn_fees;
        if withdrawable_amount > 0 {
            self.withdrawn_fees.insert(account_id, &raw_amount);
            self.total_withdrawn_fees += withdrawable_amount;
            logger::log_withdrawn_fees(&self.pool_token.token, account_id, raw_amount);
        }

        withdrawable_amount
    }

    pub fn calc_buy_amount(
        &self,
        collateral_in: Balance,
        outcome_target: u16
    ) -> Balance {
        assert!(outcome_target <= self.outcomes, "ERR_INVALID_OUTCOME");

        let outcome_tokens = &self.outcome_tokens;
        let collateral_in_minus_fees = collateral_in - math::complex_mul_u128(self.collateral_denomination, collateral_in, self.swap_fee);
        let token_to_buy = outcome_tokens.get(&outcome_target).expect("ERR_NO_TOKEN");
        let token_to_buy_balance = token_to_buy.get_balance(&env::current_account_id());
        let mut new_buy_token_balance = token_to_buy_balance;

        for (outcome, token) in outcome_tokens.iter() {
            if outcome != outcome_target {
                let balance = token.get_balance(&env::current_account_id());
                let dividend = math::complex_mul_u128(self.collateral_denomination, new_buy_token_balance, balance);
                let divisor = balance + collateral_in_minus_fees;

                new_buy_token_balance = math::complex_div_u128(self.collateral_denomination, dividend, divisor);
            }
        }
        assert!(new_buy_token_balance > 0, "ERR_MATH_APPROX");

        token_to_buy_balance + collateral_in_minus_fees - new_buy_token_balance
    }

    pub fn calc_sell_collateral_out(
        &self,
        collateral_out: Balance,
        outcome_target: u16
    ) -> Balance {
        assert!(outcome_target <= self.outcomes, "ERR_INVALID_OUTCOME");

        let outcome_tokens = &self.outcome_tokens;
        let collateral_out_plus_fees = math::complex_div_u128(self.collateral_denomination, collateral_out, self.collateral_denomination - self.swap_fee);
        let token_to_sell = outcome_tokens.get(&outcome_target).expect("ERR_NO_TOKEN");
        let token_to_sell_balance = token_to_sell.get_balance(&env::current_account_id());
        let mut new_sell_token_balance = token_to_sell_balance;

        for (outcome, token) in outcome_tokens.iter() {
            if outcome != outcome_target {
                let balance = token.get_balance(&env::current_account_id());
                let dividend = math::complex_mul_u128(self.collateral_denomination, new_sell_token_balance, balance);
                let divisor = balance - collateral_out_plus_fees;

                new_sell_token_balance = math::complex_div_u128(self.collateral_denomination, dividend, divisor);
            }
        }
        assert!(new_sell_token_balance > 0, "ERR_MATH_APPROX");

        collateral_out_plus_fees + new_sell_token_balance - token_to_sell_balance
    }

    pub fn buy(
        &mut self,
        sender: &AccountId,
        amount_in: Balance,
        outcome_target: u16,
        min_shares_out: Balance
    ) {

        assert!(outcome_target < self.outcomes, "ERR_INVALID_OUTCOME");

        let shares_out = self.calc_buy_amount(amount_in, outcome_target);
        assert!(shares_out >= min_shares_out, "ERR_MIN_BUY_AMOUNT");

        let mut escrow_account = self.resolution_escrow.get_or_new(sender.to_string());

        // Transfer collateral in
        let fee = math::complex_mul_u128(self.collateral_denomination, amount_in, self.swap_fee);
        self.fee_pool_weight += fee;

        let spent = escrow_account.add_to_spent(outcome_target, amount_in - fee);
        logger::log_account_outcome_spent(&self, sender, outcome_target, spent);

        let tokens_to_mint = amount_in - fee;
        self.add_to_pools(tokens_to_mint);

        let mut token_out = self.outcome_tokens.get(&outcome_target).expect("ERR_NO_TARGET_OUTCOME");
        token_out.safe_transfer_internal(&env::current_account_id(), sender, shares_out);
        self.outcome_tokens.insert(&outcome_target, &token_out);
        self.resolution_escrow.insert(sender, &escrow_account);

        logger::log_buy(&self, &sender, outcome_target, amount_in, shares_out, fee);
        logger::log_pool(&self);
    }

    pub fn sell(
        &mut self,
        sender: &AccountId,
        amount_out: Balance,
        outcome_target: u16,
        max_shares_in: Balance
    ) -> Balance {

        assert!(outcome_target < self.outcomes, "ERR_INVALID_OUTCOME");
        let shares_in = self.calc_sell_collateral_out(amount_out, outcome_target);

        assert!(shares_in <= max_shares_in, "ERR_MAX_SELL_AMOUNT");
        let mut token_in = self.outcome_tokens.get(&outcome_target).expect("ERR_NO_TARGET_OUTCOME");

        let mut escrow_account = self.resolution_escrow.get_expect(sender);
        let spent = escrow_account.get_spent(outcome_target);
        assert!(spent > 0, "account has no balance of outcome {} shares", outcome_target);

        // TODO: redo math and try to fit it into resolution_escrow
        let fee = math::complex_mul_u128(self.collateral_denomination, amount_out, self.swap_fee);
        let avg_price = math::complex_div_u128(self.collateral_denomination, spent, token_in.get_balance(sender));
        let sell_price = math::complex_div_u128(self.collateral_denomination, amount_out + fee, shares_in);

        token_in.transfer(&env::current_account_id(), shares_in);
        self.outcome_tokens.insert(&outcome_target, &token_in);

        self.fee_pool_weight += fee;

        let to_escrow = match (sell_price).cmp(&avg_price) {
            Ordering::Less => {
                let price_delta = avg_price - sell_price;
                let escrow_amt = math::simple_mul_u128(self.collateral_denomination, price_delta, shares_in);
                let invalid_escrow = escrow_account.add_to_escrow_invalid(escrow_amt);
                logger::log_to_invalid_escrow(self.id, &sender, invalid_escrow);

                // TODO: sub from spent and logging it is done in both cases, remove dup code
                let new_spent = escrow_account.sub_from_spent(outcome_target, amount_out + escrow_amt + fee);
                logger::log_account_outcome_spent(&self, &sender, outcome_target, new_spent);
                0
            },
            Ordering::Greater => {
                let price_delta = sell_price - avg_price;
                let escrow_amt = math::simple_mul_u128(self.collateral_denomination, price_delta, shares_in);
                let valid_escrow = escrow_account.add_to_escrow_valid(escrow_amt);
                logger::log_to_valid_escrow(self.id, &sender, valid_escrow);
                let entries_to_sub = amount_out - escrow_amt + fee;

                // TODO: entries_to_sub should never be larger than spent
                if entries_to_sub > spent {
                    let new_spent = escrow_account.sub_from_spent(outcome_target, spent);
                    logger::log_account_outcome_spent(&self, &sender, outcome_target, new_spent);
                } else {
                    let new_spent = escrow_account.sub_from_spent(outcome_target, entries_to_sub);
                    logger::log_account_outcome_spent(&self, &sender, outcome_target, new_spent);
                }


                escrow_amt
            },
            Ordering::Equal => {
                let new_spent = escrow_account.sub_from_spent(outcome_target, amount_out - fee);
                logger::log_account_outcome_spent(&self, &sender, outcome_target, new_spent);
                0
            }
        };

        let tokens_to_burn = amount_out + fee;
        self.remove_from_pools(tokens_to_burn);
        self.resolution_escrow.insert(sender, &escrow_account);

        logger::log_sell(&self, &env::predecessor_account_id(), outcome_target, shares_in, amount_out, fee, to_escrow);
        logger::log_pool(&self);

        to_escrow
    }

    pub fn payout(
        &mut self,
        account_id: &AccountId,
        payout_numerators: &Option<Vec<U128>>
    ) -> Balance {
        let pool_token_balance = self.get_pool_token_balance(account_id);
        let fees_earned = if pool_token_balance > 0 { 
            self.exit_pool(account_id, pool_token_balance) 
        } else {
            0
        };

        let balances = self.get_and_clear_balances(account_id);
        let escrow_account = match self.resolution_escrow.get(account_id) {
            Some(account) => account,
            None => return 0
        };

        let payout = if payout_numerators.is_some() {
            payout_numerators.as_ref().unwrap().iter().enumerate().fold(0, |sum, (outcome, num)| {
                let bal = balances[outcome];
                let payout = math::complex_mul_u128(self.collateral_denomination, bal, u128::from(*num));
                sum + payout
            }) + escrow_account.valid
        } else {
            balances.iter().enumerate().fold(0, |sum, (outcome, _bal)| {                
                let spent = escrow_account.get_spent(outcome as u16);
                sum + spent
            }) + escrow_account.invalid
        };

        self.resolution_escrow.remove(&account_id);

        payout + fees_earned
    }


    fn add_to_pools(&mut self, amount: Balance) {
        for outcome in 0..self.outcomes {
            let mut token = self.outcome_tokens.get(&outcome).expect("ERR_NO_OUTCOME");
            token.mint(&env::current_account_id(), amount);
            self.outcome_tokens.insert(&outcome, &token);
        }
    }

    fn remove_from_pools(&mut self, amount: Balance) {
        for outcome in 0..self.outcomes {
            let mut token = self.outcome_tokens.get(&outcome).expect("ERR_NO_OUTCOME");
            token.burn(&env::current_account_id(), amount);

            self.outcome_tokens.insert(&outcome, &token);
        }
    }

    fn min_liquidity_amount(&self) -> Balance {
        self.collateral_denomination / 1_000_000
    }

    /**
     * Test functions
    */

    // Should be done in data layer
    pub fn get_spot_price(
        &self,
        target_outcome: u16
    ) -> Balance {

        let mut odds_weight_for_target = 0;
        let mut odds_weight_sum = 0;

        for (outcome, _) in self.outcome_tokens.iter() {
            let weight_for_outcome = self.get_odds_weight_for_outcome(outcome);
            odds_weight_sum += weight_for_outcome;

            if outcome == target_outcome {
                odds_weight_for_target = weight_for_outcome;
            }
        }

        let ratio = math::complex_div_u128(self.collateral_denomination, odds_weight_for_target, odds_weight_sum);
        let scale = math::complex_div_u128(self.collateral_denomination, self.collateral_denomination, self.collateral_denomination - self.swap_fee);

        math::complex_mul_u128(self.collateral_denomination, ratio, scale)
    }

    // Should be done in data layer
    pub fn get_spot_price_sans_fee(
        &self,
        target_outcome: u16
    ) -> Balance {
        let mut odds_weight_for_target = 0;
        let mut odds_weight_sum = 0;

        for (outcome, _) in self.outcome_tokens.iter() {
            let weight_for_outcome = self.get_odds_weight_for_outcome(outcome);

            odds_weight_sum += weight_for_outcome;

            if outcome == target_outcome {
                odds_weight_for_target = weight_for_outcome;
            }
        }

        if odds_weight_sum == 0 {
            return 0
        }

        math::complex_div_u128(self.collateral_denomination, odds_weight_for_target, odds_weight_sum)
    }

    fn get_odds_weight_for_outcome(
        &self,
        target_outcome: u16
    ) -> u128 {
        let mut odds_weight_for_target = 0;

        for (outcome, token) in self.outcome_tokens.iter() {
            if outcome != target_outcome {
                let balance = token.get_balance(&env::current_account_id());
                odds_weight_for_target = if odds_weight_for_target == 0 {
                    balance
                } else {
                    math::complex_mul_u128(self.collateral_denomination, odds_weight_for_target, balance)
                };
            }
        }
        odds_weight_for_target
    }
}
