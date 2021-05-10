#![allow(clippy::needless_pass_by_value)]

use near_sdk::{
    AccountId,
    Balance,
    collections::{
		LookupMap,
	},
    env,
    borsh::{
        self,
        BorshDeserialize,
        BorshSerialize,
    },
};

use crate::logger;

/*** This are non-transferable fungible tokens which is used to represent an account's balance in a certain outcome ***/


#[derive(BorshDeserialize, BorshSerialize)]
pub struct MintableToken {
    pub accounts: LookupMap<AccountId, Balance>, // map `AccountId` to corresponding `Balance` in the market
    pub total_supply: Balance, // total supply of this outcome_token
    pub pool_id: u64, // the id of the corresponding pool, used for storage pointers
    pub outcome_id: u16, // the outcome this token represents, used for storage pointers
}

impl MintableToken {
    /**
     * @notice create new outcome token
     * @param pool_id the id of the pool associated with this outcome
     * @param outcome_id the outcome this token represent within the pool
     * @param the initial supply to be minted at creation
     * @returns the newly created outcome token     
     * */
    pub fn new(
        pool_id: u64, 
        outcome_id: u16, 
        initial_supply: Balance
    ) -> Self {
        let mut accounts: LookupMap<AccountId, Balance> = LookupMap::new(format!("bt:{}:{}", pool_id, outcome_id).as_bytes().to_vec()); 
        accounts.insert(&env::current_account_id(), &initial_supply);

        Self {
            total_supply: initial_supply,
            accounts,
            pool_id,
            outcome_id
        }
    }

    /**
     * @notice mint specific amount of tokens for an account
     * @param account_id the account_id to mint tokens for
     * @param amount the amount of tokens to mint
     */
    pub fn mint(
        &mut self, 
        account_id: &AccountId, 
        amount: Balance
    ) {
        self.total_supply += amount;
        let account_balance = self.accounts.get(account_id).unwrap_or(0);
        let new_balance = account_balance + amount;
        self.accounts.insert(account_id, &new_balance);

        logger::log_user_balance(&self, account_id, new_balance);
        logger::log_token_status(&self);
    }


    /**
     * @notice burn specific amount of tokens for an account
     * @param account_id the account_id to burn tokens for
     * @param amount the amount of tokens to burn
     */
    pub fn burn(
        &mut self, 
        account_id: &AccountId, 
        amount: Balance
    ) {
        let mut balance = self.accounts.get(&account_id).unwrap_or(0);

        assert!(balance >= amount, "ERR_INSUFFICIENT_BALANCE");

        balance -= amount;
        self.accounts.insert(account_id, &balance);
        self.total_supply -= amount;

        logger::log_user_balance(&self, &account_id, balance);
        logger::log_token_status(&self);
    }

    /**
     * @notice deposit tokens into an account
     * @param account_id the account_id to deposit into
     * @param amount the amount of tokens to deposit
     */
    pub fn deposit(
        &mut self, 
        receiver_id: &AccountId, 
        amount: Balance
    ) {
        assert!(amount > 0, "Cannot deposit 0 or lower");

        let receiver_balance = self.accounts.get(&receiver_id).unwrap_or(0);
        let new_balance = receiver_balance + amount;

        self.accounts.insert(&receiver_id, &new_balance);
        logger::log_user_balance(&self, &receiver_id, new_balance);
    }

    /**
     * @notice withdraw token from an account
     * @param account_id to withdraw from
     * @param amount of tokens to withdraw
     */
    pub fn withdraw(
        &mut self, 
        sender_id: &AccountId, 
        amount: Balance
    ) {
        let sender_balance = self.accounts.get(&sender_id).unwrap_or(0);

        assert!(amount > 0, "Cannot withdraw 0 or lower");
        assert!(sender_balance >= amount, "Not enough balance");

        let new_balance = sender_balance - amount;
        self.accounts.insert(&sender_id, &new_balance);
        logger::log_user_balance(&self, &sender_id, new_balance);
    }
}

//TODO: this extra struct makes 0 sense should just create 1 struct + impl and make certain functions private (only providing comments for unique functions for now)

#[derive(BorshDeserialize, BorshSerialize)]
pub struct MintableFungibleToken {
    pub token: MintableToken,
}

impl Default for MintableFungibleToken {
    fn default() -> Self {
        panic!("Contract should be initialized before usage")
    }
}

impl MintableFungibleToken {
    pub fn new(pool_id: u64, outcome_id: u16, initial_supply: Balance,) -> Self {
        Self {
            token: MintableToken::new(pool_id, outcome_id, initial_supply),
        }
    }

    /**
     * @notice returns account's balance
     * @param account_id is the account_id to return the balance of
     * @returns `accoun_id`s balance
     */
    pub fn get_balance(
        &self, 
        account_id: &AccountId
    ) -> Balance {
        self.token.accounts.get(account_id).unwrap_or(0)
    }

    /**
     * @returns token's total supply
     */
    pub fn total_supply(&self) -> Balance {
        self.token.total_supply
    }

    pub fn mint(&mut self, account_id: &AccountId, amount: Balance) {
        self.token.mint(account_id, amount);
    }

    pub fn burn(&mut self, account_id: &AccountId, amount: Balance) {
        self.token.burn(account_id, amount);
    }

    /**
     * @notice clear out account's balance
     * @returns an optional balance of the account, `None` if the account had no balance
     */
    pub fn remove_account(
        &mut self, 
        account_id: &AccountId
    ) -> Option<Balance> {
        self.token.accounts.remove(account_id)
    }

    // TODO: more consistent transfer, only need `safe_transfer_internal`

    /**
     * @notice transfer tokens from one account to another
     * @param receiver_id is the account that should receive the tokens
     * @param amount of tokens to transfer from predecessor to receiver
     */
    pub fn transfer(
        &mut self, 
        receiver_id: &AccountId, 
        amount: Balance
    ) {
        self.token.withdraw(&env::predecessor_account_id(), amount);
        self.token.deposit(receiver_id, amount);
    }

    /**
     * @notice transfer tokens from one account to another
     * @param sender is the account that's sending the tokens
     * @param receiver_id is the account that should receive the tokens
     * @param amount of tokens to transfer from sender to receiver
     */
    pub fn safe_transfer_internal(
        &mut self, 
        sender: &AccountId, 
        receiver_id: &AccountId, 
        amount: Balance
    ) {
        self.token.withdraw(sender, amount);
        self.token.deposit(receiver_id, amount);
    }

}
