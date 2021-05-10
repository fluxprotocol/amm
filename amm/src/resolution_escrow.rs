use crate::*;
use near_sdk::Balance;

#[derive(BorshDeserialize, BorshSerialize)]
pub struct OutcomeToBalanceMap(LookupMap<u16, Balance>);

impl OutcomeToBalanceMap {
    pub fn new(uid: Vec<u8>) -> Self {
        Self(LookupMap::new(uid))
    }

    pub fn decrement(&mut self, outcome: u16, amount: Balance) -> Balance {
        let current_val = self.get(outcome);
        let new_val = current_val - amount;
        self.0.insert(&outcome, &new_val);
        new_val
    }

    pub fn increment(&mut self, outcome: u16, amount: Balance) -> Balance {
        let current_val = self.get(outcome);
        let new_val = current_val + amount;
        self.0.insert(&outcome, &new_val);
        new_val
    }

    pub fn get(&self, outcome: u16) -> Balance {
        self.0.get(&outcome).unwrap_or(0)
    }
}

#[derive(BorshDeserialize, BorshSerialize)]
pub struct ResolutionEscrows { 
    escrow_accounts: LookupMap<AccountId, ResolutionEscrow>,
    pool_id: u64
}

impl ResolutionEscrows {
    pub fn new(pool_id: u64) -> Self {
        ResolutionEscrows { 
            escrow_accounts: LookupMap::new(format!("p{}re", pool_id).as_bytes().to_vec()),
            pool_id
        }
    }

    
    pub fn get(&self, account_id: &AccountId) -> Option<ResolutionEscrow> {
        self.escrow_accounts.get(&account_id)
    }
    
    pub fn get_expect(&self, account_id: &AccountId) -> ResolutionEscrow {
        self.escrow_accounts.get(&account_id).expect("sender does not hold any lp positions in this pool")
    }
    
    pub fn get_or_new(&self, account_id: AccountId) -> ResolutionEscrow {
        self.escrow_accounts.get(&account_id).unwrap_or(ResolutionEscrow::new(account_id, self.pool_id))
    }
    
    pub fn remove(&mut self, account_id: &AccountId ) {
        self.escrow_accounts.remove(account_id);
    }

    pub fn insert(&mut self, account_id: &AccountId, escrow_account: &ResolutionEscrow) {
        self.escrow_accounts.insert(account_id, escrow_account);
    }
}

#[derive(BorshDeserialize, BorshSerialize)]
pub struct ResolutionEscrow {
    uid: String,
    pub valid: Balance,
    pub invalid: Balance,
    lp_spent: OutcomeToBalanceMap,
    spent: OutcomeToBalanceMap,
}

impl ResolutionEscrow {
    pub fn new(account_id: AccountId, pool_id: u64) -> Self {
        Self {
            uid: format!("{}_{}", account_id, pool_id),
            valid: 0,
            invalid: 0,
            lp_spent: OutcomeToBalanceMap::new(format!("p{}_ls_{}", pool_id, account_id).as_bytes().to_vec()),
            spent: OutcomeToBalanceMap::new(format!("p{}_s_{}", pool_id, account_id).as_bytes().to_vec())
        }
    }

    pub fn get_spent(&self, outcome: u16) -> Balance {
        self.spent.get(outcome)
    }

    pub fn get_lp_spent(&self, outcome: u16) -> Balance {
        self.lp_spent.get(outcome)
    }

    pub fn sub_from_spent(&mut self, outcome: u16, amount: Balance) -> Balance {
       self.spent.decrement(outcome, amount)
    }

    pub fn add_to_spent(&mut self, outcome: u16, amount: Balance) -> Balance {
       self.spent.increment(outcome, amount)
    }
    
    pub fn sub_from_lp_spent(&mut self, outcome: u16, amount: Balance) -> Balance {
        self.lp_spent.decrement(outcome, amount)
    }

    pub fn add_to_lp_spent(&mut self, outcome: u16, amount: Balance) -> Balance {
       self.lp_spent.increment(outcome, amount)
    }

    pub fn add_to_escrow_invalid(&mut self, amount: Balance) -> Balance {
        self.invalid += amount;
        self.invalid
    }
    
    pub fn add_to_escrow_valid(&mut self, amount: Balance) -> Balance {
        self.valid += amount;
        self.valid
    }
    
    pub fn sub_from_escrow_invalid(&mut self, amount: Balance) -> Balance {
        self.invalid -= amount;
        self.invalid
    }

    pub fn sub_from_escrow_valid(&mut self, amount: Balance) -> Balance {
        self.valid -= amount;
        self.valid
    }

    

    pub fn lp_on_exit(
        &mut self,
        outcome: u16,
        spent_on_exit_shares: Balance
    ) -> Balance {
        // Account for updated lp spent
        self.sub_from_lp_spent(outcome, spent_on_exit_shares);
        
        // Account for updated spent
        self.add_to_spent(outcome, spent_on_exit_shares)
    }

    pub fn lp_on_join(
        &mut self, 
        outcome: u16, 
        spent_on_outcome: Balance,
        spent_on_amount_out: Balance
    ) -> Balance {
        let lp_spent_to_add = spent_on_outcome - spent_on_amount_out;
        self.add_to_lp_spent(outcome, lp_spent_to_add);

        self.add_to_spent(outcome, spent_on_amount_out)
    }
}
