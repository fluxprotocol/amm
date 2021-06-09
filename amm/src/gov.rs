use crate::*;

#[near_bindgen]
impl AMMContract {
    /**
     * @returns the current governance `AccountId`
     */
    pub fn gov(&self) -> AccountId {
        self.gov.to_string()
    }

    /**
     * @notice sets the `oracle` account id
     * @param `new_oracle` The new oracle
     */
    pub fn set_oracle(
        &mut self, 
        new_oracle: ValidAccountId
    ) {
        self.assert_gov();
        self.oracle = new_oracle.into();
    }

    /**
     * @notice sets the `gov` `AccountId`, only callable by previous gov
     * @param `AccountId` of the new `gov`
     */
    pub fn set_gov(
        &mut self,
        new_gov: ValidAccountId
    ) {
        self.assert_gov();
        self.gov = new_gov.into();
    }

    /**
     * @notice pauses the protocol making certain functions un-callable, can only be called by `gov`
     */
    pub fn pause(&mut self) {
        self.assert_gov();
        self.paused = true;
    }

    /**
     * @notice un-pauses the protocol making it fully operational again
     */
    pub fn unpause(&mut self) {
        self.assert_gov();
        self.paused = false;
    }
}


/*** Private methods ***/
impl AMMContract {
    /**
     * @panics if the predecessor account is not `gov`
     */
    pub fn assert_gov(&self) {
        assert_eq!(env::predecessor_account_id(), self.gov, "ERR_NO_GOVERNANCE_ADDRESS");
    }

    /**
     * @panics if the protocol is paused
     */
    pub fn assert_unpaused(&self) {
        assert!(!self.paused, "ERR_PROTCOL_PAUSED")
    }

    /**
     * @panics if the predecessor is not the oracle
     */
    pub fn assert_oracle(&self) {
        assert_eq!(env::predecessor_account_id(), self.oracle, "ERR_NO_ORACLE_ADDRESS");
    }
}