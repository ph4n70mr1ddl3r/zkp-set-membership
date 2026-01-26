use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZKProofOutput {
    pub merkle_root: String,
    pub nullifier: String,
    pub zkp_proof: Vec<u8>,
    pub verification_key: HashMap<String, String>,
    pub leaf_index: usize,
    pub timestamp: u64,
    pub merkle_siblings: Vec<String>,
}

impl ZKProofOutput {
    pub fn validate(&self) -> Result<()> {
        if self.merkle_root.is_empty() {
            return Err(anyhow::anyhow!("Merkle root cannot be empty"));
        }
        if self.nullifier.is_empty() {
            return Err(anyhow::anyhow!("Nullifier cannot be empty"));
        }
        if self.zkp_proof.is_empty() {
            return Err(anyhow::anyhow!("ZK proof cannot be empty"));
        }
        if self.merkle_siblings.is_empty() {
            return Err(anyhow::anyhow!("Merkle siblings cannot be empty"));
        }
        Ok(())
    }
}

/// Represents an Ethereum account with its address.
///
/// This type is provided for future use cases where structured account data
/// is needed. Currently, addresses are handled as strings throughout the codebase.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EthereumAccount {
    pub address: String,
}
