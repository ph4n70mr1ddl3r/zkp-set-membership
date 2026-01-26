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

/// Represents an Ethereum account with its address.
///
/// This type is provided for future use cases where structured account data
/// is needed. Currently, addresses are handled as strings throughout the codebase.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EthereumAccount {
    pub address: String,
}
