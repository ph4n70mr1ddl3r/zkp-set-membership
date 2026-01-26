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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EthereumAccount {
    pub address: String,
}
