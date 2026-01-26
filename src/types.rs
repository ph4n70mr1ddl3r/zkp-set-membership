//! Type definitions for the ZKP set membership system.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::collections::HashMap;

/// Output structure for zero-knowledge proofs.
///
/// Contains all the information needed to verify a set membership proof,
/// including the Merkle root, nullifier, ZK proof, and verification data.
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

        if let Some(leaf_hex) = self.verification_key.get("leaf") {
            let leaf_bytes =
                hex::decode(leaf_hex).map_err(|_| anyhow::anyhow!("Invalid leaf hex"))?;
            let root_bytes = hex::decode(&self.merkle_root)
                .map_err(|_| anyhow::anyhow!("Invalid merkle root hex"))?;

            let expected_nullifier = compute_nullifier(&leaf_bytes, &root_bytes);
            let expected_nullifier_hex = hex::encode(expected_nullifier);

            if self.nullifier != expected_nullifier_hex {
                return Err(anyhow::anyhow!(
                    "Nullifier mismatch: expected {}, got {}",
                    expected_nullifier_hex,
                    self.nullifier
                ));
            }
        }

        Ok(())
    }
}

fn compute_nullifier(leaf_bytes: &[u8], merkle_root: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(leaf_bytes);
    hasher.update(merkle_root);
    hasher.finalize().into()
}
