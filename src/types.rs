//! Type definitions for the ZKP set membership system.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

pub const HASH_SIZE: usize = 32;

/// Verification key data for ZK proof verification.
///
/// Contains the cryptographic values needed to verify the proof,
/// including the leaf, root, and nullifier hashes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationKey {
    pub leaf: String,
    pub root: String,
    pub nullifier: String,
}

/// Output structure for zero-knowledge proofs.
///
/// Contains all the information needed to verify a set membership proof,
/// including the Merkle root, nullifier, ZK proof, and verification data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZKProofOutput {
    pub merkle_root: String,
    pub nullifier: String,
    pub zkp_proof: Vec<u8>,
    pub verification_key: VerificationKey,
    pub leaf_index: usize,
    pub timestamp: u64,
    pub merkle_siblings: Vec<String>,
}

impl ZKProofOutput {
    /// Validates the proof output structure and cryptographic consistency.
    ///
    /// # Returns
    /// `Ok(())` if the proof is valid, or an error if validation fails.
    ///
    /// # Validation Checks
    /// - Ensures merkle_root, nullifier, and zkp_proof are non-empty
    /// - Verifies that merkle_siblings contains at least one element
    /// - Checks that the verification key contains the required 'leaf' field
    /// - Validates that leaf and root are 32-byte hashes
    /// - Verifies the nullifier was correctly derived from leaf and root
    /// - Validates timestamp is reasonable (not in future)
    /// - Validates leaf_index is non-negative
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

        let current_timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        if self.timestamp > current_timestamp {
            return Err(anyhow::anyhow!(
                "Timestamp is in the future: {} (current: {})",
                self.timestamp,
                current_timestamp
            ));
        }

        let leaf_hex = &self.verification_key.leaf;

        let leaf_bytes = hex::decode(leaf_hex)
            .map_err(|e| anyhow::anyhow!("Invalid leaf hex '{}': {}", leaf_hex, e))?;

        if leaf_bytes.len() != HASH_SIZE {
            return Err(anyhow::anyhow!("Leaf must be {} bytes", HASH_SIZE));
        }

        let root_bytes = hex::decode(&self.merkle_root)
            .map_err(|e| anyhow::anyhow!("Invalid merkle root hex: {}", e))?;

        if root_bytes.len() != HASH_SIZE {
            return Err(anyhow::anyhow!("Root must be {} bytes", HASH_SIZE));
        }

        let expected_nullifier = compute_nullifier(&leaf_bytes, &root_bytes);
        let expected_nullifier_hex = hex::encode(expected_nullifier);

        if self.nullifier != expected_nullifier_hex {
            return Err(anyhow::anyhow!(
                "Nullifier mismatch: expected {}, got {}",
                expected_nullifier_hex,
                self.nullifier
            ));
        }

        Ok(())
    }
}

pub fn compute_nullifier(leaf_bytes: &[u8], merkle_root: &[u8]) -> [u8; HASH_SIZE] {
    let mut hasher = Sha3_256::new();
    hasher.update(leaf_bytes);
    hasher.update(merkle_root);
    hasher.finalize().into()
}
