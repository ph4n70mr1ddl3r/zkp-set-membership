//! Type definitions for the ZKP set membership system.

use anyhow::Result;
use halo2_gadgets::poseidon::primitives::{
    self as poseidon, ConstantLength, P128Pow5T3 as PoseidonSpec,
};
use pasta_curves::group::ff::PrimeField;
use pasta_curves::pallas;
use serde::{Deserialize, Serialize};

pub const HASH_SIZE: usize = 32;

/// Verification key data for ZK proof verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationKey {
    pub leaf: String,
    pub root: String,
    pub nullifier: String,
}

/// Output structure for zero-knowledge proofs.
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

        const TIMESTAMP_TOLERANCE_SECS: u64 = 300;
        const TIMESTAMP_MAX_AGE_SECS: u64 = 86400;

        if self.timestamp > current_timestamp + TIMESTAMP_TOLERANCE_SECS {
            return Err(anyhow::anyhow!(
                "Timestamp is too far in the future: {} (current: {}, tolerance: {}s)",
                self.timestamp,
                current_timestamp,
                TIMESTAMP_TOLERANCE_SECS
            ));
        }

        if current_timestamp > self.timestamp + TIMESTAMP_MAX_AGE_SECS {
            return Err(anyhow::anyhow!(
                "Timestamp is too old: {} (current: {}, max age: {}s)",
                self.timestamp,
                current_timestamp,
                TIMESTAMP_MAX_AGE_SECS
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

        // Verify nullifier matches expected value
        let expected_nullifier = compute_nullifier(&leaf_bytes, &root_bytes);
        if self.nullifier != hex::encode(expected_nullifier) {
            return Err(anyhow::anyhow!(
                "Nullifier mismatch: expected {}, got {}",
                hex::encode(expected_nullifier),
                self.nullifier
            ));
        }

        Ok(())
    }
}

/// Compute nullifier as H(leaf || root) using Poseidon hash
pub fn compute_nullifier(leaf_bytes: &[u8], merkle_root: &[u8]) -> [u8; HASH_SIZE] {
    // Convert bytes to field elements
    let leaf_field = bytes_to_field(leaf_bytes);
    let root_field = bytes_to_field(merkle_root);

    // Compute Poseidon hash
    let hash_field = poseidon_hash(leaf_field, root_field);

    // Convert back to bytes
    field_to_bytes(hash_field)
}

/// Compute nullifier directly from field elements
pub fn compute_nullifier_from_fields(leaf: pallas::Base, root: pallas::Base) -> pallas::Base {
    poseidon_hash(leaf, root)
}

/// Converts 32 bytes to a field element in the Pallas curve.
fn bytes_to_field(bytes: &[u8]) -> pallas::Base {
    // Take exactly 32 bytes or pad with zeros
    let bytes_32: [u8; 32] = if bytes.len() >= 32 {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes[..32]);
        arr
    } else {
        let mut arr = [0u8; 32];
        arr[..bytes.len()].copy_from_slice(bytes);
        arr
    };

    // Use the same conversion as the circuit module
    use crate::circuit::bytes_to_field as circuit_bytes_to_field;
    circuit_bytes_to_field(&bytes_32)
}

/// Converts a field element back to 32 bytes
fn field_to_bytes(field: pallas::Base) -> [u8; HASH_SIZE] {
    // For the pasta curves, we can use the to_repr() method
    // This converts the field element to its canonical byte representation
    let mut bytes = [0u8; 32];
    let repr = field.to_repr();
    bytes.copy_from_slice(repr.as_ref());
    bytes
}

/// Poseidon hash of two field elements
fn poseidon_hash(left: pallas::Base, right: pallas::Base) -> pallas::Base {
    let inputs = [left, right];
    poseidon::Hash::<_, PoseidonSpec, ConstantLength<2>, 3, 2>::init().hash(inputs)
}
