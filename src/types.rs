//! Type definitions for the ZKP set membership system.

use crate::utils::{bytes_to_field, field_to_bytes, poseidon_hash};
use anyhow::{Context, Result};
use log::debug;
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
    const TIMESTAMP_TOLERANCE_SECS: u64 = 30;
    const TIMESTAMP_MAX_AGE_SECS: u64 = 86400;

    /// Validates the proof output structure and cryptographic consistency.
    ///
    /// # Errors
    /// Returns an error if validation fails, including:
    /// - Empty or invalid fields
    /// - Timestamp out of valid range
    /// - Nullifier mismatch
    /// - Invalid hex encoding
    /// - Incorrect byte lengths
    pub fn validate(&self) -> Result<()> {
        debug!("Starting proof output validation");
        debug!("Merkle root length: {}", self.merkle_root.len());
        debug!("Nullifier length: {}", self.nullifier.len());
        debug!("ZK proof size: {} bytes", self.zkp_proof.len());
        debug!("Leaf index: {}", self.leaf_index);
        debug!("Timestamp: {}", self.timestamp);

        if self.merkle_root.is_empty() {
            return Err(anyhow::anyhow!(
                "Merkle root cannot be empty. Expected a {}-byte hex string.",
                HASH_SIZE
            ));
        }
        if self.nullifier.is_empty() {
            return Err(anyhow::anyhow!(
                "Nullifier cannot be empty. Expected a {}-byte hex string.",
                HASH_SIZE
            ));
        }
        if self.zkp_proof.is_empty() {
            return Err(anyhow::anyhow!(
                "ZK proof cannot be empty. The proof data is missing."
            ));
        }

        let current_timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        debug!("Current timestamp: {}", current_timestamp);

        if self.timestamp > current_timestamp + Self::TIMESTAMP_TOLERANCE_SECS {
            return Err(anyhow::anyhow!(
                "Timestamp is too far in the future: {} (current: {}, tolerance: {}s). Please check system clock and proof timestamp.",
                self.timestamp,
                current_timestamp,
                Self::TIMESTAMP_TOLERANCE_SECS
            ));
        }

        if current_timestamp > self.timestamp + Self::TIMESTAMP_MAX_AGE_SECS {
            return Err(anyhow::anyhow!(
                "Timestamp is too old: {} (current: {}, max age: {}s). This proof may be expired. Please generate a fresh proof.",
                self.timestamp,
                current_timestamp,
                Self::TIMESTAMP_MAX_AGE_SECS
            ));
        }

        let leaf_hex = &self.verification_key.leaf;
        let leaf_bytes = hex::decode(leaf_hex).map_err(|e| {
            anyhow::anyhow!(
                "Invalid leaf hex '{leaf_hex}': {e}. Expected {}-byte hex string.",
                HASH_SIZE
            )
        })?;

        if leaf_bytes.len() != HASH_SIZE {
            return Err(anyhow::anyhow!(
                "Leaf must be exactly {} bytes, but got {} bytes. Please check the leaf value in the verification key.",
                HASH_SIZE,
                leaf_bytes.len()
            ));
        }

        let root_bytes = hex::decode(&self.merkle_root).map_err(|e| {
            anyhow::anyhow!(
                "Invalid merkle root hex '{}': {}. Expected {}-byte hex string.",
                self.merkle_root,
                e,
                HASH_SIZE
            )
        })?;

        if root_bytes.len() != HASH_SIZE {
            return Err(anyhow::anyhow!(
                "Root must be exactly {} bytes, but got {} bytes. Please check the Merkle root value.",
                HASH_SIZE,
                root_bytes.len()
            ));
        }

        // Verify nullifier matches expected value
        let expected_nullifier = compute_nullifier(&leaf_bytes, &root_bytes)
            .context("Failed to compute expected nullifier")?;
        if self.nullifier != hex::encode(expected_nullifier) {
            return Err(anyhow::anyhow!(
                "Nullifier mismatch: expected {}, got {}. The nullifier must equal H(leaf || root). This indicates corrupted or tampered proof data.",
                hex::encode(expected_nullifier),
                self.nullifier
            ));
        }

        Ok(())
    }
}

/// Compute nullifier as H(leaf || root) using Poseidon hash.
///
/// This function takes byte slices and validates they are exactly 32 bytes before
/// computing the Poseidon hash, which serves as a deterministic nullifier
/// to prevent proof replay attacks.
///
/// # Arguments
///
/// * `leaf_bytes` - Leaf value as bytes (must be exactly 32 bytes)
/// * `merkle_root` - Merkle root as bytes (must be exactly 32 bytes)
///
/// # Returns
///
/// 32-byte nullifier hash
///
/// # Errors
///
/// Returns an error if:
/// - `leaf_bytes` is not exactly 32 bytes
/// - `merkle_root` is not exactly 32 bytes
///
/// # Security Considerations
///
/// The nullifier is deterministic and unique for each (leaf, root) pair.
/// Reusing the same leaf with the same root will produce the same nullifier,
/// which enables replay attack detection.
///
/// Inputs longer than 32 bytes are rejected to prevent collision attacks
/// where different inputs could produce the same nullifier.
pub fn compute_nullifier(leaf_bytes: &[u8], merkle_root: &[u8]) -> Result<[u8; HASH_SIZE]> {
    if leaf_bytes.len() != HASH_SIZE {
        return Err(anyhow::anyhow!(
            "Leaf must be exactly {} bytes, got {} bytes",
            HASH_SIZE,
            leaf_bytes.len()
        ));
    }
    if merkle_root.len() != HASH_SIZE {
        return Err(anyhow::anyhow!(
            "Root must be exactly {} bytes, got {} bytes",
            HASH_SIZE,
            merkle_root.len()
        ));
    }

    let leaf_field = bytes_to_field(&normalize_to_32_bytes(leaf_bytes));
    let root_field = bytes_to_field(&normalize_to_32_bytes(merkle_root));
    let hash_field = poseidon_hash(leaf_field, root_field);
    Ok(field_to_bytes(hash_field))
}

/// Compute nullifier directly from field elements.
///
/// This is the field-level version of `compute_nullifier` for use when values
/// are already in field representation.
///
/// # Arguments
///
/// * `leaf` - Leaf value as field element
/// * `root` - Merkle root as field element
///
/// # Returns
///
/// Nullifier as field element
#[must_use]
#[inline]
pub fn compute_nullifier_from_fields(leaf: pallas::Base, root: pallas::Base) -> pallas::Base {
    poseidon_hash(leaf, root)
}

/// Converts a variable-length byte slice to 32 bytes.
///
/// If the input is < 32 bytes, pads with zeros on the right.
/// Caller must ensure input is <= 32 bytes.
///
/// # Arguments
///
/// * `bytes` - Byte slice to normalize (must be <= 32 bytes)
///
/// # Returns
///
/// 32-byte array
#[inline]
const fn normalize_to_32_bytes(bytes: &[u8]) -> [u8; HASH_SIZE] {
    let mut arr = [0u8; HASH_SIZE];
    let len = bytes.len();
    let mut i = 0;
    while i < len {
        arr[i] = bytes[i];
        i += 1;
    }
    arr
}
