//! Type definitions for the ZKP set membership system.

use crate::utils::{bytes_to_field, field_to_bytes, poseidon_hash};
use anyhow::{Context, Result};
use log::debug;
use pasta_curves::pallas;
use serde::{Deserialize, Serialize};

// Hash output size in bytes (32 bytes = 256 bits).
// Matches the Pallas field element size, which is the field used for all
// cryptographic operations in this ZKP system.
pub const HASH_SIZE: usize = 32;

/// Public inputs for ZK proof verification.
///
/// Contains the public input values that were committed to in the circuit.
/// These values must match between proof generation and verification.
///
/// # Note on Naming
///
/// Despite its name, this struct is not the Halo2 "verifying key" (which is
/// a cryptographic key used to verify proofs). Instead, it contains the public
/// input values that were committed to when generating the proof.
///
/// The values in this struct (`leaf`, `root`, `nullifier`) must match exactly
/// between the prover and verifier for verification to succeed.
///
/// # Relationship to `ZKProofOutput`
///
/// In `ZKProofOutput`, the `merkle_root` field contains the same value as
/// `verification_key.root`. Both represent the Merkle tree root. The
/// `verification_key` struct groups all public inputs together for clarity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationKey {
    /// Leaf value as hex string (32 bytes = 64 hex chars).
    ///
    /// This is the leaf in the Merkle tree that the prover claims membership of.
    pub leaf: String,
    /// Merkle root as hex string (32 bytes = 64 hex chars).
    ///
    /// This is the root of the Merkle tree containing the leaf.
    /// Note: This value is the same as `ZKProofOutput.merkle_root`.
    pub root: String,
    /// Nullifier as hex string (H(leaf || root)).
    ///
    /// Deterministic hash computed from leaf and root, used for replay attack prevention.
    pub nullifier: String,
}

/// Output structure for zero-knowledge proofs.
///
/// Contains all data needed to verify a set membership proof including
/// the Merkle proof, ZK-SNARK proof, and nullifier for replay attack prevention.
///
/// # Public Input Consistency
///
/// The following values represent the same data:
/// - `merkle_root` == `verification_key.root` (both are the Merkle tree root)
///
/// When verifying, the verifier should use:
/// - `merkle_root` for the Merkle root
/// - `verification_key.leaf` for the leaf value
/// - `verification_key.nullifier` for the nullifier
///
/// All three values together form the public inputs to the circuit.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZKProofOutput {
    /// Merkle root hash as hex string (32 bytes = 64 hex chars).
    ///
    /// This is the root of the Merkle tree. It is the same value as
    /// `verification_key.root` - both can be used interchangeably.
    pub merkle_root: String,
    /// Deterministic nullifier hash as hex string (H(leaf || root)).
    ///
    /// Used for replay attack prevention. The same nullifier is also stored
    /// in `verification_key.nullifier`.
    pub nullifier: String,
    /// Raw ZK-SNARK proof bytes
    pub zkp_proof: Vec<u8>,
    /// Verification key containing the public input commitments.
    ///
    /// Contains `leaf`, `root`, and `nullifier` values. Note that `root`
    /// is the same as `merkle_root` in this struct.
    pub verification_key: VerificationKey,
    /// Index of the proven leaf in the original set
    pub leaf_index: usize,
    /// Unix timestamp when proof was generated
    pub timestamp: u64,
    /// Merkle path siblings as hex strings (for verification)
    pub merkle_siblings: Vec<String>,
}

impl ZKProofOutput {
    // Acceptable clock drift in seconds to account for system clock skew
    const DEFAULT_TIMESTAMP_TOLERANCE_SECS: u64 = 30;
    // Maximum proof age in seconds (24 hours) to prevent use of expired proofs
    const DEFAULT_TIMESTAMP_MAX_AGE_SECS: u64 = 86400;

    fn get_timestamp_tolerance() -> u64 {
        std::env::var("ZKP_TIMESTAMP_TOLERANCE_SECS")
            .ok()
            .and_then(|s| {
                let parsed = s.parse::<u64>();
                if parsed.is_err() {
                    log::warn!(
                        "Invalid ZKP_TIMESTAMP_TOLERANCE_SECS value '{}', using default {}",
                        s,
                        Self::DEFAULT_TIMESTAMP_TOLERANCE_SECS
                    );
                }
                parsed.ok()
            })
            .unwrap_or(Self::DEFAULT_TIMESTAMP_TOLERANCE_SECS)
    }

    fn get_timestamp_max_age() -> u64 {
        std::env::var("ZKP_TIMESTAMP_MAX_AGE_SECS")
            .ok()
            .and_then(|s| {
                let parsed = s.parse::<u64>();
                if parsed.is_err() {
                    log::warn!(
                        "Invalid ZKP_TIMESTAMP_MAX_AGE_SECS value '{}', using default {}",
                        s,
                        Self::DEFAULT_TIMESTAMP_MAX_AGE_SECS
                    );
                }
                parsed.ok()
            })
            .unwrap_or(Self::DEFAULT_TIMESTAMP_MAX_AGE_SECS)
    }

    /// Validates the proof output structure and cryptographic consistency.
    ///
    /// Performs comprehensive validation including:
    /// - Field presence and non-empty checks
    /// - Timestamp validation (not too old or in future)
    /// - Hex encoding validation
    /// - Byte length verification
    /// - Cryptographic consistency (nullifier matches H(leaf || root))
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
                "Merkle root cannot be empty. Expected a {HASH_SIZE}-byte hex string."
            ));
        }
        if self.nullifier.is_empty() {
            return Err(anyhow::anyhow!(
                "Nullifier cannot be empty. Expected a {HASH_SIZE}-byte hex string."
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
            .map_err(|e| anyhow::anyhow!("System clock unavailable: {e}"))?;
        debug!("Current timestamp: {current_timestamp}");

        let timestamp_tolerance = Self::get_timestamp_tolerance();
        if self.timestamp > current_timestamp + timestamp_tolerance {
            return Err(anyhow::anyhow!(
                "Timestamp is too far in the future: {} (current: {}, tolerance: {}s). Please check system clock and proof timestamp.",
                self.timestamp,
                current_timestamp,
                timestamp_tolerance
            ));
        }

        let timestamp_max_age = Self::get_timestamp_max_age();
        if current_timestamp > self.timestamp + timestamp_max_age {
            return Err(anyhow::anyhow!(
                "Timestamp is too old: {} (current: {}, max age: {}s). This proof may be expired. Please generate a fresh proof.",
                self.timestamp,
                current_timestamp,
                timestamp_max_age
            ));
        }

        let leaf_hex = &self.verification_key.leaf;
        let leaf_bytes = hex::decode(leaf_hex).map_err(|e| {
            anyhow::anyhow!(
                "Invalid leaf hex '{leaf_hex}': {e}. Expected {HASH_SIZE}-byte hex string."
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
///
/// # Examples
///
/// ```
/// use zkp_set_membership::types::compute_nullifier;
///
/// let leaf = [1u8; 32];
/// let root = [2u8; 32];
/// let nullifier = compute_nullifier(&leaf, &root).unwrap();
/// assert_eq!(nullifier.len(), 32);
///
/// // Same inputs produce same nullifier (deterministic)
/// let nullifier2 = compute_nullifier(&leaf, &root).unwrap();
/// assert_eq!(nullifier, nullifier2);
/// ```
pub fn compute_nullifier(leaf_bytes: &[u8], merkle_root: &[u8]) -> Result<[u8; HASH_SIZE]> {
    let leaf_arr: [u8; HASH_SIZE] = leaf_bytes.try_into().map_err(|_| {
        anyhow::anyhow!(
            "Leaf must be exactly {} bytes, got {} bytes",
            HASH_SIZE,
            leaf_bytes.len()
        )
    })?;
    let root_arr: [u8; HASH_SIZE] = merkle_root.try_into().map_err(|_| {
        anyhow::anyhow!(
            "Root must be exactly {} bytes, got {} bytes",
            HASH_SIZE,
            merkle_root.len()
        )
    })?;

    let leaf_field = bytes_to_field(&leaf_arr);
    let root_field = bytes_to_field(&root_arr);
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
///
/// # Examples
///
/// ```
/// use zkp_set_membership::types::compute_nullifier_from_fields;
/// use pasta_curves::pallas;
///
/// let leaf = pallas::Base::from(42);
/// let root = pallas::Base::from(100);
/// let nullifier = compute_nullifier_from_fields(leaf, root);
/// assert_ne!(nullifier, pallas::Base::zero());
/// ```
#[must_use]
#[inline]
pub fn compute_nullifier_from_fields(leaf: pallas::Base, root: pallas::Base) -> pallas::Base {
    poseidon_hash(leaf, root)
}

/// Converts a variable-length byte slice to 32 bytes.
///
/// If the input is < 32 bytes, pads with zeros on the right.
///
/// # Arguments
///
/// * `bytes` - Byte slice to normalize (must be <= 32 bytes)
///
/// # Returns
///
/// 32-byte array with zero-padding if input is shorter
///
/// # Errors
///
/// Returns an error if input length exceeds 32 bytes
///
/// # Examples
///
/// ```
/// use zkp_set_membership::types::normalize_to_32_bytes;
///
/// let input = vec![1u8, 2, 3];
/// let result = normalize_to_32_bytes(&input).unwrap();
/// assert_eq!(result[0..3], [1, 2, 3]);
/// assert_eq!(result[3..], [0u8; 29]);
/// ```
#[inline]
pub fn normalize_to_32_bytes(bytes: &[u8]) -> Result<[u8; HASH_SIZE]> {
    if bytes.len() > HASH_SIZE {
        return Err(anyhow::anyhow!(
            "Input must be at most {} bytes, got {}",
            HASH_SIZE,
            bytes.len()
        ));
    }
    let mut arr = [0u8; HASH_SIZE];
    arr[..bytes.len()].copy_from_slice(bytes);
    Ok(arr)
}
