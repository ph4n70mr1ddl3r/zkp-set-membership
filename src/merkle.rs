//! Merkle tree implementation for set membership proofs using Poseidon hash.
//!
//! This module provides a binary Merkle tree implementation using Poseidon hash
//! for efficient in-circuit verification. It supports proof generation and
//! verification for set membership.

use crate::types::HASH_SIZE;
use crate::utils::{bytes_to_field, field_to_bytes, poseidon_hash};
use std::fmt;

/// Performs constant-time comparison of two 32-byte arrays.
///
/// This function uses constant-time comparison to prevent timing attacks
/// that could leak information about hash values during proof verification.
///
/// # Security
///
/// The comparison always iterates through all bytes regardless of differences,
/// preventing an attacker from learning partial information through timing analysis.
///
/// # Arguments
///
/// * `a` - First byte array to compare
/// * `b` - Second byte array to compare
///
/// # Returns
///
/// `true` if the arrays are equal, `false` otherwise
#[inline]
fn constant_time_eq(a: &[u8; HASH_SIZE], b: &[u8; HASH_SIZE]) -> bool {
    let mut result = 0u8;
    for i in 0..HASH_SIZE {
        result |= a[i] ^ b[i];
    }
    result == 0
}

const MAX_LEAVES: usize = 1 << 12;

const _: () = {
    assert!(
        MAX_LEAVES == 1 << crate::CIRCUIT_K,
        "MAX_LEAVES must match circuit capacity (1 << CIRCUIT_K)"
    );
};

/// A Merkle proof for leaf inclusion.
///
/// Contains the leaf value, root hash, sibling hashes, and leaf index needed
/// to verify that a specific leaf is included in the Merkle tree.
#[derive(Debug, Clone, Eq)]
pub struct MerkleProof {
    pub leaf: [u8; HASH_SIZE],
    pub root: [u8; HASH_SIZE],
    pub siblings: Vec<[u8; HASH_SIZE]>,
    pub index: usize,
}

impl PartialEq for MerkleProof {
    fn eq(&self, other: &Self) -> bool {
        if self.index != other.index {
            return false;
        }
        if self.siblings.len() != other.siblings.len() {
            return false;
        }
        if !constant_time_eq(&self.leaf, &other.leaf) {
            return false;
        }
        if !constant_time_eq(&self.root, &other.root) {
            return false;
        }
        for (a, b) in self.siblings.iter().zip(other.siblings.iter()) {
            if !constant_time_eq(a, b) {
                return false;
            }
        }
        true
    }
}

/// A binary Merkle tree using Poseidon hash for efficient in-circuit verification.
///
/// This implementation stores the root hash and all leaves, supporting
/// proof generation and verification for set membership.
///
/// # Examples
///
/// ```
/// use zkp_set_membership::merkle::MerkleTree;
///
/// let leaves = vec![[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]];
/// let tree = MerkleTree::new(leaves.clone()).unwrap();
///
/// let proof = tree.generate_proof(0).unwrap();
/// assert!(tree.verify_proof(&proof));
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerkleTree {
    pub root: [u8; HASH_SIZE],
    pub leaves: Vec<[u8; HASH_SIZE]>,
}

/// Computes Poseidon hash of two 32-byte values.
///
/// # Arguments
///
/// * `left` - Left input value (32 bytes)
/// * `right` - Right input value (32 bytes)
///
/// # Returns
///
/// 32-byte hash result
#[inline]
fn hash_pair(left: &[u8; HASH_SIZE], right: &[u8; HASH_SIZE]) -> [u8; HASH_SIZE] {
    let left_field = bytes_to_field(left);
    let right_field = bytes_to_field(right);
    let hash_field = poseidon_hash(left_field, right_field);
    field_to_bytes(hash_field)
}

/// Computes the next level of the Merkle tree from the current level.
///
/// Hashes pairs of adjacent values to compute the parent level.
/// If the level has an odd number of elements, the last element is
/// propagated up without hashing.
///
/// # Arguments
///
/// * `level` - Current level of the Merkle tree
///
/// # Returns
///
/// Next level of the tree with half (or roughly half) the elements
#[inline]
fn compute_next_level(level: &[[u8; HASH_SIZE]]) -> Vec<[u8; HASH_SIZE]> {
    let chunk_count = level.len() / 2 + (level.len() % 2);
    let mut result = Vec::with_capacity(chunk_count);
    for chunk in level.chunks_exact(2) {
        result.push(hash_pair(&chunk[0], &chunk[1]));
    }
    if let Some(remaining) = level.chunks_exact(2).remainder().first() {
        result.push(*remaining);
    }
    result
}

impl MerkleTree {
    /// Create a new Merkle tree from a list of leaves.
    ///
    /// # Arguments
    /// * `leaves` - Vector of 32-byte leaf values
    ///
    /// # Returns
    /// A `MerkleTree` instance with computed root hash
    ///
    /// # Errors
    /// Returns an error if number of leaves exceeds `MAX_LEAVES` (4096).
    ///
    /// # Note
    /// For optimal performance, the number of leaves should be a power of 2.
    /// If not, the tree will handle it by propagating odd nodes up.
    ///
    /// # Examples
    ///
    /// ```
    /// use zkp_set_membership::merkle::MerkleTree;
    ///
    /// let leaves = vec![[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]];
    /// let tree = MerkleTree::new(leaves).unwrap();
    /// assert!(!tree.root.is_empty());
    /// ```
    #[must_use = "The Merkle tree should be used for further operations"]
    pub fn new(leaves: Vec<[u8; HASH_SIZE]>) -> Result<Self, anyhow::Error> {
        if leaves.is_empty() {
            return Err(anyhow::anyhow!(
                "Empty Merkle trees are not allowed. Please provide at least one leaf."
            ));
        }
        if leaves.len() > MAX_LEAVES {
            return Err(anyhow::anyhow!(
                "Number of leaves {} exceeds maximum allowed {}. The circuit capacity is {} leaves (2^{}), which is the limit for CIRCUIT_K={}",
                leaves.len(),
                MAX_LEAVES,
                MAX_LEAVES,
                crate::CIRCUIT_K,
                crate::CIRCUIT_K
            ));
        }
        let root = Self::compute_root(&leaves);
        Ok(MerkleTree { root, leaves })
    }

    #[inline]
    #[must_use]
    fn compute_root(leaves: &[[u8; HASH_SIZE]]) -> [u8; HASH_SIZE] {
        let mut level = leaves.to_vec();

        while level.len() > 1 {
            level = compute_next_level(&level);
        }

        level[0]
    }

    /// Generate a Merkle proof for a leaf at the given index.
    ///
    /// # Arguments
    /// * `leaf_index` - Index of the leaf to prove inclusion for
    ///
    /// # Returns
    /// `Some(MerkleProof)` if the index is valid, `None` otherwise
    ///
    /// # Examples
    ///
    /// ```
    /// use zkp_set_membership::merkle::MerkleTree;
    ///
    /// let leaves = vec![[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]];
    /// let tree = MerkleTree::new(leaves).unwrap();
    ///
    /// let proof = tree.generate_proof(0).unwrap();
    /// assert_eq!(proof.index, 0);
    /// assert!(tree.verify_proof(&proof));
    ///
    /// // Invalid index returns None
    /// assert!(tree.generate_proof(999).is_none());
    /// ```
    #[must_use]
    pub fn generate_proof(&self, leaf_index: usize) -> Option<MerkleProof> {
        if leaf_index >= self.leaves.len() {
            return None;
        }

        let max_depth = self.leaves.len().next_power_of_two().ilog2() as usize;
        let mut siblings = Vec::with_capacity(max_depth);
        let mut level: Vec<[u8; HASH_SIZE]> = Vec::with_capacity(self.leaves.len());
        level.extend_from_slice(&self.leaves);
        let mut index = leaf_index;

        while level.len() > 1 {
            let is_right = index % 2 == 1;
            let sibling_index = if is_right { index - 1 } else { index + 1 };

            if sibling_index < level.len() {
                siblings.push(level[sibling_index]);
            } else if index.is_multiple_of(2) {
                // For non-power-of-two trees, if the node is the last at its level (even index),
                // it serves as its own sibling (propagates up without hashing)
                siblings.push(level[index]);
            }

            index /= 2;
            level = compute_next_level(&level);
        }

        Some(MerkleProof {
            leaf: self.leaves[leaf_index],
            root: self.root,
            siblings,
            index: leaf_index,
        })
    }

    /// Verify a Merkle proof against this tree's root.
    ///
    /// # Arguments
    /// * `proof` - The Merkle proof to verify
    ///
    /// # Returns
    /// `true` if the proof is valid, `false` otherwise
    ///
    /// # Note
    /// This only verifies the cryptographic correctness of the proof.
    /// It does not verify that the `leaf_index` is valid for this tree.
    ///
    /// # Security
    /// This function uses constant-time comparison and completes all operations
    /// before returning to prevent timing attacks that could leak information
    /// about which leaf is being verified.
    ///
    /// # Performance
    /// Verification is O(log n) where n is the number of leaves, as it must
    /// hash through each level of the Merkle tree from leaf to root.
    ///
    /// # Examples
    ///
    /// ```
    /// use zkp_set_membership::merkle::MerkleTree;
    ///
    /// let leaves = vec![[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]];
    /// let tree = MerkleTree::new(leaves).unwrap();
    ///
    /// let proof = tree.generate_proof(0).unwrap();
    /// assert!(tree.verify_proof(&proof));
    /// ```
    #[must_use]
    pub fn verify_proof(&self, proof: &MerkleProof) -> bool {
        let mut valid = 1u8;

        valid &= u8::from(constant_time_eq(&proof.root, &self.root));

        valid &= u8::from(proof.index < self.leaves.len());

        valid &= u8::from(constant_time_eq(
            &proof.leaf,
            &self.leaves.get(proof.index).copied().unwrap_or([0u8; 32]),
        ));

        let mut current_hash = proof.leaf;
        let mut index = proof.index;

        for sibling in &proof.siblings {
            if index.is_multiple_of(2) {
                current_hash = hash_pair(&current_hash, sibling);
            } else {
                current_hash = hash_pair(sibling, &current_hash);
            }
            index /= 2;
        }

        valid &= u8::from(constant_time_eq(&current_hash, &self.root));

        valid != 0
    }
}

impl fmt::Display for MerkleProof {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "MerkleProof:\n  Leaf: {}\n  Root: {}\n  Index: {}\n  Siblings: {}",
            hex::encode(self.leaf),
            hex::encode(self.root),
            self.index,
            self.siblings.len()
        )
    }
}
