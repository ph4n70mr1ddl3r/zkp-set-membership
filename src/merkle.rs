//! Merkle tree implementation for set membership proofs using Poseidon hash.
//!
//! This module provides a binary Merkle tree implementation using Poseidon hash
//! for efficient in-circuit verification. It supports proof generation and
//! verification for set membership.

use crate::types::HASH_SIZE;
use crate::utils::{bytes_to_field, field_to_bytes, poseidon_hash};
use anyhow;
use std::fmt;

const MAX_LEAVES: usize = 4096;

/// A Merkle proof for leaf inclusion.
///
/// Contains the leaf value, root hash, sibling hashes, and leaf index needed
/// to verify that a specific leaf is included in the Merkle tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MerkleProof {
    pub leaf: [u8; HASH_SIZE],
    pub root: [u8; HASH_SIZE],
    pub siblings: Vec<[u8; HASH_SIZE]>,
    pub index: usize,
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

#[inline]
fn hash_pair(left: &[u8; HASH_SIZE], right: &[u8; HASH_SIZE]) -> [u8; HASH_SIZE] {
    let left_field = bytes_to_field(left);
    let right_field = bytes_to_field(right);
    let hash_field = poseidon_hash(left_field, right_field);
    field_to_bytes(hash_field)
}

fn compute_next_level(level: &[[u8; HASH_SIZE]]) -> Vec<[u8; HASH_SIZE]> {
    level
        .chunks(2)
        .map(|chunk| {
            if chunk.len() == 2 {
                hash_pair(&chunk[0], &chunk[1])
            } else {
                chunk[0]
            }
        })
        .collect()
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
    /// Returns an error if number of leaves exceeds MAX_LEAVES (4096).
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
            return Err(anyhow::anyhow!("Empty Merkle trees are not allowed"));
        }
        if leaves.len() > MAX_LEAVES {
            return Err(anyhow::anyhow!(
                "Number of leaves {} exceeds maximum allowed {}",
                leaves.len(),
                MAX_LEAVES
            ));
        }
        let root = Self::compute_root(&leaves);
        Ok(MerkleTree { root, leaves })
    }

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
        let mut level = self.leaves.clone();
        let mut index = leaf_index;

        while level.len() > 1 {
            let is_right = !index.is_multiple_of(2);
            let sibling_index = if is_right { index - 1 } else { index + 1 };

            if sibling_index < level.len() {
                siblings.push(level[sibling_index]);
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
        if proof.root != self.root {
            return false;
        }

        if proof.index >= self.leaves.len() {
            return false;
        }

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

        current_hash == self.root
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
