//! Merkle tree implementation for set membership proofs using Poseidon hash.
//!
//! This module provides a binary Merkle tree implementation using Poseidon hash
//! for efficient in-circuit verification. It supports proof generation and
//! verification for set membership.

use crate::utils::{bytes_to_field, field_to_bytes, poseidon_hash};
use std::fmt;

const HASH_SIZE: usize = 32;

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
/// let tree = MerkleTree::new(leaves.clone());
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

impl MerkleTree {
    /// Create a new Merkle tree from a list of leaves.
    ///
    /// # Arguments
    /// * `leaves` - Vector of 32-byte leaf values
    ///
    /// # Returns
    /// A MerkleTree instance with computed root hash
    ///
    /// # Note
    /// For optimal performance, the number of leaves should be a power of 2.
    /// If not, the tree will handle it by propagating odd nodes up.
    pub fn new(leaves: Vec<[u8; HASH_SIZE]>) -> Self {
        let root = Self::compute_root(&leaves);
        MerkleTree { root, leaves }
    }

    fn compute_root(leaves: &[[u8; HASH_SIZE]]) -> [u8; HASH_SIZE] {
        let mut level = leaves.to_vec();

        while level.len() > 1 {
            let new_level_capacity = level.len().div_ceil(2);
            let mut new_level = Vec::with_capacity(new_level_capacity);
            for i in (0..level.len()).step_by(2) {
                if i + 1 < level.len() {
                    let hash = hash_pair(&level[i], &level[i + 1]);
                    new_level.push(hash);
                } else {
                    new_level.push(level[i]);
                }
            }
            level = new_level;
        }

        if level.is_empty() {
            [0u8; HASH_SIZE]
        } else {
            level[0]
        }
    }

    /// Generate a Merkle proof for a leaf at the given index.
    ///
    /// # Arguments
    /// * `leaf_index` - Index of the leaf to prove inclusion for
    ///
    /// # Returns
    /// `Some(MerkleProof)` if the index is valid, `None` otherwise
    #[must_use]
    pub fn generate_proof(&self, leaf_index: usize) -> Option<MerkleProof> {
        if leaf_index >= self.leaves.len() {
            return None;
        }

        let mut siblings = Vec::new();
        let mut level: Vec<[u8; HASH_SIZE]> = self.leaves.to_vec();
        let mut index = leaf_index;

        while level.len() > 1 {
            let is_right = !index.is_multiple_of(2);
            let sibling_index = if is_right { index - 1 } else { index + 1 };

            if sibling_index < level.len() {
                siblings.push(level[sibling_index]);
            }

            let mut new_level = Vec::new();
            for i in (0..level.len()).step_by(2) {
                if i + 1 < level.len() {
                    let hash = hash_pair(&level[i], &level[i + 1]);
                    new_level.push(hash);
                } else {
                    new_level.push(level[i]);
                }
            }

            index /= 2;
            level = new_level;
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
    /// It does not verify that the leaf_index is valid for this tree.
    #[must_use]
    pub fn verify_proof(&self, proof: &MerkleProof) -> bool {
        if proof.root != self.root {
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
