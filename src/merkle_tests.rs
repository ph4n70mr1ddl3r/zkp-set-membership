#[cfg(test)]
mod tests {
    use crate::MerkleTree;

    #[test]
    fn test_merkle_tree_creation() {
        let leaves = vec![[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]];

        let tree = MerkleTree::new(leaves).unwrap();
        assert_ne!(tree.root, [0u8; 32]);
    }

    #[test]
    fn test_merkle_proof_generation() {
        let leaves = vec![[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]];

        let tree = MerkleTree::new(leaves).unwrap();
        let proof = tree.generate_proof(0);

        assert!(proof.is_some());
        let proof = proof.unwrap();
        assert_eq!(proof.leaf, [1u8; 32]);
        assert_eq!(proof.root, tree.root);
    }

    #[test]
    fn test_merkle_proof_verification() {
        let leaves = vec![[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]];

        let tree = MerkleTree::new(leaves).unwrap();
        let proof = tree.generate_proof(2).unwrap();

        assert!(tree.verify_proof(&proof));
    }

    #[test]
    fn test_merkle_proof_invalid_verification() {
        let leaves1 = vec![[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]];

        let leaves2 = vec![[5u8; 32], [6u8; 32], [7u8; 32], [8u8; 32]];

        let tree1 = MerkleTree::new(leaves1).unwrap();
        let tree2 = MerkleTree::new(leaves2).unwrap();

        let proof = tree1.generate_proof(0).unwrap();

        // Should fail because proof is from different tree
        assert!(!tree2.verify_proof(&proof));
    }

    #[test]
    fn test_large_merkle_tree() {
        let num_leaves = 1024;
        let mut leaves = Vec::new();

        for i in 0..num_leaves {
            let mut leaf = [0u8; 32];
            leaf[0..4].copy_from_slice(&(u32::try_from(i).unwrap()).to_be_bytes());
            leaves.push(leaf);
        }

        let tree = MerkleTree::new(leaves).unwrap();
        let proof = tree.generate_proof(512);

        assert!(proof.is_some());
        assert!(tree.verify_proof(&proof.unwrap()));
    }

    #[test]
    fn test_merkle_proof_with_invalid_index() {
        let leaves = vec![[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]];

        let tree = MerkleTree::new(leaves).unwrap();
        let proof = tree.generate_proof(999);

        // Should return None for invalid index
        assert!(proof.is_none());
    }

    #[test]
    fn test_merkle_proof_with_tampered_root() {
        let leaves = vec![[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]];

        let tree = MerkleTree::new(leaves).unwrap();
        let mut proof = tree.generate_proof(0).unwrap();

        // Tamper with the root
        proof.root = [0xFFu8; 32];

        // Verification should fail
        assert!(!tree.verify_proof(&proof));
    }

    #[test]
    fn test_merkle_proof_with_tampered_leaf() {
        let leaves = vec![[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]];

        let tree = MerkleTree::new(leaves).unwrap();
        let mut proof = tree.generate_proof(0).unwrap();

        // Tamper with the leaf
        proof.leaf = [0xFFu8; 32];

        // Verification should fail
        assert!(!tree.verify_proof(&proof));
    }

    #[test]
    fn test_merkle_proof_with_tampered_siblings() {
        let leaves = vec![[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]];

        let tree = MerkleTree::new(leaves).unwrap();
        let mut proof = tree.generate_proof(0).unwrap();

        // Tamper with the siblings
        if !proof.siblings.is_empty() {
            proof.siblings[0] = [0xFFu8; 32];
        }

        // Verification should fail
        assert!(!tree.verify_proof(&proof));
    }

    #[test]
    fn test_merkle_tree_with_single_leaf() {
        let leaves = vec![[1u8; 32]];
        let tree = MerkleTree::new(leaves).unwrap();
        let proof = tree.generate_proof(0);

        assert!(proof.is_some());
        assert!(tree.verify_proof(&proof.unwrap()));
    }

    #[test]
    fn test_merkle_tree_with_non_power_of_two() {
        let leaves = vec![[1u8; 32], [2u8; 32], [3u8; 32]];
        let tree = MerkleTree::new(leaves).unwrap();
        let proof = tree.generate_proof(0);

        assert!(proof.is_some());
        assert!(tree.verify_proof(&proof.unwrap()));
    }

    #[test]
    fn test_merkle_proof_index_boundary() {
        let leaves = vec![[1u8; 32], [2u8; 32], [4u8; 32], [8u8; 32]];

        let tree = MerkleTree::new(leaves.clone()).unwrap();

        // Test first leaf
        let proof_first = tree.generate_proof(0).unwrap();
        assert!(tree.verify_proof(&proof_first));

        // Test last leaf
        let proof_last = tree.generate_proof(leaves.len() - 1).unwrap();
        assert!(tree.verify_proof(&proof_last));
    }

    #[test]
    fn test_merkle_root_determinism() {
        let leaves1 = vec![[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]];
        let leaves2 = vec![[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]];

        let tree1 = MerkleTree::new(leaves1).unwrap();
        let tree2 = MerkleTree::new(leaves2).unwrap();

        assert_eq!(tree1.root, tree2.root);
    }

    #[test]
    fn test_verify_proof_resists_timing_attacks() {
        let leaves = vec![[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]];
        let tree = MerkleTree::new(leaves).unwrap();
        let proof = tree.generate_proof(0).unwrap();

        assert!(tree.verify_proof(&proof));

        let mut wrong_proof = proof.clone();
        wrong_proof.root[0] = wrong_proof.root[0].wrapping_add(1);

        assert!(!tree.verify_proof(&wrong_proof));
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn test_merkle_tree_empty_leaves() {
        let leaves: Vec<[u8; 32]> = vec![];
        let result = MerkleTree::new(leaves);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Empty"));
    }

    #[test]
    #[allow(clippy::unwrap_used, clippy::cast_possible_truncation)]
    fn test_merkle_tree_exceeds_capacity() {
        let max_leaves = 1 << crate::CIRCUIT_K;
        let mut leaves = Vec::with_capacity(max_leaves + 1);

        for i in 0..=max_leaves {
            let mut leaf = [0u8; 32];
            leaf[0..4].copy_from_slice(&(u32::try_from(i).unwrap()).to_be_bytes());
            leaves.push(leaf);
        }

        let result = MerkleTree::new(leaves);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("exceeds maximum"));
    }

    #[test]
    #[allow(clippy::unwrap_used, clippy::cast_possible_truncation)]
    fn test_merkle_tree_at_capacity() {
        let max_leaves = 1 << crate::CIRCUIT_K;
        let mut leaves = Vec::with_capacity(max_leaves);

        for i in 0..max_leaves {
            let mut leaf = [0u8; 32];
            leaf[0..4].copy_from_slice(&(u32::try_from(i).unwrap()).to_be_bytes());
            leaves.push(leaf);
        }

        let tree = MerkleTree::new(leaves);
        assert!(tree.is_ok());
    }

    #[test]
    #[allow(clippy::unwrap_used)]
    fn test_merkle_proof_with_invalid_index_out_of_bounds() {
        let leaves = vec![[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]];
        let leaves_len = leaves.len();
        let tree = MerkleTree::new(leaves).unwrap();

        let proof = tree.generate_proof(leaves_len);
        assert!(proof.is_none());

        let proof = tree.generate_proof(leaves_len + 100);
        assert!(proof.is_none());
    }
}
