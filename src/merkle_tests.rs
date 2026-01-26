#[cfg(test)]
mod tests {
    use crate::MerkleTree;

    #[test]
    fn test_merkle_tree_creation() {
        let leaves = vec![[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]];

        let tree = MerkleTree::new(leaves);
        assert_ne!(tree.root, [0u8; 32]);
    }

    #[test]
    fn test_merkle_proof_generation() {
        let leaves = vec![[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]];

        let tree = MerkleTree::new(leaves);
        let proof = tree.generate_proof(0);

        assert!(proof.is_some());
        let proof = proof.unwrap();
        assert_eq!(proof.leaf, [1u8; 32]);
        assert_eq!(proof.root, tree.root);
    }

    #[test]
    fn test_merkle_proof_verification() {
        let leaves = vec![[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]];

        let tree = MerkleTree::new(leaves);
        let proof = tree.generate_proof(2).unwrap();

        assert!(tree.verify_proof(&proof));
    }

    #[test]
    fn test_merkle_proof_invalid_verification() {
        let leaves1 = vec![[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]];

        let leaves2 = vec![[5u8; 32], [6u8; 32], [7u8; 32], [8u8; 32]];

        let tree1 = MerkleTree::new(leaves1);
        let tree2 = MerkleTree::new(leaves2);

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
            leaf[0..4].copy_from_slice(&(i as u32).to_be_bytes());
            leaves.push(leaf);
        }

        let tree = MerkleTree::new(leaves);
        let proof = tree.generate_proof(512);

        assert!(proof.is_some());
        assert!(tree.verify_proof(&proof.unwrap()));
    }

    #[test]
    fn test_merkle_proof_with_invalid_index() {
        let leaves = vec![[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]];

        let tree = MerkleTree::new(leaves);
        let proof = tree.generate_proof(999);

        // Should return None for invalid index
        assert!(proof.is_none());
    }

    #[test]
    fn test_merkle_proof_with_tampered_root() {
        let leaves = vec![[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]];

        let tree = MerkleTree::new(leaves);
        let mut proof = tree.generate_proof(0).unwrap();

        // Tamper with the root
        proof.root = [0xFFu8; 32];

        // Verification should fail
        assert!(!tree.verify_proof(&proof));
    }

    #[test]
    fn test_merkle_proof_with_tampered_leaf() {
        let leaves = vec![[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]];

        let tree = MerkleTree::new(leaves);
        let mut proof = tree.generate_proof(0).unwrap();

        // Tamper with the leaf
        proof.leaf = [0xFFu8; 32];

        // Verification should fail
        assert!(!tree.verify_proof(&proof));
    }

    #[test]
    fn test_merkle_proof_with_tampered_siblings() {
        let leaves = vec![[1u8; 32], [2u8; 32], [3u8; 32], [4u8; 32]];

        let tree = MerkleTree::new(leaves);
        let mut proof = tree.generate_proof(0).unwrap();

        // Tamper with the siblings
        if !proof.siblings.is_empty() {
            proof.siblings[0] = [0xFFu8; 32];
        }

        // Verification should fail
        assert!(!tree.verify_proof(&proof));
    }
}
