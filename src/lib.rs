//! ZKP Set Membership Proof System
//!
//! This library provides a zero-knowledge proof system for proving set membership
//! without revealing which member you possess.
//!
//! # Components
//!
//! - [`SetMembershipCircuit`]: ZK-SNARK circuit for set membership proofs
//! - [`SetMembershipProver`]: Prover utility for generating and verifying proofs
//! - [`MerkleTree`]: Binary Merkle tree implementation for managing the set
//! - [`MerkleProof`]: Proof structure for leaf inclusion in Merkle tree
//! - [`ZKProofOutput`]: Serialized proof output format
//!
//! # Example
//!
//! ```no_run
//! use zkp_set_membership::{circuit::SetMembershipCircuit, merkle::MerkleTree, CIRCUIT_K};
//! ```

pub mod circuit;
pub mod merkle;
pub mod types;
pub mod utils;

#[cfg(test)]
mod merkle_tests;

pub use circuit::{SetMembershipCircuit, SetMembershipProver};
pub use merkle::{MerkleProof, MerkleTree};
pub use types::ZKProofOutput;
pub use utils::{bytes_to_field, field_to_bytes, poseidon_hash};

/// Circuit parameter for Halo2 proving system.
///
/// The value `k=12` creates a circuit with 2^k = 4096 rows.
/// This supports Merkle trees with a maximum depth of 12 levels,
/// which can handle up to 2^12 = 4096 leaves when the tree is a full binary tree.
///
/// # Security Considerations
///
/// Changing `CIRCUIT_K` requires regenerating all proving and verifying keys.
/// Prover and verifier must use the same value, or verification will fail.
///
/// # Performance Trade-offs
///
/// If you need to support more leaves:
/// - Increase `CIRCUIT_K` to 13 for up to 8192 leaves
/// - Increase `CIRCUIT_K` to 14 for up to 16384 leaves
/// - Each increment doubles the circuit size and proof generation time
///
/// - Higher k values allow larger trees but increase memory and computation
/// - Lower k values are faster but limit the maximum tree size
pub const CIRCUIT_K: u32 = 12;
