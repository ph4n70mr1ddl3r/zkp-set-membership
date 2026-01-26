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

pub const CIRCUIT_K: u32 = 11;
