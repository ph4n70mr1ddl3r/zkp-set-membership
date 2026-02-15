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
//!
//! # Security Considerations
//!
//! ## Threat Model
//!
//! This system protects against the following threats:
//!
//! - **Privacy**: The prover can demonstrate membership in a set without revealing which element
//! - **Replay Attacks**: Nullifiers ensure each proof can only be used once (when properly tracked)
//! - **Forgery**: The ZK-SNARK ensures only valid proofs from the Merkle tree are accepted
//!
//! ## Operational Security
//!
//! ### Private Key Management
//! - Private keys must never be logged, committed to version control, or shared insecurely
//! - Environment variable storage of private keys is discouraged due to potential shell history leaks
//! - Consider using hardware security modules (HSMs) or secure key management systems in production
//!
//! ### Nullifier Tracking
//! - Verifiers MUST maintain a persistent, secure database of used nullifiers
//! - The nullifier file must be protected with proper file locking to prevent race conditions
//! - Nullifiers should be treated as sensitive data and protected accordingly
//!
//! ### Resource Limits
//! - Implement rate limiting on proof generation to prevent resource exhaustion attacks
//! - Validate input file sizes before processing to prevent `DoS` attacks
//! - Monitor memory usage during proof operations
//!
//! ### Timestamp Validation
//! - Proofs have configurable time-to-live (default 24 hours)
//! - Adjust timestamp tolerances based on your security requirements
//! - Consider implementing proof nonces for stricter replay protection
//!
//! ## Cryptographic Assumptions
//!
//! - **Poseidon Hash**: The security of the system depends on the collision resistance of Poseidon
//! - **Merkle Trees**: Tree integrity must be maintained; root must be securely distributed
//! - **Halo2 ZK-SNARK**: Security relies on the hardness of the underlying cryptographic assumptions
//!
//! # Performance Considerations
//!
//! - Circuit size is limited by `CIRCUIT_K` (k=12 = 4096 rows, max 4096 leaves)
//! - Proof generation is CPU-intensive; consider parallel processing for large-scale deployments
//! - Key caching improves performance for repeated operations
//!
//! # Best Practices
//!
//! 1. **Always verify proofs** before accepting claims of set membership
//! 2. **Track nullifiers** to prevent proof reuse
//! 3. **Secure Merkle roots** by distributing them through trusted channels
//! 4. **Monitor for anomalies** in proof verification patterns
//! 5. **Keep dependencies updated** for security patches

pub mod circuit;
pub mod ethereum;
pub mod merkle;
pub mod types;
pub mod utils;

#[cfg(test)]
mod merkle_tests;

pub use circuit::{SetMembershipCircuit, SetMembershipProver};
pub use ethereum::{
    address_to_bytes_normalized, normalize_address, normalize_addresses_batch, validate_address,
    validate_addresses_batch, validate_private_key,
};
pub use merkle::{MerkleProof, MerkleTree};
pub use types::{PublicInputs, ZKProofOutput};
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
