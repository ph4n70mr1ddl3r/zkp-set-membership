pub mod circuit;
pub mod merkle;
pub mod types;

#[cfg(test)]
mod merkle_tests;

pub use circuit::{SetMembershipCircuit, SetMembershipProver};
pub use merkle::{MerkleProof, MerkleTree};
pub use types::{EthereumAccount, ZKProofOutput};
