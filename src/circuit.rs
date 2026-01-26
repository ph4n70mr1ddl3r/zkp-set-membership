//! ZK-SNARK circuit for set membership proof.
//!
//! # Important Security Note
//!
//! The circuit currently lacks proper cryptographic constraints. The following
//! should be implemented for production use:
//! 1. Merkle path verification using Poseidon hash in the circuit
//! 2. Constraint enforcement that leaf + siblings produces the root
//! 3. Nullifier derivation constraint: nullifier = H(public_key || merkle_root)
//!
//! Currently, the circuit only assigns values with minimal constraints,
//! which means proofs can be generated for invalid values in some cases.
//! This is intended for testing and prototyping only.
//!
//! # Production Requirements
//!
//! Before using in production:
//! - Implement Poseidon hash chip for efficient in-circuit hashing
//! - Add Merkle path verification constraints
//! - Add nullifier verification constraints (H(leaf || root) == nullifier)
//! - Add proper range checks for all inputs
//! - Perform security audits of the circuit constraints
//! - Consider using a trusted setup ceremony for parameter generation

use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{
        create_proof, keygen_pk, keygen_vk, verify_proof, Advice, Circuit, Column,
        ConstraintSystem, Error, Instance, ProvingKey, SingleVerifier, VerifyingKey,
    },
    poly::commitment::Params,
    transcript::{Blake2bRead, Blake2bWrite},
};
use pasta_curves::{pallas, vesta};
use std::sync::Arc;

#[derive(Debug, Clone, Copy)]
pub struct SetMembershipConfig {
    pub leaf_cell: Column<Advice>,
    pub root_cell: Column<Advice>,
    pub nullifier_cell: Column<Advice>,
    pub instance: Column<Instance>,
}

#[derive(Debug, Default, Clone)]
pub struct SetMembershipCircuit {
    pub leaf: pallas::Base,
    pub root: pallas::Base,
    pub nullifier: pallas::Base,
    /// Merkle path siblings for inclusion proof.
    ///
    /// This field stores the sibling hashes along the Merkle tree path from the leaf to the root.
    /// These siblings are used to verify that the leaf is included in the tree by computing
    /// the root hash through the path.
    ///
    /// **Security Note**: Currently this field is stored but not enforced in circuit constraints.
    /// The circuit does not verify that leaf + siblings produces the root, which means proofs
    /// can be generated for invalid values. This is a critical security limitation.
    ///
    /// TODO: Implement circuit constraints to verify Merkle path using these siblings:
    /// 1. Add Poseidon hash chip for efficient in-circuit hashing
    /// 2. Implement Merkle path verification using siblings
    /// 3. Add constraint: H(leaf || siblings[0]) = intermediate, H(intermediate || siblings[1]) = ...
    /// 4. Final constraint: final_hash == root
    pub siblings: Vec<pallas::Base>,
    pub leaf_index: usize,
}

impl Circuit<pallas::Base> for SetMembershipCircuit {
    type Config = SetMembershipConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<pallas::Base>) -> Self::Config {
        // CRITICAL: No cryptographic constraints are currently implemented.
        // This circuit only assigns values to cells without enforcing relationships.
        //
        // SECURITY WARNING: This means proofs can be generated for ANY values,
        // not just those where leaf is actually in the tree at the root.
        //
        // Required constraints for production use:
        // 1. Merkle path verification using Poseidon hash:
        //    - Start with leaf
        //    - For each sibling in siblings: current = H(current || sibling) (or H(sibling || current) depending on path)
        //    - Final constraint: current == root
        //
        // 2. Nullifier derivation constraint:
        //    - Compute H(leaf || root) in-circuit
        //    - Constrain: computed_hash == nullifier
        //
        // 3. Instance column constraints:
        //    - Expose leaf, root, nullifier as public inputs
        //    - Constrain advice values to match instance values
        //
        // Recommended approach:
        // - Use halo2-gadgets or implement a Poseidon chip
        // - See halo2-pasta or halo2-examples for reference implementations
        let leaf_cell = meta.advice_column();
        let root_cell = meta.advice_column();
        let nullifier_cell = meta.advice_column();
        let instance = meta.instance_column();

        SetMembershipConfig {
            leaf_cell,
            root_cell,
            nullifier_cell,
            instance,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<pallas::Base>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "set membership",
            |mut region| {
                region.assign_advice(|| "leaf", config.leaf_cell, 0, || Value::known(self.leaf))?;
                region.assign_advice(|| "root", config.root_cell, 1, || Value::known(self.root))?;
                region.assign_advice(
                    || "nullifier",
                    config.nullifier_cell,
                    2,
                    || Value::known(self.nullifier),
                )?;

                Ok(())
            },
        )
    }
}

const BASE_U64: u64 = 256;

/// Converts 32 bytes to a field element in the Pallas curve.
///
/// This function interprets the 32-byte input as a base-256 number
/// and reduces it modulo the field order.
///
/// # Arguments
///
/// * `bytes` - A 32-byte slice to convert
///
/// # Returns
///
/// A Pallas field element representing the input bytes
///
/// This function interprets the 32-byte input as a base-256 number
/// and reduces it modulo the field order.
///
/// # Arguments
///
/// * `bytes` - A 32-byte slice to convert
///
/// # Returns
///
/// A Pallas field element representing the input bytes
pub fn bytes_to_field(bytes: &[u8; 32]) -> pallas::Base {
    let mut value = pallas::Base::zero();
    let base = pallas::Base::from(BASE_U64);

    for &byte in bytes.iter() {
        value = value * base + pallas::Base::from(byte as u64);
    }

    value
}

/// Prover utility for generating and verifying set membership proofs with cached keys.
pub struct SetMembershipProver {
    vk: Option<Arc<VerifyingKey<vesta::Affine>>>,
    pk: Option<Arc<ProvingKey<vesta::Affine>>>,
}

impl Default for SetMembershipProver {
    fn default() -> Self {
        Self::new()
    }
}

impl SetMembershipProver {
    /// Create a new prover with no cached keys.
    pub fn new() -> Self {
        Self { vk: None, pk: None }
    }

    /// Create a prover with pre-generated keys.
    pub fn with_keys(
        vk: Arc<VerifyingKey<vesta::Affine>>,
        pk: Arc<ProvingKey<vesta::Affine>>,
    ) -> Self {
        Self {
            vk: Some(vk),
            pk: Some(pk),
        }
    }

    /// Generate keys and cache them for future use.
    pub fn generate_and_cache_keys(&mut self, params: &Params<vesta::Affine>) -> Result<(), Error> {
        let circuit = SetMembershipCircuit::default();
        let vk = keygen_vk(params, &circuit)?;
        let pk = keygen_pk(params, vk.clone(), &circuit)?;

        self.vk = Some(Arc::new(vk));
        self.pk = Some(Arc::new(pk));
        Ok(())
    }

    /// Generates a zero-knowledge proof for set membership.
    ///
    /// # Arguments
    /// * `params` - The proving system parameters
    /// * `circuit` - The circuit instance with witnesses
    /// * `public_inputs` - The public inputs to the circuit
    ///
    /// # Returns
    /// A serialized proof as bytes
    pub fn generate_proof(
        &mut self,
        params: &Params<vesta::Affine>,
        circuit: SetMembershipCircuit,
        public_inputs: Vec<pallas::Base>,
    ) -> Result<Vec<u8>, Error> {
        let pk = if let Some(pk) = &self.pk {
            pk.clone()
        } else {
            let vk = keygen_vk(params, &circuit)?;
            let pk = keygen_pk(params, vk, &circuit)?;
            let pk_arc = Arc::new(pk);
            self.pk = Some(pk_arc.clone());
            pk_arc
        };

        let mut transcript = Blake2bWrite::init(vec![]);
        let mut rng = rand::rngs::ThreadRng::default();

        let public_inputs_slice: &[&[&[pallas::Base]]] = &[&[&public_inputs]];
        create_proof(
            params,
            &pk,
            &[circuit],
            public_inputs_slice,
            &mut rng,
            &mut transcript,
        )?;

        Ok(transcript.finalize())
    }

    /// Verifies a zero-knowledge proof for set membership.
    ///
    /// # Arguments
    /// * `params` - The proving system parameters
    /// * `circuit` - The circuit instance (used for verification key if not cached)
    /// * `proof` - The serialized proof bytes
    /// * `public_inputs` - The public inputs to verify against
    ///
    /// # Returns
    /// `Ok(true)` if the proof is valid, `Ok(false)` if invalid,
    /// or an error if verification fails unexpectedly
    pub fn verify_proof(
        &mut self,
        params: &Params<vesta::Affine>,
        circuit: SetMembershipCircuit,
        proof: &[u8],
        public_inputs: Vec<pallas::Base>,
    ) -> Result<bool, Error> {
        let vk = if let Some(vk) = &self.vk {
            vk.clone()
        } else {
            let vk = keygen_vk(params, &circuit)?;
            let vk_arc = Arc::new(vk);
            self.vk = Some(vk_arc.clone());
            vk_arc
        };

        let strategy = SingleVerifier::new(params);
        let mut transcript = Blake2bRead::init(proof);

        let public_inputs_slice: &[&[&[pallas::Base]]] = &[&[&public_inputs]];
        let result = verify_proof(params, &vk, strategy, public_inputs_slice, &mut transcript);

        Ok(result.is_ok())
    }
}
