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
//! Currently, the circuit only assigns values without enforcing constraints,
//! which means proofs can be generated for any values without validation.
//! This is intended for testing and prototyping only.

use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{
        create_proof, keygen_pk, keygen_vk, verify_proof, Advice, Circuit, Column,
        ConstraintSystem, Error, Instance, SingleVerifier,
    },
    poly::commitment::Params,
    transcript::{Blake2bRead, Blake2bWrite},
};
use pasta_curves::{pallas, vesta};

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
pub fn bytes_to_field(bytes: &[u8; 32]) -> pallas::Base {
    let mut value = pallas::Base::zero();
    let base = pallas::Base::from(BASE_U64);

    for &byte in bytes.iter() {
        value = value * base + pallas::Base::from(byte as u64);
    }

    value
}

/// Prover utility for generating and verifying set membership proofs.
pub struct SetMembershipProver;

impl SetMembershipProver {
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
        params: &Params<vesta::Affine>,
        circuit: SetMembershipCircuit,
        public_inputs: Vec<pallas::Base>,
    ) -> Result<Vec<u8>, Error> {
        let vk = keygen_vk(params, &circuit)?;
        let pk = keygen_pk(params, vk, &circuit)?;

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
    /// * `circuit` - The circuit instance (used for verification key)
    /// * `proof` - The serialized proof bytes
    /// * `public_inputs` - The public inputs to verify against
    ///
    /// # Returns
    /// `Ok(true)` if the proof is valid, `Ok(false)` if invalid,
    /// or an error if verification fails unexpectedly
    pub fn verify_proof(
        params: &Params<vesta::Affine>,
        circuit: SetMembershipCircuit,
        proof: &[u8],
        public_inputs: Vec<pallas::Base>,
    ) -> Result<bool, Error> {
        let vk = keygen_vk(params, &circuit)?;

        let strategy = SingleVerifier::new(params);
        let mut transcript = Blake2bRead::init(proof);

        let public_inputs_slice: &[&[&[pallas::Base]]] = &[&[&public_inputs]];
        let result = verify_proof(params, &vk, strategy, public_inputs_slice, &mut transcript);

        Ok(result.is_ok())
    }
}
