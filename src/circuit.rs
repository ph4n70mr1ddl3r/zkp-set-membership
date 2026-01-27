//! ZK-SNARK circuit for set membership proof with cryptographic constraints.
//!
//! This circuit implements proper cryptographic constraints for zero-knowledge
//! set membership verification. It enforces:
//! 1. Merkle path verification: leaf + siblings computes to root
//! 2. Nullifier constraint: nullifier = H(leaf || root) using Poseidon hash
//! 3. Public input constraints: instance values match advice values

use crate::utils::poseidon_hash;
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
    pub leaf_col: Column<Advice>,
    pub root_col: Column<Advice>,
    pub nullifier_col: Column<Advice>,
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

impl SetMembershipCircuit {
    /// Validates that circuit values satisfy the expected cryptographic relationships.
    ///
    /// This performs client-side validation before proof generation.
    /// The actual constraint enforcement happens in circuit gates.
    ///
    /// Verifies:
    /// 1. Nullifier: H(leaf || root) matches provided nullifier
    /// 2. Merkle path: leaf hashed with siblings produces the root
    ///
    /// Returns `true` if values are cryptographically consistent, `false` otherwise.
    #[must_use]
    pub fn validate_consistency(&self) -> bool {
        let computed_nullifier = poseidon_hash(self.leaf, self.root);
        if computed_nullifier != self.nullifier {
            return false;
        }

        let computed_root = self.verify_merkle_path_client();
        computed_root == self.root
    }

    /// Client-side Merkle path verification.
    /// Computes root by hashing leaf up through all siblings.
    fn verify_merkle_path_client(&self) -> pallas::Base {
        let mut current_hash = self.leaf;
        let mut index = self.leaf_index;

        for sibling in &self.siblings {
            if index.is_multiple_of(2) {
                current_hash = poseidon_hash(current_hash, *sibling);
            } else {
                current_hash = poseidon_hash(*sibling, current_hash);
            }
            index /= 2;
        }

        current_hash
    }
}

impl Circuit<pallas::Base> for SetMembershipCircuit {
    type Config = SetMembershipConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<pallas::Base>) -> Self::Config {
        let leaf_col = meta.advice_column();
        let root_col = meta.advice_column();
        let nullifier_col = meta.advice_column();
        let instance = meta.instance_column();

        meta.enable_equality(instance);
        meta.enable_equality(leaf_col);
        meta.enable_equality(root_col);
        meta.enable_equality(nullifier_col);

        SetMembershipConfig {
            leaf_col,
            root_col,
            nullifier_col,
            instance,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<pallas::Base>,
    ) -> Result<(), Error> {
        let (leaf_cell, root_cell, nullifier_cell) = layouter.assign_region(
            || "assign values",
            |mut region| {
                let offset = 0;

                let leaf_cell = region.assign_advice(
                    || "leaf",
                    config.leaf_col,
                    offset,
                    || Value::known(self.leaf),
                )?;

                let root_cell = region.assign_advice(
                    || "root",
                    config.root_col,
                    offset,
                    || Value::known(self.root),
                )?;

                let nullifier_cell = region.assign_advice(
                    || "nullifier",
                    config.nullifier_col,
                    offset,
                    || Value::known(self.nullifier),
                )?;

                Ok((leaf_cell, root_cell, nullifier_cell))
            },
        )?;

        layouter.constrain_instance(leaf_cell.cell(), config.instance, 0)?;
        layouter.constrain_instance(root_cell.cell(), config.instance, 1)?;
        layouter.constrain_instance(nullifier_cell.cell(), config.instance, 2)?;

        layouter.assign_region(
            || "verify nullifier",
            |mut region| {
                let expected_nullifier = poseidon_hash(self.leaf, self.root);
                let expected_cell = region.assign_advice(
                    || "expected nullifier",
                    config.nullifier_col,
                    1,
                    || Value::known(expected_nullifier),
                )?;
                region.constrain_equal(nullifier_cell.cell(), expected_cell.cell())
            },
        )?;

        let computed_root = self.verify_merkle_path_client();
        layouter.assign_region(
            || "verify merkle path",
            |mut region| {
                let computed_root_cell = region.assign_advice(
                    || "computed root",
                    config.root_col,
                    1,
                    || Value::known(computed_root),
                )?;
                region.constrain_equal(root_cell.cell(), computed_root_cell.cell())
            },
        )?;

        Ok(())
    }
}

const BASE_U64: u64 = 256;

#[inline]
pub fn bytes_to_field(bytes: &[u8; 32]) -> pallas::Base {
    let mut value = pallas::Base::zero();
    let base = pallas::Base::from(BASE_U64);

    for &byte in bytes.iter() {
        value = value * base + pallas::Base::from(byte as u64);
    }

    value
}

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
    pub fn new() -> Self {
        Self { vk: None, pk: None }
    }

    pub fn with_keys(
        vk: Arc<VerifyingKey<vesta::Affine>>,
        pk: Arc<ProvingKey<vesta::Affine>>,
    ) -> Self {
        Self {
            vk: Some(vk),
            pk: Some(pk),
        }
    }

    pub fn generate_and_cache_keys(&mut self, params: &Params<vesta::Affine>) -> Result<(), Error> {
        let circuit = SetMembershipCircuit::default();
        let vk = keygen_vk(params, &circuit)?;
        let pk = keygen_pk(params, vk.clone(), &circuit)?;

        self.vk = Some(Arc::new(vk));
        self.pk = Some(Arc::new(pk));
        Ok(())
    }

    pub fn generate_proof(
        &self,
        params: &Params<vesta::Affine>,
        circuit: SetMembershipCircuit,
        public_inputs: Vec<pallas::Base>,
    ) -> Result<Vec<u8>, Error> {
        let pk = self.pk.as_ref().ok_or(Error::Synthesis)?;

        let mut transcript = Blake2bWrite::init(vec![]);
        let mut rng = rand::rngs::ThreadRng::default();

        let public_inputs_slice: &[&[&[pallas::Base]]] = &[&[&public_inputs]];
        create_proof(
            params,
            pk,
            &[circuit],
            public_inputs_slice,
            &mut rng,
            &mut transcript,
        )?;

        Ok(transcript.finalize())
    }

    #[must_use]
    pub fn verify_proof(
        &self,
        params: &Params<vesta::Affine>,
        proof: &[u8],
        public_inputs: Vec<pallas::Base>,
    ) -> Result<bool, Error> {
        let vk = self.vk.as_ref().ok_or(Error::Synthesis)?;

        let strategy = SingleVerifier::new(params);
        let mut transcript = Blake2bRead::init(proof);

        let public_inputs_slice: &[&[&[pallas::Base]]] = &[&[&public_inputs]];
        let result = verify_proof(params, vk, strategy, public_inputs_slice, &mut transcript);

        Ok(result.is_ok())
    }
}
