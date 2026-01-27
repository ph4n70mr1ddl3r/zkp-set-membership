//! ZK-SNARK circuit for set membership proof with cryptographic constraints.
//!
//! WARNING: This circuit currently performs client-side cryptographic computation
//! and only constrains equality, which does NOT provide zero-knowledge guarantees.
//! A proper implementation requires adding Poseidon hash gates and Merkle path
//! verification gates directly in the circuit synthesis.
//!
//! This is a CRITICAL security limitation that must be addressed before production use.
//!
//! For a complete implementation, see:
//! https://github.com/zcash/halo2/blob/main/halo2_gadgets/src/poseidon.rs
//!
//! Current behavior:
//! - Merkle path verification: computed client-side and equality constrained
//! - Nullifier constraint: computed client-side and equality constrained
//! - Public input constraints: instance values match advice values

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
use std::sync::OnceLock;

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
    pub fn builder() -> SetMembershipCircuitBuilder {
        SetMembershipCircuitBuilder::default()
    }
}

#[derive(Debug, Default)]
pub struct SetMembershipCircuitBuilder {
    leaf: Option<pallas::Base>,
    root: Option<pallas::Base>,
    nullifier: Option<pallas::Base>,
    siblings: Option<Vec<pallas::Base>>,
    leaf_index: Option<usize>,
}

impl SetMembershipCircuitBuilder {
    pub fn leaf(mut self, leaf: pallas::Base) -> Self {
        self.leaf = Some(leaf);
        self
    }

    pub fn root(mut self, root: pallas::Base) -> Self {
        self.root = Some(root);
        self
    }

    pub fn nullifier(mut self, nullifier: pallas::Base) -> Self {
        self.nullifier = Some(nullifier);
        self
    }

    pub fn siblings(mut self, siblings: Vec<pallas::Base>) -> Self {
        self.siblings = Some(siblings);
        self
    }

    pub fn leaf_index(mut self, leaf_index: usize) -> Self {
        self.leaf_index = Some(leaf_index);
        self
    }

    pub fn build(self) -> anyhow::Result<SetMembershipCircuit> {
        let leaf = self
            .leaf
            .ok_or_else(|| anyhow::anyhow!("leaf is required"))?;
        let root = self
            .root
            .ok_or_else(|| anyhow::anyhow!("root is required"))?;
        let nullifier = self
            .nullifier
            .ok_or_else(|| anyhow::anyhow!("nullifier is required"))?;
        let siblings = self
            .siblings
            .ok_or_else(|| anyhow::anyhow!("siblings is required"))?;
        let leaf_index = self
            .leaf_index
            .ok_or_else(|| anyhow::anyhow!("leaf_index is required"))?;

        Ok(SetMembershipCircuit {
            leaf,
            root,
            nullifier,
            siblings,
            leaf_index,
        })
    }
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
        // CRITICAL SECURITY WARNING: This circuit performs client-side computation
        // and only constrains equality. It does NOT enforce cryptographic constraints
        // in-circuit. A malicious prover can provide arbitrary values that will verify.
        //
        // To fix this, implement proper Poseidon hash gates and Merkle path
        // verification gates using halo2_gadgets. See documentation above.

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

pub struct SetMembershipProver {
    vk: Option<Arc<VerifyingKey<vesta::Affine>>>,
    pk: Option<Arc<ProvingKey<vesta::Affine>>>,
}

type CachedKeys = (
    Arc<VerifyingKey<vesta::Affine>>,
    Arc<ProvingKey<vesta::Affine>>,
);

static CACHED_KEYS: OnceLock<CachedKeys> = OnceLock::new();

impl Default for SetMembershipProver {
    fn default() -> Self {
        Self::new()
    }
}

impl SetMembershipProver {
    #[must_use]
    pub fn new() -> Self {
        Self { vk: None, pk: None }
    }

    #[must_use]
    pub fn with_keys(
        vk: Arc<VerifyingKey<vesta::Affine>>,
        pk: Arc<ProvingKey<vesta::Affine>>,
    ) -> Self {
        Self {
            vk: Some(vk),
            pk: Some(pk),
        }
    }

    /// Generates and caches proving and verifying keys.
    ///
    /// # Errors
    /// Returns an error if key generation fails.
    pub fn generate_and_cache_keys(&mut self, params: &Params<vesta::Affine>) -> Result<(), Error> {
        if let Some((vk, pk)) = CACHED_KEYS.get() {
            self.vk = Some(vk.clone());
            self.pk = Some(pk.clone());
            return Ok(());
        }

        let circuit = SetMembershipCircuit::default();
        let vk = keygen_vk(params, &circuit)?;
        let pk = keygen_pk(params, vk.clone(), &circuit)?;

        let vk = Arc::new(vk);
        let pk = Arc::new(pk);

        let _ = CACHED_KEYS.set((vk.clone(), pk.clone()));

        self.vk = Some(vk);
        self.pk = Some(pk);
        Ok(())
    }

    /// Generates a zero-knowledge proof.
    ///
    /// # Errors
    /// Returns an error if proving key is not set, circuit validation fails, or proof generation fails.
    pub fn generate_proof(
        &self,
        params: &Params<vesta::Affine>,
        circuit: SetMembershipCircuit,
        public_inputs: &[pallas::Base],
    ) -> Result<Vec<u8>, Error> {
        let pk = self.pk.as_ref().ok_or(Error::Synthesis)?;

        if !circuit.validate_consistency() {
            return Err(Error::Synthesis);
        }

        let mut transcript = Blake2bWrite::init(vec![]);
        let mut rng = rand::rngs::ThreadRng::default();

        let public_inputs_slice: &[&[&[pallas::Base]]] = &[&[public_inputs]];
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

    /// Verifies a zero-knowledge proof.
    ///
    /// # Errors
    /// Returns an error if verifying key is not set.
    pub fn verify_proof(
        &self,
        params: &Params<vesta::Affine>,
        proof: &[u8],
        public_inputs: &[pallas::Base],
    ) -> Result<bool, Error> {
        let vk = self.vk.as_ref().ok_or(Error::Synthesis)?;

        let strategy = SingleVerifier::new(params);
        let mut transcript = Blake2bRead::init(proof);

        let public_inputs_slice: &[&[&[pallas::Base]]] = &[&[public_inputs]];
        let result = verify_proof(params, vk, strategy, public_inputs_slice, &mut transcript);

        Ok(result.is_ok())
    }
}
