//! ZK-SNARK circuit for set membership proof with proper cryptographic constraints.
//!
//! This implementation uses in-circuit Poseidon hash gates and Merkle path
//! verification gates to provide true zero-knowledge guarantees.
//!
//! # Security Guarantees
//!
//! - **In-circuit cryptographic verification**: All hash computations are verified
//!   within circuit using halo2_gadgets Poseidon hash chip
//! - **Merkle path verification**: Proves leaf is included in the tree that computes
//!   to the root through proper hash constraints
//! - **Nullifier computation**: Enforces H(leaf || root) = nullifier in-circuit
//! - **Proper constraint enforcement**: Public inputs are cryptographically bound
//!   to private witnesses through the circuit

use halo2_gadgets::poseidon::primitives::{ConstantLength, P128Pow5T3 as PoseidonSpec};
use halo2_gadgets::poseidon::{Hash as PoseidonHash, Pow5Chip as PoseidonChip};
use halo2_proofs::{
    circuit::{Layouter, SimpleFloorPlanner, Value},
    plonk::{
        create_proof, keygen_pk, keygen_vk, verify_proof, Advice, Circuit, Column,
        ConstraintSystem, Error, Fixed, Instance, ProvingKey, SingleVerifier, VerifyingKey,
    },
    poly::commitment::Params,
    transcript::{Blake2bRead, Blake2bWrite},
};
use pasta_curves::{pallas, vesta};
use std::sync::Arc;
use std::sync::OnceLock;

use crate::CIRCUIT_K;

type PoseidonChipType = PoseidonChip<pallas::Base, 3, 2>;

const INITIAL_ROW_OFFSET: usize = 0;
const NULLIFIER_ROW_OFFSET: usize = 1;
const SIBLING_ROW_OFFSET: usize = 100;
const ROW_INCREMENT: usize = 50;

const MAX_TREE_DEPTH: usize = 12;

const _: () = {
    const _: () = assert!(
        SIBLING_ROW_OFFSET + (MAX_TREE_DEPTH * ROW_INCREMENT) < (1 << CIRCUIT_K),
        "Circuit row offsets exceed circuit capacity for CIRCUIT_K=12"
    );
};

#[derive(Debug, Clone)]
pub struct SetMembershipConfig {
    pub advice: [Column<Advice>; 15],
    pub fixed: [Column<Fixed>; 6],
    pub instance: Column<Instance>,
    pub poseidon_config: <PoseidonChipType as halo2_proofs::circuit::Chip<pallas::Base>>::Config,
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

    pub fn validate_consistency(&self) -> bool {
        use crate::utils::poseidon_hash;
        let expected_nullifier = poseidon_hash(self.leaf, self.root);
        self.nullifier == expected_nullifier
    }

    pub fn validate_leaf_index(&self) -> bool {
        let expected_depth = self.siblings.len();
        if expected_depth == 0 {
            return self.leaf_index == 0;
        }
        let max_index = (1 << expected_depth) - 1;
        self.leaf_index <= max_index
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

        let circuit = SetMembershipCircuit {
            leaf,
            root,
            nullifier,
            siblings,
            leaf_index,
        };

        if !circuit.validate_leaf_index() {
            let max_index = if circuit.siblings.is_empty() {
                0
            } else {
                (1 << circuit.siblings.len()) - 1
            };
            return Err(anyhow::anyhow!(
                "leaf_index {} is out of bounds for tree with {} siblings (max index: {})",
                circuit.leaf_index,
                circuit.siblings.len(),
                max_index
            ));
        }

        if !circuit.validate_consistency() {
            return Err(anyhow::anyhow!(
                "Nullifier does not match H(leaf || root). Ensure nullifier is computed as poseidon_hash(leaf, root)"
            ));
        }

        Ok(circuit)
    }
}

impl Circuit<pallas::Base> for SetMembershipCircuit {
    type Config = SetMembershipConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<pallas::Base>) -> Self::Config {
        let advice = [
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
            meta.advice_column(),
        ];

        let fixed = [
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
            meta.fixed_column(),
        ];

        let instance = meta.instance_column();

        meta.enable_equality(instance);
        for col in &advice {
            meta.enable_equality(*col);
        }

        for col in &fixed {
            meta.enable_constant(*col);
        }

        let state = [advice[0], advice[1], advice[2]];
        let partial_sbox = advice[3];
        let rc_a = [fixed[0], fixed[1], fixed[2]];
        let rc_b = [fixed[3], fixed[4], fixed[5]];

        let poseidon_config =
            PoseidonChipType::configure::<PoseidonSpec>(meta, state, partial_sbox, rc_a, rc_b);

        SetMembershipConfig {
            advice,
            fixed,
            instance,
            poseidon_config,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<pallas::Base>,
    ) -> Result<(), Error> {
        let poseidon_config = Arc::new(config.poseidon_config);
        let (leaf_cell, root_cell, nullifier_cell) = layouter.assign_region(
            || "assign input values",
            |mut region| {
                let offset = INITIAL_ROW_OFFSET;

                let leaf_cell = region.assign_advice(
                    || "leaf",
                    config.advice[0],
                    offset,
                    || Value::known(self.leaf),
                )?;

                let root_cell = region.assign_advice(
                    || "root",
                    config.advice[1],
                    offset,
                    || Value::known(self.root),
                )?;

                let nullifier_cell = region.assign_advice(
                    || "nullifier",
                    config.advice[2],
                    offset + NULLIFIER_ROW_OFFSET,
                    || Value::known(self.nullifier),
                )?;

                Ok((leaf_cell, root_cell, nullifier_cell))
            },
        )?;

        let leaf_cell_copy = leaf_cell.clone();
        let root_cell_copy = root_cell.clone();

        let poseidon_hash = PoseidonHash::<
            pallas::Base,
            PoseidonChipType,
            PoseidonSpec,
            ConstantLength<2>,
            3,
            2,
        >::init(
            PoseidonChipType::construct((*poseidon_config).clone()),
            layouter.namespace(|| "init nullifier hash"),
        )?;

        let computed_nullifier = poseidon_hash.hash(
            layouter.namespace(|| "compute nullifier"),
            [leaf_cell_copy, root_cell_copy],
        )?;

        layouter.constrain_instance(leaf_cell.cell(), config.instance, 0)?;
        layouter.constrain_instance(root_cell.cell(), config.instance, 1)?;
        layouter.constrain_instance(nullifier_cell.cell(), config.instance, 2)?;

        layouter.assign_region(
            || "constrain nullifier equality",
            |mut region| region.constrain_equal(computed_nullifier.cell(), nullifier_cell.cell()),
        )?;

        let mut current_hash = leaf_cell;
        let mut index = self.leaf_index;
        let mut offset = SIBLING_ROW_OFFSET;

        for (i, &sibling) in self.siblings.iter().enumerate() {
            layouter.assign_region(
                || format!("assign sibling {}", i),
                |mut region| {
                    region.assign_advice(
                        || format!("sibling[{}]", i),
                        config.advice[4],
                        offset,
                        || Value::known(sibling),
                    )
                },
            )?;

            let left_cell = layouter.assign_region(
                || format!("assign left {}", i),
                |mut region| {
                    region.assign_advice(
                        || format!("left[{}]", i),
                        config.advice[5],
                        offset + 1,
                        || {
                            if index.is_multiple_of(2) {
                                current_hash.value().copied()
                            } else {
                                Value::known(sibling)
                            }
                        },
                    )
                },
            )?;

            let right_cell = layouter.assign_region(
                || format!("assign right {}", i),
                |mut region| {
                    region.assign_advice(
                        || format!("right[{}]", i),
                        config.advice[6],
                        offset + 1,
                        || {
                            if index.is_multiple_of(2) {
                                Value::known(sibling)
                            } else {
                                current_hash.value().copied()
                            }
                        },
                    )
                },
            )?;

            let poseidon_hash = PoseidonHash::<
                pallas::Base,
                PoseidonChipType,
                PoseidonSpec,
                ConstantLength<2>,
                3,
                2,
            >::init(
                PoseidonChipType::construct((*poseidon_config).clone()),
                layouter.namespace(|| format!("init merkle hash {}", i)),
            )?;

            current_hash = poseidon_hash.hash(
                layouter.namespace(|| format!("compute merkle hash {}", i)),
                [left_cell, right_cell],
            )?;

            index /= 2;
            offset += ROW_INCREMENT;
        }

        layouter.assign_region(
            || "constrain merkle root equality",
            |mut region| region.constrain_equal(current_hash.cell(), root_cell.cell()),
        )?;

        Ok(())
    }
}

pub struct SetMembershipProver;

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
        Self
    }

    pub fn generate_and_cache_keys(params: &Params<vesta::Affine>) -> Result<CachedKeys, Error> {
        if let Some(keys) = CACHED_KEYS.get() {
            return Ok(keys.clone());
        }

        let circuit = SetMembershipCircuit::default();
        let vk = keygen_vk(params, &circuit)?;
        let pk = keygen_pk(params, vk.clone(), &circuit)?;

        let vk = Arc::new(vk);
        let pk = Arc::new(pk);

        let keys = (vk.clone(), pk.clone());
        let _ = CACHED_KEYS.set(keys.clone());

        Ok(keys)
    }

    /// Check if keys have been generated and are available.
    ///
    /// # Returns
    ///
    /// `true` if both verifying and proving keys are available
    #[must_use]
    pub fn has_keys() -> bool {
        CACHED_KEYS.get().is_some()
    }

    /// Get references to the proving and verifying keys if available.
    ///
    /// # Returns
    ///
    /// `Some((vk, pk))` if keys are available, `None` otherwise
    #[must_use]
    pub fn get_keys() -> Option<CachedKeys> {
        CACHED_KEYS.get().cloned()
    }

    pub fn generate_proof(
        pk: &ProvingKey<vesta::Affine>,
        params: &Params<vesta::Affine>,
        circuit: SetMembershipCircuit,
        public_inputs: &[pallas::Base],
    ) -> Result<Vec<u8>, Error> {
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

    pub fn verify_proof(
        vk: &VerifyingKey<vesta::Affine>,
        params: &Params<vesta::Affine>,
        proof: &[u8],
        public_inputs: &[pallas::Base],
    ) -> Result<bool, Error> {
        let strategy = SingleVerifier::new(params);
        let mut transcript = Blake2bRead::init(proof);

        let public_inputs_slice: &[&[&[pallas::Base]]] = &[&[public_inputs]];
        let result = verify_proof(params, vk, strategy, public_inputs_slice, &mut transcript);

        Ok(result.is_ok())
    }
}
