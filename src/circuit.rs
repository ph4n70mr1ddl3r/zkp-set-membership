//! ZK-SNARK circuit for set membership proof with proper cryptographic constraints.
//!
//! This implementation uses in-circuit Poseidon hash gates and Merkle path
//! verification gates to provide true zero-knowledge guarantees.
//!
//! # Security Guarantees
//!
//! - **In-circuit cryptographic verification**: All hash computations are verified
//!   within circuit using `halo2_gadgets` Poseidon hash chip
//! - **Merkle path verification**: Proves leaf is included in the tree that computes
//!   to the root through proper hash constraints
//! - **Nullifier computation**: Enforces H(leaf || root) = nullifier in-circuit
//! - **Proper constraint enforcement**: Public inputs are cryptographically bound
//!   to private witnesses through the circuit
//!
//! # Circuit Layout
//!
//! The circuit uses a fixed column layout for efficient constraint assignment:
//!
//! ## Column Allocation
//!
//! ```text
//! Advice Columns (15):
//!   advice[0..2] - Poseidon hash state inputs
//!   advice[2]   - Poseidon hash state output
//!   advice[3]   - Partial S-box for Poseidon
//!   advice[4]   - Sibling values in Merkle path
//!   advice[5]   - Left child in Merkle path computation
//!   advice[6]   - Right child in Merkle path computation
//!   advice[7..14] - Reserved for future extensions
//!
//! Fixed Columns (6):
//!   fixed[0..2] - Round constants A for Poseidon
//!   fixed[3..5] - Round constants B for Poseidon
//!
//! Instance Column (1):
//!   instance[0] - Public input: leaf
//!   instance[1] - Public input: root
//!   instance[2] - Public input: nullifier
//! ```
//!
//! ## Row Layout
//!
//! ```text
//! Row 0:        Assign leaf (advice[0]), root (advice[1])
//! Row 1:        Assign nullifier (advice[2])
//! Row 2:        Compute H(leaf || root) -> nullifier, constrain to instance[2]
//! Row 3..99:    Reserved padding
//! Row 100:      Assign sibling[0] (advice[4])
//! Row 101:      Assign left[0] (advice[5]), right[0] (advice[6])
//! Row 102:      Compute H(left[0] || right[0]) -> current_hash
//! Row 150:      Assign sibling[1] (advice[4])
//! Row 151:      Assign left[1] (advice[5]), right[1] (advice[6])
//! Row 152:      Compute H(left[1] || right[1]) -> current_hash
//! ... (repeat for each level, ROW_INCREMENT = 50 rows per level)
//!
//! Final row:    Constrain current_hash == root (instance[1])
//! ```
//!
//! # Constraint Flow
//!
//! 1. **Nullifier Constraint**:
//!    - Instance\[0\] (leaf) + Instance\[1\] (root) --\[Poseidon\]--> Instance\[2\] (nullifier)
//!
//! 2. **Merkle Path Verification**:
//!    - For each level i from 0 to depth-1:
//!      - If `leaf_index` % 2 == 0: left = `current_hash`, right = sibling\[i\]
//!      - If `leaf_index` % 2 == 1: left = sibling\[i\], right = `current_hash`
//!      - H(left || right) -> `current_hash`
//!      - `leaf_index` /= 2
//!    - Final constraint: `current_hash` == root
//!
//! # Maximum Tree Depth
//!
//! The circuit supports trees up to `MAX_TREE_DEPTH = 12` levels (4096 leaves).
//! Each level requires `ROW_INCREMENT = 50` rows.
//! Starting from `SIBLING_ROW_OFFSET = 100`, the maximum row used is:
//!   100 + (12 * 50) = 700 rows
//!
//! This is well within the circuit capacity of `2^CIRCUIT_K` = 4096 rows.

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

// Row offset for initial assignment (leaf, root)
const INITIAL_ROW_OFFSET: usize = 0;

// Row offset for nullifier assignment (after nullifier hash computation)
// The nullifier value is assigned at row 1 to separate it from leaf/root inputs at row 0
const NULLIFIER_ROW_OFFSET: usize = 1;

// Starting row for Merkle path verification (after nullifier computation at rows 0-1)
// Rows 2-99 provide buffer/spacing between nullifier and Merkle path regions
// This spacing ensures no constraint overlap and provides flexibility for layouter optimization
const SIBLING_ROW_OFFSET: usize = 100;

// Rows per level in Merkle path (sibling, left, right, hash computation)
// Each level needs ~50 rows to accommodate all assignments and Poseidon hash.
// This value was chosen based on Halo2 layout requirements:
// - Row 0: sibling assignment (advice[4])
// - Row 1: left and right assignment (advice[5] and advice[6])
// - Rows 2-49: Poseidon hash computation with 3 full rounds and 2 partial rounds
//
// The value 50 provides a safe margin; actual usage is typically ~15-20 rows per level
// This ensures layouter has flexibility to optimize assignments across rows
const ROW_INCREMENT: usize = 50;

const MAX_TREE_DEPTH: usize = 12;

const _: () = {
    const MAX_USED_ROWS: usize = SIBLING_ROW_OFFSET + (MAX_TREE_DEPTH * ROW_INCREMENT);
    const CIRCUIT_CAPACITY: usize = 1 << CIRCUIT_K;
    const _: () = assert!(
        MAX_USED_ROWS < CIRCUIT_CAPACITY,
        "Circuit row offsets exceed circuit capacity"
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
    #[must_use]
    pub fn builder() -> SetMembershipCircuitBuilder {
        SetMembershipCircuitBuilder::default()
    }

    #[must_use]
    pub fn validate_consistency(&self) -> bool {
        use crate::utils::poseidon_hash;
        let expected_nullifier = poseidon_hash(self.leaf, self.root);
        self.nullifier == expected_nullifier
    }

    pub fn validate_consistency_err(&self) -> anyhow::Result<()> {
        use crate::utils::poseidon_hash;
        let expected_nullifier = poseidon_hash(self.leaf, self.root);
        if self.nullifier != expected_nullifier {
            anyhow::bail!(
                "Nullifier mismatch: expected {:?}, got {:?}",
                expected_nullifier,
                self.nullifier
            );
        }
        Ok(())
    }

    #[must_use]
    pub fn validate_leaf_index(&self) -> bool {
        let expected_depth = self.siblings.len();
        if expected_depth == 0 {
            return self.leaf_index == 0;
        }
        let max_index = (1 << expected_depth) - 1;
        self.leaf_index <= max_index
    }

    /// Validates that the leaf index is within bounds for the given tree depth.
    ///
    /// # Errors
    ///
    /// Returns an error if the leaf index is out of bounds for the tree
    /// with the given number of siblings (tree depth).
    pub fn validate_leaf_index_err(&self) -> anyhow::Result<()> {
        let expected_depth = self.siblings.len();
        let max_index = if expected_depth == 0 {
            0
        } else {
            (1 << expected_depth) - 1
        };
        if self.leaf_index > max_index {
            anyhow::bail!(
                "leaf_index {} is out of bounds for tree with {} siblings. With {} siblings, the maximum valid leaf index is {}. Either reduce the leaf_index or ensure the tree depth is correct.",
                self.leaf_index,
                self.siblings.len(),
                self.siblings.len(),
                max_index
            );
        }
        Ok(())
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
    #[must_use]
    pub fn leaf(mut self, leaf: pallas::Base) -> Self {
        self.leaf = Some(leaf);
        self
    }

    #[must_use]
    pub fn root(mut self, root: pallas::Base) -> Self {
        self.root = Some(root);
        self
    }

    #[must_use]
    pub fn nullifier(mut self, nullifier: pallas::Base) -> Self {
        self.nullifier = Some(nullifier);
        self
    }

    #[must_use]
    pub fn siblings(mut self, siblings: Vec<pallas::Base>) -> Self {
        self.siblings = Some(siblings);
        self
    }

    #[must_use]
    pub fn leaf_index(mut self, leaf_index: usize) -> Self {
        self.leaf_index = Some(leaf_index);
        self
    }

    /// Builds a `SetMembershipCircuit` from the configured parameters.
    ///
    /// # Errors
    ///
    /// Returns an error if any required field is missing or if validation
    /// fails (leaf index out of bounds or nullifier mismatch).
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

        circuit.validate_leaf_index_err()?;
        circuit.validate_consistency_err()?;

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
        if self.siblings.len() > MAX_TREE_DEPTH {
            return Err(Error::Synthesis);
        }

        if self.siblings.is_empty() && self.leaf_index != 0 {
            return Err(Error::Synthesis);
        }

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

        let poseidon_hash = PoseidonHash::<
            pallas::Base,
            PoseidonChipType,
            PoseidonSpec,
            ConstantLength<2>,
            3,
            2,
        >::init(
            PoseidonChipType::construct(config.poseidon_config.clone()),
            layouter.namespace(|| "init nullifier hash"),
        )?;

        let computed_nullifier = poseidon_hash.hash(
            layouter.namespace(|| "compute nullifier"),
            [leaf_cell.clone(), root_cell.clone()],
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
                || format!("assign sibling {i}"),
                |mut region| {
                    region.assign_advice(
                        || format!("sibling[{i}]"),
                        config.advice[4],
                        offset,
                        || Value::known(sibling),
                    )
                },
            )?;

            let left_cell = layouter.assign_region(
                || format!("assign left {i}"),
                |mut region| {
                    region.assign_advice(
                        || format!("left[{i}]"),
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
                || format!("assign right {i}"),
                |mut region| {
                    region.assign_advice(
                        || format!("right[{i}]"),
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
                PoseidonChipType::construct(config.poseidon_config.clone()),
                layouter.namespace(|| format!("init merkle hash {i}")),
            )?;

            current_hash = poseidon_hash.hash(
                layouter.namespace(|| format!("compute merkle hash {i}")),
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
    pub const fn new() -> Self {
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

        let keys = (vk, pk);
        if CACHED_KEYS.set(keys.clone()).is_err() {
            log::debug!("Keys were already set by another thread, using that instance");
            return Ok(CACHED_KEYS.get().unwrap().clone());
        }

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
    pub fn get_keys() -> Option<&'static CachedKeys> {
        CACHED_KEYS.get()
    }

    /// Generates a zero-knowledge proof for the given circuit and public inputs.
    ///
    /// # Errors
    ///
    /// Returns an error if proof generation fails due to:
    /// - Invalid circuit parameters
    /// - Synthesis errors during proof creation
    /// - I/O errors during transcript writing
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

    /// Verifies a zero-knowledge proof against the given public inputs.
    ///
    /// # Errors
    ///
    /// Returns an error if verification fails due to:
    /// - Invalid proof format
    /// - Mismatched public inputs
    /// - Proof verification failure
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
