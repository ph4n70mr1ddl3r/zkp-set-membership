// ZK-SNARK circuit for set membership proof.

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

pub fn bytes_to_field(bytes: &[u8; 32]) -> pallas::Base {
    let mut value = 0u64;
    for (i, &byte) in bytes.iter().take(8).enumerate() {
        value |= (byte as u64) << (i * 8);
    }
    pallas::Base::from(value)
}

pub struct SetMembershipProver;

impl SetMembershipProver {
    pub fn generate_proof(
        params: &Params<vesta::Affine>,
        circuit: SetMembershipCircuit,
        public_inputs: Vec<pallas::Base>,
    ) -> Result<Vec<u8>, Error> {
        let vk = keygen_vk(params, &circuit)?;
        let pk = keygen_pk(params, vk, &circuit)?;

        let mut transcript = Blake2bWrite::init(vec![]);
        let mut rng = rand::rngs::OsRng;

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
