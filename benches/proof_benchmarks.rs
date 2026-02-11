use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use halo2_proofs::poly::commitment::Params;
use pasta_curves::{pallas, vesta};
use zkp_set_membership::{
    circuit::{SetMembershipCircuit, SetMembershipProver},
    merkle::MerkleTree,
    types::compute_nullifier_from_fields,
    utils::bytes_to_field,
    CIRCUIT_K,
};

fn bench_proof_generation(c: &mut Criterion) {
    let params: Params<_> = Params::<vesta::Affine>::new(CIRCUIT_K);
    let (_, pk) = SetMembershipProver::generate_and_cache_keys(&params).unwrap();

    let mut group = c.benchmark_group("proof_generation");

    for leaf_count in [4, 8, 16, 32, 64, 128, 256].iter() {
        let leaves: Vec<[u8; 32]> = (0..*leaf_count)
            .map(|i| {
                let mut bytes = [0u8; 32];
                bytes[0..8].copy_from_slice(&(i as u64).to_le_bytes());
                bytes
            })
            .collect();

        let tree = MerkleTree::new(leaves.clone()).unwrap();
        let proof = tree.generate_proof(0).unwrap();

        let leaf = bytes_to_field(&proof.leaf);
        let root = bytes_to_field(&proof.root);
        let nullifier = compute_nullifier_from_fields(leaf, root);
        let siblings: Vec<pallas::Base> = proof.siblings.iter().map(bytes_to_field).collect();

        let circuit = SetMembershipCircuit {
            leaf,
            root,
            nullifier,
            siblings,
            leaf_index: 0,
        };

        let public_inputs = vec![leaf, root, nullifier];

        group.bench_with_input(
            BenchmarkId::from_parameter(leaf_count),
            leaf_count,
            |b, _| {
                b.iter(|| {
                    black_box(
                        SetMembershipProver::generate_proof(
                            &pk,
                            &params,
                            circuit.clone(),
                            &public_inputs,
                        )
                        .unwrap(),
                    )
                })
            },
        );
    }

    group.finish();
}

fn bench_proof_verification(c: &mut Criterion) {
    let params: Params<_> = Params::<vesta::Affine>::new(CIRCUIT_K);
    let (vk, pk) = SetMembershipProver::generate_and_cache_keys(&params).unwrap();

    let leaves: Vec<[u8; 32]> = (0..32)
        .map(|i| {
            let mut bytes = [0u8; 32];
            bytes[0..8].copy_from_slice(&(i as u64).to_le_bytes());
            bytes
        })
        .collect();

    let tree = MerkleTree::new(leaves.clone()).unwrap();
    let proof = tree.generate_proof(0).unwrap();

    let leaf = bytes_to_field(&proof.leaf);
    let root = bytes_to_field(&proof.root);
    let nullifier = compute_nullifier_from_fields(leaf, root);
    let siblings: Vec<pallas::Base> = proof.siblings.iter().map(bytes_to_field).collect();

    let circuit = SetMembershipCircuit {
        leaf,
        root,
        nullifier,
        siblings,
        leaf_index: 0,
    };

    let public_inputs = vec![leaf, root, nullifier];

    let zkp_proof =
        SetMembershipProver::generate_proof(&pk, &params, circuit, &public_inputs).unwrap();

    c.bench_function("proof_verification", |b| {
        b.iter(|| {
            black_box(
                SetMembershipProver::verify_proof(&vk, &params, &zkp_proof, &public_inputs)
                    .unwrap(),
            )
        })
    });
}

fn bench_merkle_tree_construction(c: &mut Criterion) {
    let mut group = c.benchmark_group("merkle_tree_construction");

    for leaf_count in [4, 8, 16, 32, 64, 128, 256, 512, 1024].iter() {
        let leaves: Vec<[u8; 32]> = (0..*leaf_count)
            .map(|i| {
                let mut bytes = [0u8; 32];
                bytes[0..8].copy_from_slice(&(i as u64).to_le_bytes());
                bytes
            })
            .collect();

        group.bench_with_input(
            BenchmarkId::from_parameter(leaf_count),
            leaf_count,
            |b, _| b.iter(|| black_box(MerkleTree::new(black_box(leaves.clone())).unwrap())),
        );
    }

    group.finish();
}

fn bench_merkle_proof_generation(c: &mut Criterion) {
    let mut group = c.benchmark_group("merkle_proof_generation");

    for leaf_count in [4, 8, 16, 32, 64, 128, 256].iter() {
        let leaves: Vec<[u8; 32]> = (0..*leaf_count)
            .map(|i| {
                let mut bytes = [0u8; 32];
                bytes[0..8].copy_from_slice(&(i as u64).to_le_bytes());
                bytes
            })
            .collect();

        let tree = MerkleTree::new(leaves).unwrap();

        group.bench_with_input(
            BenchmarkId::from_parameter(leaf_count),
            leaf_count,
            |b, _| b.iter(|| black_box(tree.generate_proof(black_box(0)).unwrap())),
        );
    }

    group.finish();
}

fn bench_poseidon_hash(c: &mut Criterion) {
    c.bench_function("poseidon_hash", |b| {
        b.iter(|| {
            black_box(zkp_set_membership::utils::poseidon_hash(
                black_box(pallas::Base::from(42)),
                black_box(pallas::Base::from(99)),
            ))
        })
    });
}

criterion_group!(
    benches,
    bench_proof_generation,
    bench_proof_verification,
    bench_merkle_tree_construction,
    bench_merkle_proof_generation,
    bench_poseidon_hash
);
criterion_main!(benches);
