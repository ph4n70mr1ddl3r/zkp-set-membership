use halo2_proofs::poly::commitment::Params;
use pasta_curves::{pallas, vesta};
use zkp_set_membership::circuit::{bytes_to_field, SetMembershipCircuit, SetMembershipProver};
use zkp_set_membership::CIRCUIT_K;

fn compute_poseidon_hash(left: pallas::Base, right: pallas::Base) -> pallas::Base {
    use halo2_gadgets::poseidon::primitives::{
        self as poseidon, ConstantLength, P128Pow5T3 as PoseidonSpec,
    };
    let inputs = [left, right];
    poseidon::Hash::<_, PoseidonSpec, ConstantLength<2>, 3, 2>::init().hash(inputs)
}

fn generate_valid_test_data(leaf_bytes: [u8; 32]) -> (SetMembershipCircuit, Vec<pallas::Base>) {
    let leaf = bytes_to_field(&leaf_bytes);

    let root = leaf;
    let nullifier = compute_poseidon_hash(leaf, root);

    let circuit = SetMembershipCircuit {
        leaf,
        root,
        nullifier,
        siblings: vec![],
        leaf_index: 0,
    };

    let public_inputs = vec![leaf, root, nullifier];

    (circuit, public_inputs)
}

#[test]
fn test_circuit_proof_generation() {
    let leaf_bytes = [42u8; 32];
    let (circuit, public_inputs) = generate_valid_test_data(leaf_bytes);

    let params: Params<_> = Params::<vesta::Affine>::new(CIRCUIT_K);

    let mut prover = SetMembershipProver::new();
    prover
        .generate_and_cache_keys(&params)
        .expect("Failed to generate keys");
    let proof = prover.generate_proof(&params, circuit.clone(), public_inputs.clone());
    assert!(proof.is_ok(), "Proof generation should succeed");

    let verification_result = prover.verify_proof(&params, &proof.unwrap(), public_inputs);
    assert!(
        verification_result.is_ok(),
        "Proof verification should succeed"
    );
    assert!(verification_result.unwrap(), "Proof should be valid");
}

#[test]
fn test_circuit_with_zero_values() {
    let leaf = pallas::Base::zero();
    let root = pallas::Base::zero();
    let nullifier = compute_poseidon_hash(leaf, root);

    let circuit = SetMembershipCircuit {
        leaf,
        root,
        nullifier,
        siblings: vec![],
        leaf_index: 0,
    };

    let params: Params<_> = Params::<vesta::Affine>::new(CIRCUIT_K);

    let public_inputs = vec![leaf, root, nullifier];

    let mut prover = SetMembershipProver::new();
    prover
        .generate_and_cache_keys(&params)
        .expect("Failed to generate keys");
    let proof = prover.generate_proof(&params, circuit.clone(), public_inputs.clone());
    assert!(
        proof.is_ok(),
        "Proof generation with zero values should succeed"
    );

    let verification_result = prover.verify_proof(&params, &proof.unwrap(), public_inputs);
    assert!(
        verification_result.is_ok(),
        "Proof verification should not panic with zero values"
    );
}

#[test]
fn test_bytes_to_field() {
    let test_bytes = [1u8; 32];
    let field_element = bytes_to_field(&test_bytes);

    assert_ne!(field_element, pallas::Base::zero());

    let other_bytes = [2u8; 32];
    let other_field = bytes_to_field(&other_bytes);
    assert_ne!(field_element, other_field);
}

#[test]
fn test_proof_with_invalid_public_inputs() {
    let leaf_bytes = [42u8; 32];
    let (circuit, public_inputs) = generate_valid_test_data(leaf_bytes);

    let params: Params<_> = Params::<vesta::Affine>::new(CIRCUIT_K);

    let mut prover = SetMembershipProver::new();
    prover
        .generate_and_cache_keys(&params)
        .expect("Failed to generate keys");
    let proof = prover
        .generate_proof(&params, circuit.clone(), public_inputs)
        .unwrap();

    let invalid_leaf = bytes_to_field(&[99u8; 32]);
    let invalid_nullifier = compute_poseidon_hash(invalid_leaf, circuit.root);
    let invalid_inputs = vec![invalid_leaf, circuit.root, invalid_nullifier];
    let result = prover.verify_proof(&params, &proof, invalid_inputs);

    assert!(result.is_ok());
    assert!(!result.unwrap());
}

#[test]
fn test_bytes_to_field_uses_all_bytes() {
    let mut bytes1 = [0u8; 32];
    let mut bytes2 = [0u8; 32];

    bytes1[31] = 1;
    bytes2[31] = 2;

    let field1 = bytes_to_field(&bytes1);
    let field2 = bytes_to_field(&bytes2);

    assert_ne!(field1, field2);
}

#[test]
fn test_bytes_to_field_zero_bytes() {
    let zero_bytes = [0u8; 32];
    let field_element = bytes_to_field(&zero_bytes);

    assert_eq!(field_element, pallas::Base::zero());
}

#[test]
fn test_circuit_with_siblings() {
    let leaf_bytes = [42u8; 32];
    let sibling_bytes = [43u8; 32];

    let leaf = bytes_to_field(&leaf_bytes);
    let sibling = bytes_to_field(&sibling_bytes);

    let root = compute_poseidon_hash(leaf, sibling);
    let nullifier = compute_poseidon_hash(leaf, root);

    let circuit = SetMembershipCircuit {
        leaf,
        root,
        nullifier,
        siblings: vec![sibling],
        leaf_index: 0,
    };

    let params: Params<_> = Params::<vesta::Affine>::new(CIRCUIT_K);
    let public_inputs = vec![leaf, root, nullifier];

    let mut prover = SetMembershipProver::new();
    prover
        .generate_and_cache_keys(&params)
        .expect("Failed to generate keys");
    let proof = prover.generate_proof(&params, circuit.clone(), public_inputs.clone());
    assert!(
        proof.is_ok(),
        "Proof generation with siblings should succeed"
    );

    let verification_result = prover.verify_proof(&params, &proof.unwrap(), public_inputs);
    assert!(
        verification_result.unwrap(),
        "Proof with siblings should be valid"
    );
}

#[test]
fn test_validate_consistency() {
    let leaf_bytes = [42u8; 32];
    let sibling_bytes = [43u8; 32];

    let leaf = bytes_to_field(&leaf_bytes);
    let sibling = bytes_to_field(&sibling_bytes);

    let root = compute_poseidon_hash(leaf, sibling);
    let nullifier = compute_poseidon_hash(leaf, root);

    let circuit = SetMembershipCircuit {
        leaf,
        root,
        nullifier,
        siblings: vec![sibling],
        leaf_index: 0,
    };

    assert!(circuit.validate_consistency());
}

#[test]
fn test_validate_consistency_fails() {
    let leaf_bytes = [42u8; 32];
    let sibling_bytes = [43u8; 32];

    let leaf = bytes_to_field(&leaf_bytes);
    let sibling = bytes_to_field(&sibling_bytes);

    let root = compute_poseidon_hash(leaf, sibling);
    let wrong_nullifier = pallas::Base::from(12345);

    let circuit = SetMembershipCircuit {
        leaf,
        root,
        nullifier: wrong_nullifier,
        siblings: vec![sibling],
        leaf_index: 0,
    };

    assert!(!circuit.validate_consistency());
}
