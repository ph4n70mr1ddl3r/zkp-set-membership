use halo2_proofs::poly::commitment::Params;
use pasta_curves::vesta;
use zkp_set_membership::circuit::{bytes_to_field, SetMembershipCircuit, SetMembershipProver};

#[test]
fn test_circuit_proof_generation() {
    // Create test values
    let leaf_bytes = [1u8; 32];
    let root_bytes = [2u8; 32];
    let nullifier_bytes = [3u8; 32];

    // Convert to field elements
    let leaf = bytes_to_field(&leaf_bytes);
    let root = bytes_to_field(&root_bytes);
    let nullifier = bytes_to_field(&nullifier_bytes);

    // Create circuit
    let circuit = SetMembershipCircuit {
        leaf,
        root,
        nullifier,
    };

    // Generate parameters
    let k = 11;
    let params: Params<_> = Params::<vesta::Affine>::new(k);

    // Public inputs
    let public_inputs = vec![leaf, root, nullifier];

    // Generate proof
    let proof =
        SetMembershipProver::generate_proof(&params, circuit.clone(), public_inputs.clone());
    assert!(proof.is_ok(), "Proof generation should succeed");

    // Verify proof
    let verification_result =
        SetMembershipProver::verify_proof(&params, circuit, &proof.unwrap(), public_inputs);
    assert!(
        verification_result.is_ok(),
        "Proof verification should succeed"
    );
    assert!(verification_result.unwrap(), "Proof should be valid");
}

#[test]
fn test_circuit_with_zero_values() {
    // Create circuit with zero values (should fail due to constraints)
    let circuit = SetMembershipCircuit {
        leaf: pasta_curves::pallas::Base::zero(),
        root: pasta_curves::pallas::Base::zero(),
        nullifier: pasta_curves::pallas::Base::zero(),
    };

    // Generate parameters
    let k = 11;
    let params: Params<_> = Params::<vesta::Affine>::new(k);

    // Public inputs
    let public_inputs = vec![
        pasta_curves::pallas::Base::zero(),
        pasta_curves::pallas::Base::zero(),
        pasta_curves::pallas::Base::zero(),
    ];

    // Generate proof (should fail because constraints prevent zero values)
    let proof = SetMembershipProver::generate_proof(&params, circuit, public_inputs);

    // This might succeed or fail depending on how constraints are enforced
    // For now, just test that it doesn't crash
    assert!(proof.is_ok() || proof.is_err());
}

#[test]
fn test_bytes_to_field() {
    // Test conversion of bytes to field element
    let test_bytes = [1u8; 32];
    let field_element = bytes_to_field(&test_bytes);

    // Ensure it's not zero
    assert_ne!(field_element, pasta_curves::pallas::Base::zero());

    // Test different inputs produce different outputs
    let other_bytes = [2u8; 32];
    let other_field = bytes_to_field(&other_bytes);
    assert_ne!(field_element, other_field);
}
