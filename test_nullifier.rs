use halo2_gadgets::poseidon::primitives::{
    self as poseidon, ConstantLength, P128Pow5T3 as PoseidonSpec,
};
use pasta_curves::group::ff::PrimeField;
use pasta_curves::pallas;

fn bytes_to_field(bytes: &[u8]) -> pallas::Base {
    let mut value = pallas::Base::zero();
    let base = pallas::Base::from(256u64);
    
    let bytes_32: [u8; 32] = if bytes.len() >= 32 {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes[..32]);
        arr
    } else {
        let mut arr = [0u8; 32];
        arr[..bytes.len()].copy_from_slice(bytes);
        arr
    };
    
    for &byte in &bytes_32 {
        value = value * base + pallas::Base::from(byte as u64);
    }
    
    value
}

fn field_to_bytes(field: pallas::Base) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    let repr = field.to_repr();
    bytes.copy_from_slice(repr.as_ref());
    bytes
}

fn poseidon_hash(left: pallas::Base, right: pallas::Base) -> pallas::Base {
    let inputs = [left, right];
    poseidon::Hash::<_, PoseidonSpec, ConstantLength<2>, 3, 2>::init().hash(inputs)
}

fn compute_nullifier(leaf_bytes: &[u8], merkle_root: &[u8]) -> [u8; 32] {
    let leaf_field = bytes_to_field(leaf_bytes);
    let root_field = bytes_to_field(merkle_root);
    let hash_field = poseidon_hash(leaf_field, root_field);
    field_to_bytes(hash_field)
}

fn main() {
    // Test values from the prover run
    let leaf_str = "f39fd6e51aad88f6f4ce6ab8827279cfffb92266";
    let leaf_addr_bytes = hex::decode(leaf_str).unwrap();
    let mut leaf_32 = [0u8; 32];
    leaf_32[12..].copy_from_slice(&leaf_addr_bytes);
    
    let root_str = "e795172e114afa5fc39960ba6a16795c6a66b14105e9cecdc117ec06e2430d57";
    let root_bytes = hex::decode(root_str).unwrap();
    let mut root_32 = [0u8; 32];
    root_32.copy_from_slice(&root_bytes);
    
    let nullifier = compute_nullifier(&leaf_32, &root_32);
    println!("Expected nullifier: {}", hex::encode(nullifier));
    
    // Show what the circuit is computing
    let leaf_field = bytes_to_field(&leaf_32);
    let root_field = bytes_to_field(&root_32);
    println!("Leaf field: {:?}", leaf_field);
    println!("Root field: {:?}", root_field);
    
    let hash_field = poseidon_hash(leaf_field, root_field);
    println!("Hash field: {:?}", hash_field);
}
