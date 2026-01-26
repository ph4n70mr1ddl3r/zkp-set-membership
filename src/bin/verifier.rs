use anyhow::{Context, Result};
use clap::Parser;
use halo2_proofs::poly::commitment::Params;
use pasta_curves::vesta;
use std::fs;
use zkp_set_membership::{
    circuit::{bytes_to_field, SetMembershipCircuit, SetMembershipProver},
    types::ZKProofOutput,
};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    proof_file: String,
}

fn main() -> Result<()> {
    let args = Args::parse();

    println!("Loading proof from: {}", args.proof_file);
    let proof_content =
        fs::read_to_string(&args.proof_file).context("Failed to read proof file")?;

    println!("Parsing proof JSON...");
    let proof: ZKProofOutput =
        serde_json::from_str(&proof_content).context("Failed to parse proof JSON")?;

    println!("Proof details:");
    println!("  Merkle Root: {}", proof.merkle_root);
    println!("  Nullifier: {}", proof.nullifier);
    println!("  Leaf Index: {}", proof.leaf_index);
    println!("  Timestamp: {}", proof.timestamp);
    println!("  ZK Proof Size: {} bytes", proof.zkp_proof.len());

    println!("Verifying ZK proof...");
    let k = 11;
    let params: Params<_> = Params::<vesta::Affine>::new(k);

    // Parse hex strings from the proof
    let leaf_bytes =
        hex::decode(&proof.verification_key["leaf"]).context("Failed to decode leaf")?;
    let root_bytes = hex::decode(&proof.merkle_root).context("Failed to decode merkle root")?;
    let nullifier_bytes = hex::decode(&proof.nullifier).context("Failed to decode nullifier")?;

    // Ensure we have 32-byte arrays
    let leaf_array: [u8; 32] = leaf_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("Leaf must be 32 bytes"))?;
    let root_array: [u8; 32] = root_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("Root must be 32 bytes"))?;
    let nullifier_array: [u8; 32] = nullifier_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("Nullifier must be 32 bytes"))?;

    // Convert to field elements
    let leaf_base = bytes_to_field(&leaf_array);
    let root_base = bytes_to_field(&root_array);
    let nullifier_base = bytes_to_field(&nullifier_array);

    let circuit = SetMembershipCircuit {
        leaf: leaf_base,
        root: root_base,
        nullifier: nullifier_base,
    };

    // Public inputs for verification
    let public_inputs = vec![leaf_base, root_base, nullifier_base];

    let verification_result =
        SetMembershipProver::verify_proof(&params, circuit, &proof.zkp_proof, public_inputs);

    match verification_result {
        Ok(_) => {
            println!("\n✓ Proof verification PASSED!");
            println!("The prover has demonstrated knowledge of a private key");
            println!("corresponding to an Ethereum address in set.");
            println!("\nDeterministic nullifier: {}", proof.nullifier);
            println!("This nullifier can be used to prevent double-spending or");
            println!("reuse of same proof while maintaining privacy.");
            Ok(())
        }
        Err(e) => {
            println!("\n✗ Proof verification FAILED!");
            println!("Error: {}", e);
            Err(anyhow::anyhow!("Proof verification failed"))
        }
    }
}
