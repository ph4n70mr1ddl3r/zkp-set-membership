use anyhow::{Context, Result};
use clap::Parser;
use halo2_proofs::poly::commitment::Params;
use pasta_curves::vesta;
use std::fs;
use zkp_set_membership::{
    circuit::{bytes_to_field, SetMembershipCircuit, SetMembershipProver},
    types::{ZKProofOutput, HASH_SIZE},
    CIRCUIT_K,
};

const MAX_PROOF_FILE_SIZE: u64 = 1024 * 1024;
const MAX_ZK_PROOF_SIZE: usize = 512 * 1024;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    proof_file: String,
}

fn bytes_to_fixed_array(bytes: &[u8], name: &str) -> Result<[u8; HASH_SIZE]> {
    let len = bytes.len();
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("{} must be {} bytes, got {} bytes", name, HASH_SIZE, len))
}

fn main() -> Result<()> {
    let args = Args::parse();

    println!("Loading proof from: {}", args.proof_file);

    let metadata = fs::metadata(&args.proof_file).context("Failed to read proof file metadata")?;

    if metadata.len() > MAX_PROOF_FILE_SIZE {
        return Err(anyhow::anyhow!(
            "Proof file too large: {} bytes (max {} bytes). This may indicate a corrupted or invalid proof file.",
            metadata.len(),
            MAX_PROOF_FILE_SIZE
        ));
    }

    let proof_content =
        fs::read_to_string(&args.proof_file).context("Failed to read proof file")?;

    println!("Parsing proof JSON...");
    let proof: ZKProofOutput =
        serde_json::from_str(&proof_content).context("Failed to parse proof JSON")?;

    proof.validate().context("Proof validation failed")?;

    println!("Proof details:");
    println!("  Merkle Root: {}", proof.merkle_root);
    println!("  Nullifier: {}", proof.nullifier);
    println!("  Leaf Index: {}", proof.leaf_index);
    println!("  Timestamp: {}", proof.timestamp);
    println!("  ZK Proof Size: {} bytes", proof.zkp_proof.len());

    if proof.zkp_proof.len() > MAX_ZK_PROOF_SIZE {
        return Err(anyhow::anyhow!(
            "ZK proof size exceeds limit: {} bytes (max {} bytes). The proof may be malformed or generated with incompatible parameters.",
            proof.zkp_proof.len(),
            MAX_ZK_PROOF_SIZE
        ));
    }

    if proof.merkle_siblings.is_empty() {
        return Err(anyhow::anyhow!(
            "Invalid proof: Merkle proof must contain at least one sibling"
        ));
    }

    println!("Verifying ZK proof...");
    let params: Params<_> = Params::<vesta::Affine>::new(CIRCUIT_K);

    let nullifier_file = args.proof_file.replace(".json", "_nullifiers.txt");
    let has_replay = if std::path::Path::new(&nullifier_file).exists() {
        let existing_nullifiers = fs::read_to_string(&nullifier_file)?;
        existing_nullifiers
            .lines()
            .any(|line| line.trim() == proof.nullifier)
    } else {
        false
    };

    if has_replay {
        return Err(anyhow::anyhow!(
            "Proof replay detected: nullifier {} has already been used",
            proof.nullifier
        ));
    }

    let leaf_hex = proof.verification_key.leaf.clone();
    let root_hex = proof.merkle_root.clone();
    let nullifier_hex = proof.nullifier.clone();

    let leaf_bytes = hex::decode(&leaf_hex).with_context(|| {
        format!(
            "Failed to decode leaf hex '{}': expected 32-byte hex string",
            leaf_hex
        )
    })?;
    let root_bytes = hex::decode(&root_hex).with_context(|| {
        format!(
            "Failed to decode merkle root hex '{}': expected 32-byte hex string",
            root_hex
        )
    })?;
    let nullifier_bytes = hex::decode(&nullifier_hex).with_context(|| {
        format!(
            "Failed to decode nullifier hex '{}': expected 32-byte hex string",
            nullifier_hex
        )
    })?;

    // Ensure we have 32-byte arrays
    let leaf_array = bytes_to_fixed_array(&leaf_bytes, "Leaf")?;
    let root_array = bytes_to_fixed_array(&root_bytes, "Root")?;
    let nullifier_array = bytes_to_fixed_array(&nullifier_bytes, "Nullifier")?;

    let leaf_base = bytes_to_field(&leaf_array);
    let root_base = bytes_to_field(&root_array);
    let nullifier_base = bytes_to_field(&nullifier_array);

    // Parse Merkle siblings from proof
    let siblings: Result<Vec<[u8; 32]>> = proof
        .merkle_siblings
        .iter()
        .map(|s| {
            let bytes = hex::decode(s).with_context(|| {
                format!(
                    "Failed to decode merkle sibling hex '{}': expected 32-byte hex string",
                    s
                )
            })?;
            bytes_to_fixed_array(&bytes, "Merkle sibling")
        })
        .collect();

    let siblings = siblings.context("Failed to parse merkle siblings from proof")?;

    let circuit = SetMembershipCircuit {
        leaf: leaf_base,
        root: root_base,
        nullifier: nullifier_base,
        siblings: siblings.iter().map(bytes_to_field).collect(),
        leaf_index: proof.leaf_index,
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

            fs::write(&nullifier_file, format!("{}\n", proof.nullifier))
                .context("Failed to record nullifier")?;
            println!("\nNullifier recorded to: {}", nullifier_file);
            Ok(())
        }
        Err(e) => {
            println!("\n✗ Proof verification FAILED!");
            println!("Error: {}", e);
            Err(anyhow::anyhow!("Proof verification failed"))
        }
    }
}
