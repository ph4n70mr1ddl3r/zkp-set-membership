use anyhow::{Context, Result};
use clap::Parser;
use halo2_proofs::poly::commitment::Params;
use log::{debug, error, info};
use pasta_curves::vesta;
use std::fs;
use zkp_set_membership::{
    circuit::{SetMembershipCircuit, SetMembershipProver},
    types::{ZKProofOutput, HASH_SIZE},
    utils::bytes_to_field,
    CIRCUIT_K,
};

/// Default maximum allowed size for the proof JSON file (1MB)
/// Prevents memory exhaustion from excessively large proof files
/// Can be overridden via `ZKP_MAX_PROOF_FILE_SIZE` environment variable
const DEFAULT_MAX_PROOF_FILE_SIZE: u64 = 1024 * 1024;

/// Default maximum allowed size for the ZK proof bytes (512KB)
/// ZK proofs generated with k=11 should be well below this limit
/// Exceeding this indicates a potentially malformed or incompatible proof
/// Can be overridden via `ZKP_MAX_ZK_PROOF_SIZE` environment variable
const DEFAULT_MAX_ZK_PROOF_SIZE: usize = 512 * 1024;

fn get_max_proof_file_size() -> u64 {
    std::env::var("ZKP_MAX_PROOF_FILE_SIZE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_MAX_PROOF_FILE_SIZE)
}

fn get_max_zk_proof_size() -> usize {
    std::env::var("ZKP_MAX_ZK_PROOF_SIZE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_MAX_ZK_PROOF_SIZE)
}

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
        .map_err(|_| anyhow::anyhow!("{name} must be {HASH_SIZE} bytes, got {len} bytes"))
}

fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args = Args::parse();

    info!("Loading proof from: {}", args.proof_file);
    println!("Loading proof from: {}", args.proof_file);

    let metadata = fs::metadata(&args.proof_file).context("Failed to read proof file metadata")?;

    let max_proof_file_size = get_max_proof_file_size();
    if metadata.len() > max_proof_file_size {
        return Err(anyhow::anyhow!(
            "Proof file too large: {} bytes (max {} bytes). This may indicate a corrupted or invalid proof file. To fix: 1) Verify the proof file is valid, 2) Check if the proof was generated with compatible parameters, or 3) Set ZKP_MAX_PROOF_FILE_SIZE environment variable",
            metadata.len(),
            max_proof_file_size
        ));
    }

    let proof_content =
        fs::read_to_string(&args.proof_file).context("Failed to read proof file")?;

    info!("Parsing proof JSON...");
    println!("Parsing proof JSON...");
    let proof: ZKProofOutput =
        serde_json::from_str(&proof_content).context("Failed to parse proof JSON")?;

    proof.validate().context("Proof validation failed. The proof structure is invalid or contains inconsistent cryptographic data.")?;
    info!("Proof validation passed");

    println!("Proof details:");
    println!("  Merkle Root: {}", proof.merkle_root);
    println!("  Nullifier: {}", proof.nullifier);
    println!("  Leaf Index: {}", proof.leaf_index);
    println!("  Timestamp: {}", proof.timestamp);
    println!("  ZK Proof Size: {} bytes", proof.zkp_proof.len());
    debug!(
        "Proof details: merkle_root={}, nullifier={}, leaf_index={}, timestamp={}",
        proof.merkle_root, proof.nullifier, proof.leaf_index, proof.timestamp
    );

    if proof.zkp_proof.len() > get_max_zk_proof_size() {
        return Err(anyhow::anyhow!(
            "ZK proof size exceeds limit: {} bytes (max {} bytes). The proof may be malformed or generated with incompatible parameters. To fix: 1) Regenerate the proof with the current prover, 2) Verify CIRCUIT_K parameter matches between prover and verifier (current: {}), or 3) Set ZKP_MAX_ZK_PROOF_SIZE environment variable",
            proof.zkp_proof.len(),
            get_max_zk_proof_size(),
            CIRCUIT_K
        ));
    }

    info!("Verifying ZK proof...");
    println!("Verifying ZK proof...");
    let params: Params<_> = Params::<vesta::Affine>::new(CIRCUIT_K);

    let nullifier_file = args.proof_file.replace(".json", "_nullifiers.txt");
    debug!("Nullifier file: {nullifier_file}");

    let mut prover = SetMembershipProver::new();
    info!("Generating/caching ZK-SNARK keys");
    println!("Generating ZK-SNARK keys...");
    prover
        .generate_and_cache_keys(&params)
        .context("Failed to generate verification keys")?;
    let has_replay = if std::path::Path::new(&nullifier_file).exists() {
        let existing_nullifiers = fs::read_to_string(&nullifier_file)
            .with_context(|| format!("Failed to read nullifier file: {nullifier_file}"))?;
        existing_nullifiers
            .lines()
            .any(|line| line.trim() == proof.nullifier)
    } else {
        false
    };

    if has_replay {
        error!(
            "Proof replay detected: nullifier {} has already been used. See {} for details.",
            proof.nullifier, nullifier_file
        );
        return Err(anyhow::anyhow!(
            "Proof replay detected: nullifier {} has already been used. See {} for details.",
            proof.nullifier,
            nullifier_file
        ));
    }

    info!("Replay attack check passed");
    let leaf_hex = proof.verification_key.leaf.clone();
    let root_hex = proof.merkle_root.clone();
    let nullifier_hex = proof.nullifier.clone();

    let leaf_bytes = hex::decode(&leaf_hex).with_context(|| {
        format!("Failed to decode leaf hex '{leaf_hex}': expected 32-byte hex string")
    })?;
    let root_bytes = hex::decode(&root_hex).with_context(|| {
        format!("Failed to decode merkle root hex '{root_hex}': expected 32-byte hex string")
    })?;
    let nullifier_bytes = hex::decode(&nullifier_hex).with_context(|| {
        format!("Failed to decode nullifier hex '{nullifier_hex}': expected 32-byte hex string")
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
                format!("Failed to decode merkle sibling hex '{s}': expected 32-byte hex string")
            })?;
            bytes_to_fixed_array(&bytes, "Merkle sibling")
        })
        .collect();

    let siblings = siblings.context("Failed to parse merkle siblings from proof")?;

    // Note: The circuit is reconstructed here for potential future use, but verification
    // currently only uses the public inputs. The circuit itself is not needed for the
    // verification process with the current implementation.
    let _circuit = SetMembershipCircuit {
        leaf: leaf_base,
        root: root_base,
        nullifier: nullifier_base,
        siblings: siblings.iter().map(bytes_to_field).collect(),
        leaf_index: proof.leaf_index,
    };

    // Public inputs for verification
    let public_inputs = vec![leaf_base, root_base, nullifier_base];

    info!("Verifying ZK proof with public inputs");
    let verification_result = prover.verify_proof(&params, &proof.zkp_proof, &public_inputs);

    match verification_result {
        Ok(_) => {
            info!("Proof verification PASSED");
            println!("\n✓ Proof verification PASSED!");
            println!("The prover has demonstrated knowledge of a private key");
            println!("corresponding to an Ethereum address in set.");
            println!("\nDeterministic nullifier: {}", proof.nullifier);
            println!("This nullifier can be used to prevent double-spending or");
            println!("reuse of same proof while maintaining privacy.");

            fs::write(&nullifier_file, format!("{}\n", proof.nullifier))
                .with_context(|| format!("Failed to record nullifier to: {nullifier_file}"))?;
            info!("Nullifier recorded to: {nullifier_file}");
            println!("\nNullifier recorded to: {nullifier_file}");
            Ok(())
        }
        Err(e) => {
            error!("Proof verification FAILED: {e}");
            println!("\n✗ Proof verification FAILED!");
            println!("Error: {e}");
            Err(anyhow::anyhow!("Proof verification failed"))
        }
    }
}
