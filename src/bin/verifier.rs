use anyhow::{Context, Result};
use clap::Parser;
use halo2_proofs::poly::commitment::Params;
use log::{debug, error, info};
use pasta_curves::vesta;
use std::fs;
use std::io::Write;
use std::path::Path;
use zkp_set_membership::{
    circuit::SetMembershipProver,
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

fn check_and_add_nullifier(nullifier_file: &Path, nullifier: &str) -> Result<()> {
    let normalized_nullifier = nullifier.trim().to_lowercase();

    let existing_content = if nullifier_file.exists() {
        fs::read_to_string(nullifier_file).with_context(|| {
            format!(
                "Failed to read nullifier file: {}",
                nullifier_file.display()
            )
        })?
    } else {
        String::new()
    };

    let existing_nullifiers: std::collections::HashSet<String> = existing_content
        .lines()
        .map(|line| line.trim().to_lowercase())
        .collect();

    if existing_nullifiers.contains(&normalized_nullifier) {
        return Err(anyhow::anyhow!("Nullifier already exists in file"));
    }

    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(nullifier_file)
        .with_context(|| {
            format!(
                "Failed to open nullifier file: {}",
                nullifier_file.display()
            )
        })?;

    if !existing_nullifiers.is_empty() {
        writeln!(file).context("Failed to write newline")?;
    }

    writeln!(file, "{}", normalized_nullifier).context("Failed to write nullifier")?;
    Ok(())
}

fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args = Args::parse();

    let proof_path = Path::new(&args.proof_file);
    if !proof_path.exists() {
        return Err(anyhow::anyhow!(
            "Proof file does not exist: {}",
            args.proof_file
        ));
    }

    info!("Loading proof from: {}", args.proof_file);
    debug!("Starting proof file validation");
    println!("Loading proof from: {}", args.proof_file);

    let metadata = fs::metadata(&args.proof_file).context("Failed to read proof file metadata")?;
    debug!("Proof file size: {} bytes", metadata.len());

    let max_proof_file_size = get_max_proof_file_size();
    if metadata.len() > max_proof_file_size {
        return Err(anyhow::anyhow!(
            "Proof file too large: {} bytes (max {} bytes). Set ZKP_MAX_PROOF_FILE_SIZE to override",
            metadata.len(), max_proof_file_size
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
            "ZK proof size {} bytes exceeds limit {} bytes. Set ZKP_MAX_ZK_PROOF_SIZE to override. File: {}",
            proof.zkp_proof.len(),
            get_max_zk_proof_size(),
            args.proof_file
        ));
    }

    info!("Verifying ZK proof...");
    println!("Verifying ZK proof...");
    let params: Params<_> = Params::<vesta::Affine>::new(CIRCUIT_K);

    let mut nullifier_path = proof_path.to_path_buf();
    nullifier_path.set_extension("nullifiers.txt");
    let nullifier_file = nullifier_path
        .to_str()
        .context("Failed to convert nullifier path to string")?;
    debug!("Nullifier file: {nullifier_file}");

    info!("Generating/caching ZK-SNARK keys");
    println!("Generating ZK-SNARK keys...");
    let (vk, _) = SetMembershipProver::generate_and_cache_keys(&params)
        .context("Failed to generate verification keys")?;

    let leaf_hex = &proof.verification_key.leaf;
    let root_hex = &proof.merkle_root;
    let nullifier_hex = &proof.nullifier;

    let leaf_bytes = hex::decode(leaf_hex).with_context(|| {
        format!("Failed to decode leaf hex '{leaf_hex}': expected 32-byte hex string")
    })?;
    let root_bytes = hex::decode(root_hex).with_context(|| {
        format!("Failed to decode merkle root hex '{root_hex}': expected 32-byte hex string")
    })?;
    let nullifier_bytes = hex::decode(nullifier_hex).with_context(|| {
        format!("Failed to decode nullifier hex '{nullifier_hex}': expected 32-byte hex string")
    })?;

    // Ensure we have 32-byte arrays
    let leaf_array = bytes_to_fixed_array(&leaf_bytes, "Leaf")?;
    let root_array = bytes_to_fixed_array(&root_bytes, "Root")?;
    let nullifier_array = bytes_to_fixed_array(&nullifier_bytes, "Nullifier")?;

    let leaf_base = bytes_to_field(&leaf_array);
    let root_base = bytes_to_field(&root_array);
    let nullifier_base = bytes_to_field(&nullifier_array);

    // Validate Merkle siblings format (proof structure verification)
    proof
        .merkle_siblings
        .iter()
        .map(|s| {
            let bytes = hex::decode(s).with_context(|| {
                format!("Failed to decode merkle sibling hex '{s}': expected 32-byte hex string")
            })?;
            bytes_to_fixed_array(&bytes, "Merkle sibling")
        })
        .collect::<Result<Vec<_>>>()
        .context("Failed to validate merkle siblings from proof")?;

    // Public inputs for verification
    let public_inputs = vec![leaf_base, root_base, nullifier_base];

    info!("Verifying ZK proof with public inputs");
    let verification_result =
        SetMembershipProver::verify_proof(&vk, &params, &proof.zkp_proof, &public_inputs);

    match verification_result {
        Ok(_) => {
            info!("Proof verification PASSED");
            println!("\n✓ Proof verification PASSED!");
            println!("The prover has demonstrated knowledge of a private key");
            println!("corresponding to an Ethereum address in set.");
            println!("\nDeterministic nullifier: {}", proof.nullifier);
            println!("This nullifier can be used to prevent double-spending or");
            println!("reuse of same proof while maintaining privacy.");

            check_and_add_nullifier(&nullifier_path, &proof.nullifier).with_context(|| {
                format!(
                    "Failed to record nullifier to: {}",
                    nullifier_path.display()
                )
            })?;
            info!("Nullifier recorded to: {}", nullifier_path.display());
            println!("\nNullifier recorded to: {}", nullifier_path.display());
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
