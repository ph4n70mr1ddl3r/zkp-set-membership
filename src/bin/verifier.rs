use anyhow::{Context, Result};
use clap::Parser;
use halo2_proofs::poly::commitment::Params;
use log::{debug, error, info};
use pasta_curves::pallas;
use pasta_curves::vesta;
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use zkp_set_membership::{
    circuit::SetMembershipProver,
    types::{ZKProofOutput, HASH_SIZE},
    utils::bytes_to_field,
    CIRCUIT_K,
};

const DEFAULT_MAX_PROOF_FILE_SIZE: u64 = 100 * 1024;
const DEFAULT_MAX_ZK_PROOF_SIZE: usize = 100 * 1024;

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

fn load_and_validate_proof(path: &str) -> Result<ZKProofOutput> {
    let proof_path = Path::new(path);
    if !proof_path.exists() {
        return Err(anyhow::anyhow!("Proof file does not exist: {path}"));
    }

    info!("Loading proof from: {path}");
    debug!("Starting proof file validation");
    println!("Loading proof from: {path}");

    let metadata = fs::metadata(proof_path).context("Failed to read proof file metadata")?;
    debug!("Proof file size: {} bytes", metadata.len());

    let max_proof_file_size = get_max_proof_file_size();
    if metadata.len() > max_proof_file_size {
        return Err(anyhow::anyhow!(
            "Proof file too large: {} bytes (max {} bytes). Set ZKP_MAX_PROOF_FILE_SIZE to override",
            metadata.len(), max_proof_file_size
        ));
    }

    let proof_content = fs::read_to_string(proof_path).context("Failed to read proof file")?;

    info!("Parsing proof JSON...");
    println!("Parsing proof JSON...");
    let proof: ZKProofOutput =
        serde_json::from_str(&proof_content).context("Failed to parse proof JSON")?;

    proof.validate().context("Proof validation failed. The proof structure is invalid or contains inconsistent cryptographic data.")?;
    info!("Proof validation passed");

    println!("Proof details:");
    println!("  Merkle Root: {}", proof.merkle_root);
    println!("  Nullifier: {}", proof.public_inputs.nullifier);
    println!("  Leaf Index: {}", proof.leaf_index);
    println!("  Timestamp: {}", proof.timestamp);
    println!("  ZK Proof Size: {} bytes", proof.zkp_proof.len());
    debug!(
        "Proof details: merkle_root={}, nullifier={}, leaf_index={}, timestamp={}",
        proof.merkle_root, proof.public_inputs.nullifier, proof.leaf_index, proof.timestamp
    );

    if proof.zkp_proof.len() > get_max_zk_proof_size() {
        return Err(anyhow::anyhow!(
            "ZK proof size {} bytes exceeds limit {} bytes. Set ZKP_MAX_ZK_PROOF_SIZE to override. File: {path}",
            proof.zkp_proof.len(),
            get_max_zk_proof_size()
        ));
    }

    Ok(proof)
}

fn decode_hex_field(hex_str: &str, name: &str) -> Result<[u8; HASH_SIZE]> {
    let bytes = hex::decode(hex_str).with_context(|| {
        format!("Failed to decode {name} hex '{hex_str}': expected 32-byte hex string")
    })?;
    let len = bytes.len();
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("{name} must be {HASH_SIZE} bytes, got {len} bytes"))
}

fn prepare_public_inputs(proof: &ZKProofOutput) -> Result<Vec<pallas::Base>> {
    let leaf_array = decode_hex_field(&proof.public_inputs.leaf, "Leaf")?;
    let root_array = decode_hex_field(&proof.merkle_root, "Root")?;
    let nullifier_array = decode_hex_field(&proof.public_inputs.nullifier, "Nullifier")?;

    let leaf_base = bytes_to_field(&leaf_array);
    let root_base = bytes_to_field(&root_array);
    let nullifier_base = bytes_to_field(&nullifier_array);

    for s in &proof.merkle_siblings {
        decode_hex_field(s, "Merkle sibling")?;
    }

    Ok(vec![leaf_base, root_base, nullifier_base])
}

fn get_nullifier_path(proof_path: &Path) -> PathBuf {
    let mut nullifier_path = proof_path.to_path_buf();
    nullifier_path.set_extension("nullifiers.txt");
    nullifier_path
}

fn check_and_add_nullifier(nullifier_file: &Path, nullifier: &str) -> Result<()> {
    let normalized_nullifier = nullifier.trim().to_lowercase();

    if normalized_nullifier.is_empty() {
        return Err(anyhow::anyhow!(
            "Nullifier is empty. Cannot record invalid nullifier to file: {}",
            nullifier_file.display()
        ));
    }

    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(nullifier_file)
        .with_context(|| {
            format!(
                "Failed to open nullifier file: {}. Check file permissions and disk space.",
                nullifier_file.display()
            )
        })?;

    if let Err(e) = fs2::FileExt::try_lock_exclusive(&file) {
        return Err(anyhow::anyhow!(
            "Could not acquire exclusive lock on nullifier file: {}. This may indicate:\n\
             - Another verifier process is currently running\n\
             - A previous verifier process crashed without releasing the lock\n\
             - File system permission issues\n\
             Error details: {}. Please wait a moment and retry, or manually check if another process is holding the lock.",
            nullifier_file.display(),
            e
        ));
    }

    let reader = BufReader::new(&file);
    let existing_nullifiers: std::collections::HashSet<String> =
        reader.lines().map_while(Result::ok).collect();

    if existing_nullifiers.contains(&normalized_nullifier) {
        fs2::FileExt::unlock(&file)?;
        return Err(anyhow::anyhow!(
            "Nullifier {} already exists in file {}. This indicates a replay attack attempt or the proof has been used before.",
            normalized_nullifier,
            nullifier_file.display()
        ));
    }

    file.seek(SeekFrom::End(0)).with_context(|| {
        format!(
            "Failed to seek to end of nullifier file: {}",
            nullifier_file.display()
        )
    })?;

    if !existing_nullifiers.is_empty() {
        writeln!(file).context("Failed to write newline to nullifier file")?;
    }

    writeln!(file, "{normalized_nullifier}").context("Failed to write nullifier to file")?;

    fs2::FileExt::unlock(&file)?;

    debug!(
        "Nullifier {} recorded to: {}. File locking was used to prevent race conditions.",
        normalized_nullifier,
        nullifier_file.display()
    );
    Ok(())
}

fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args = Args::parse();
    let proof_path = Path::new(&args.proof_file);

    let proof = load_and_validate_proof(&args.proof_file)?;

    info!("Verifying ZK proof...");
    println!("Verifying ZK proof...");
    let params: Params<_> = Params::<vesta::Affine>::new(CIRCUIT_K);

    let nullifier_path = get_nullifier_path(proof_path);
    let nullifier_file = nullifier_path
        .to_str()
        .context("Failed to convert nullifier path to string")?;
    debug!("Nullifier file: {nullifier_file}");

    info!("Generating/caching ZK-SNARK keys");
    println!("Generating ZK-SNARK keys...");
    let (vk, _) = SetMembershipProver::generate_and_cache_keys(&params)
        .context("Failed to generate verification keys")?;

    let public_inputs = prepare_public_inputs(&proof)?;

    info!("Verifying ZK proof with public inputs");
    let verification_result =
        SetMembershipProver::verify_proof(&vk, &params, &proof.zkp_proof, &public_inputs);

    match verification_result {
        Ok(_) => {
            info!("Proof verification PASSED");
            println!("\n✓ Proof verification PASSED!");
            println!("The prover has demonstrated knowledge of a private key");
            println!("corresponding to an Ethereum address in set.");
            println!(
                "\nDeterministic nullifier: {}",
                proof.public_inputs.nullifier
            );
            println!("This nullifier can be used to prevent double-spending or");
            println!("reuse of same proof while maintaining privacy.");

            check_and_add_nullifier(&nullifier_path, &proof.public_inputs.nullifier).with_context(
                || {
                    format!(
                        "Failed to record nullifier to: {}",
                        nullifier_path.display()
                    )
                },
            )?;
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
