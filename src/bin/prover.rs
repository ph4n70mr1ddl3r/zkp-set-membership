use anyhow::{Context, Result};
use clap::Parser;
use ethers::signers::{LocalWallet, Signer};
use halo2_proofs::poly::commitment::Params;
use pasta_curves::vesta;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use zkp_set_membership::{
    circuit::{SetMembershipCircuit, SetMembershipProver},
    merkle::MerkleTree,
    types::{compute_nullifier, compute_nullifier_from_fields, VerificationKey, ZKProofOutput},
    utils::{bytes_to_field, validate_and_strip_hex},
    CIRCUIT_K,
};

/// Default maximum allowed size for the accounts file (10MB)
/// Prevents memory exhaustion from excessively large input files
/// Can be overridden via ZKP_MAX_ACCOUNTS_FILE_SIZE environment variable
const DEFAULT_MAX_ACCOUNTS_FILE_SIZE: u64 = 10 * 1024 * 1024;

fn get_max_accounts_file_size() -> u64 {
    std::env::var("ZKP_MAX_ACCOUNTS_FILE_SIZE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_MAX_ACCOUNTS_FILE_SIZE)
}

/// Expected length of an Ethereum address in hex characters (excluding 0x prefix)
/// Ethereum addresses are 20 bytes = 40 hex characters
const ADDRESS_HEX_LENGTH: usize = 40;

/// Expected length of a private key in hex characters (excluding 0x prefix)
/// Ethereum private keys are 32 bytes = 64 hex characters
const PRIVATE_KEY_HEX_LENGTH: usize = 64;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    accounts_file: PathBuf,

    #[arg(short, long)]
    private_key: String,

    #[arg(short, long, default_value = "proof.json")]
    output: PathBuf,
}

fn address_to_bytes_normalized(normalized_address: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(normalized_address).context("Failed to decode address from hex")?;

    if bytes.len() != 20 {
        return Err(anyhow::anyhow!("Address bytes length mismatch"));
    }

    let mut full_bytes = [0u8; 32];
    full_bytes[12..32].copy_from_slice(&bytes);
    Ok(full_bytes)
}

fn normalize_address(address: &str) -> Result<String> {
    validate_and_strip_hex(address, ADDRESS_HEX_LENGTH).map(|s| s.to_lowercase())
}

/// Validates and normalizes a batch of addresses in one pass.
/// More efficient than processing individually.
fn normalize_addresses_batch(addresses: &[String]) -> Result<Vec<String>> {
    addresses
        .iter()
        .enumerate()
        .map(|(i, addr)| {
            normalize_address(addr).with_context(|| {
                format!("Failed to validate address at line {}: '{}'", i + 1, addr)
            })
        })
        .collect()
}

fn validate_private_key(private_key: &str) -> Result<()> {
    validate_and_strip_hex(private_key, PRIVATE_KEY_HEX_LENGTH)?;
    Ok(())
}

fn main() -> Result<()> {
    let args = Args::parse();

    println!("Loading accounts from: {:?}", args.accounts_file);

    let accounts_content =
        fs::read_to_string(&args.accounts_file).context("Failed to read accounts file")?;

    let content_size = accounts_content.len() as u64;
    let max_accounts_size = get_max_accounts_file_size();
    if content_size > max_accounts_size {
        return Err(anyhow::anyhow!(
            "Accounts file too large: {} bytes (max {} bytes). To fix: 1) Reduce the number of accounts, 2) Split into multiple files, or 3) Set ZKP_MAX_ACCOUNTS_FILE_SIZE environment variable (current max: {} bytes)",
            content_size,
            max_accounts_size,
            max_accounts_size
        ));
    }

    let addresses: Vec<String> = accounts_content
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| line.trim().to_string())
        .collect();

    if addresses.is_empty() {
        return Err(anyhow::anyhow!(
            "No valid addresses found in accounts file '{}'. Please ensure the file contains Ethereum addresses in hex format (one per line, e.g., 0x742d35Cc6634C0532925a3b844Bc454e4438f44e)",
            args.accounts_file.display()
        ));
    }

    println!(
        "Loaded {} addresses from {}",
        addresses.len(),
        args.accounts_file.display()
    );
    println!("Validating private key...");
    validate_private_key(&args.private_key)?;

    println!("Parsing private key...");
    let wallet: LocalWallet = args
        .private_key
        .parse()
        .context("Failed to parse private key")?;
    let prover_address = wallet.address();
    let prover_address_str = format!("{:x}", prover_address);
    println!("Prover address: 0x{}", prover_address_str);

    let normalized_addresses =
        normalize_addresses_batch(&addresses).context("Failed to normalize addresses")?;

    let prover_normalized = normalize_address(&prover_address_str)?;

    let mut leaf_hashes = Vec::with_capacity(addresses.len());
    let mut leaf_index = None;

    for (i, (address, normalized)) in addresses
        .iter()
        .zip(normalized_addresses.iter())
        .enumerate()
    {
        let address_bytes = address_to_bytes_normalized(normalized).with_context(|| {
            format!("Failed to process address at line {}: '{}'", i + 1, address)
        })?;
        leaf_hashes.push(address_bytes);

        if normalized == &prover_normalized {
            if leaf_index.is_some() {
                return Err(anyhow::anyhow!(
                    "Duplicate prover address found in accounts file at line {}",
                    i + 1
                ));
            }
            leaf_index = Some(i);
            println!("Found prover address at index {}", i);
        }
    }

    let leaf_index = leaf_index.context(format!(
        "Prover address '0x{}' not found in accounts file '{}'. Ensure: 1) Your private key corresponds to an address in the set, 2) The address is in lowercase format, 3) The accounts file contains exactly one address per line",
        prover_address_str,
        args.accounts_file.display()
    ))?;

    println!("Building Merkle tree...");
    let merkle_tree = MerkleTree::new(leaf_hashes.clone());
    println!("Merkle root: {}", hex::encode(merkle_tree.root));

    println!("Generating Merkle proof...");
    let merkle_proof = merkle_tree
        .generate_proof(leaf_index)
        .context("Failed to generate Merkle proof")?;

    let leaf_hash = merkle_proof.leaf;
    let root_hash = merkle_proof.root;

    println!("Computing deterministic nullifier...");
    let nullifier = compute_nullifier(&leaf_hash, &root_hash);
    println!("Nullifier: {}", hex::encode(nullifier));

    println!("Creating ZK-SNARK circuit...");

    // Convert actual values to field elements
    let leaf_base = bytes_to_field(&leaf_hash);
    let root_base = bytes_to_field(&root_hash);

    // Compute nullifier directly from field elements to ensure consistency
    let nullifier_base = compute_nullifier_from_fields(leaf_base, root_base);

    let circuit = SetMembershipCircuit {
        leaf: leaf_base,
        root: root_base,
        nullifier: nullifier_base,
        siblings: merkle_proof.siblings.iter().map(bytes_to_field).collect(),
        leaf_index,
    };

    // Public inputs for verification
    let public_inputs = vec![leaf_base, root_base, nullifier_base];

    println!("Generating ZK proof (this may take a while)...");
    let params: Params<_> = Params::<vesta::Affine>::new(CIRCUIT_K);

    let mut prover = SetMembershipProver::new();
    prover
        .generate_and_cache_keys(&params)
        .context("Failed to generate keys")?;

    let zkp_proof = prover
        .generate_proof(&params, circuit, public_inputs)
        .context("Failed to create proof")?;

    println!("ZK proof generated, size: {} bytes", zkp_proof.len());

    let verification_key = VerificationKey {
        leaf: hex::encode(leaf_hash),
        root: hex::encode(root_hash),
        nullifier: hex::encode(nullifier),
    };

    let merkle_siblings: Vec<String> = merkle_proof.siblings.iter().map(hex::encode).collect();

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("System time is before Unix epoch")?
        .as_secs();

    let output = ZKProofOutput {
        merkle_root: hex::encode(merkle_tree.root),
        nullifier: hex::encode(nullifier),
        zkp_proof,
        verification_key,
        leaf_index,
        timestamp,
        merkle_siblings,
    };

    println!("Writing proof to: {:?}", args.output);

    let parent_dir = args
        .output
        .parent()
        .ok_or_else(|| anyhow::anyhow!("Output file has no parent directory"))?;

    if !parent_dir.exists() {
        return Err(anyhow::anyhow!(
            "Output directory does not exist: {}",
            parent_dir.display()
        ));
    }

    let json_output =
        serde_json::to_string_pretty(&output).context("Failed to serialize proof to JSON")?;

    let metadata = fs::metadata(parent_dir).context("Failed to read directory metadata")?;
    let perms = metadata.permissions();

    if perms.readonly() {
        return Err(anyhow::anyhow!(
            "Output directory is not writable: {}",
            parent_dir.display()
        ));
    }

    if args.output.exists() {
        eprintln!(
            "Warning: Overwriting existing file: {}",
            args.output.display()
        );
    }

    fs::write(&args.output, json_output).context("Failed to write proof file")?;

    println!("Proof successfully generated and saved!");
    println!("Merkle Root: {}", output.merkle_root);
    println!("Nullifier: {}", output.nullifier);

    Ok(())
}
