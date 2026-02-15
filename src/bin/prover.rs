use anyhow::{Context, Result};
use clap::Parser;
use ethers::signers::{LocalWallet, Signer};
use halo2_proofs::poly::commitment::Params;
use log::{debug, info};
use pasta_curves::vesta;
use rpassword::read_password;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use zkp_set_membership::{
    circuit::{SetMembershipCircuit, SetMembershipProver},
    ethereum::{
        address_to_bytes_normalized, normalize_address, normalize_addresses_batch,
        validate_private_key,
    },
    merkle::MerkleTree,
    types::{compute_nullifier_from_fields, PublicInputs, ZKProofOutput},
    utils::{bytes_to_field, field_to_bytes},
    CIRCUIT_K,
};

const DEFAULT_MAX_ACCOUNTS_FILE_SIZE: u64 = 1024 * 1024;

fn get_max_accounts_file_size() -> u64 {
    std::env::var("ZKP_MAX_ACCOUNTS_FILE_SIZE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_MAX_ACCOUNTS_FILE_SIZE)
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    accounts_file: PathBuf,
    #[arg(short, long, default_value = "proof.json")]
    output: PathBuf,
}

fn read_private_key() -> Result<String> {
    if let Ok(key) = std::env::var("ZKP_PRIVATE_KEY") {
        info!("Using private key from ZKP_PRIVATE_KEY environment variable");
        info!("Warning: Private key from environment variable may be stored in shell history");
        if key.trim().is_empty() {
            return Err(anyhow::anyhow!(
                "ZKP_PRIVATE_KEY environment variable is set but empty. Please provide a valid private key."
            ));
        }
        Ok(key)
    } else {
        print!("Enter private key: ");
        std::io::stdout()
            .flush()
            .context("Failed to flush stdout")?;
        let key = read_password().context("Failed to read private key from stdin")?;
        if key.trim().is_empty() {
            return Err(anyhow::anyhow!(
                "Private key cannot be empty. Please provide a valid private key."
            ));
        }
        info!("Using private key from secure stdin");
        Ok(key)
    }
}

fn load_and_validate_addresses(path: &PathBuf) -> Result<Vec<String>> {
    info!("Loading accounts from: {}", path.display());
    debug!("Starting accounts file read operation");
    println!("Loading accounts from: {}", path.display());

    let accounts_content = fs::read_to_string(path).context("Failed to read accounts file")?;

    let content_size = accounts_content.len() as u64;
    debug!("Accounts file size: {content_size} bytes");
    let max_accounts_size = get_max_accounts_file_size();
    if content_size > max_accounts_size {
        return Err(anyhow::anyhow!(
            "Accounts file too large: {} bytes (max {} bytes). Set ZKP_MAX_ACCOUNTS_FILE_SIZE to override. File: {}",
            content_size, max_accounts_size, path.display()
        ));
    }

    let addresses: Vec<String> = accounts_content
        .lines()
        .filter_map(|line| {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.to_string())
            }
        })
        .collect();

    if addresses.is_empty() {
        return Err(anyhow::anyhow!(
            "No valid addresses found in accounts file '{}'. Please ensure the file contains Ethereum addresses in hex format (one per line, e.g., 0x742d35Cc6634C0532925a3b844Bc454e4438f44e)",
            path.display()
        ));
    }

    info!(
        "Loaded {} addresses from {}",
        addresses.len(),
        path.display()
    );
    println!(
        "Loaded {} addresses from {}",
        addresses.len(),
        path.display()
    );
    Ok(addresses)
}

fn process_addresses(addresses: &[String], prover_address: &str) -> Result<(Vec<[u8; 32]>, usize)> {
    let normalized_addresses =
        normalize_addresses_batch(addresses).context("Failed to normalize addresses")?;

    if normalized_addresses.len() > (1 << CIRCUIT_K) {
        return Err(anyhow::anyhow!(
            "Number of addresses {} exceeds circuit capacity {} (1 << CIRCUIT_K={}). Please reduce the number of addresses or increase CIRCUIT_K",
            normalized_addresses.len(),
            1 << CIRCUIT_K,
            CIRCUIT_K
        ));
    }

    let prover_normalized = normalize_address(prover_address)?;

    let mut leaf_hashes = Vec::with_capacity(addresses.len());
    let mut leaf_index = None;
    let mut prover_count = 0;

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
            prover_count += 1;
            leaf_index = Some(i);
            info!("Found prover address at index {i}");
            println!("Found prover address at index {i}");
        }
    }

    if prover_count == 0 {
        return Err(anyhow::anyhow!(
            "Prover address '{prover_address}' not found in accounts file. Ensure your private key corresponds to an address in the set"
        ));
    }
    if prover_count > 1 {
        return Err(anyhow::anyhow!(
            "Duplicate prover address found {prover_count} times in accounts file"
        ));
    }

    Ok((
        leaf_hashes,
        leaf_index.expect("validated above: prover_count > 0 ensures Some"),
    ))
}

fn generate_proof_output(leaf_hashes: &[[u8; 32]], leaf_index: usize) -> Result<ZKProofOutput> {
    info!("Building Merkle tree with {} leaves", leaf_hashes.len());
    println!("Building Merkle tree...");
    let merkle_tree =
        MerkleTree::new(leaf_hashes.to_owned()).context("Failed to create Merkle tree")?;
    println!("Merkle root: {}", hex::encode(merkle_tree.root));
    debug!("Merkle root: {}", hex::encode(merkle_tree.root));

    info!("Generating Merkle proof for leaf index {leaf_index}");
    println!("Generating Merkle proof...");
    let merkle_proof = merkle_tree
        .generate_proof(leaf_index)
        .context("Failed to generate Merkle proof")?;

    let leaf_hash = merkle_proof.leaf;
    let root_hash = merkle_proof.root;

    info!("Creating ZK-SNARK circuit");
    println!("Creating ZK-SNARK circuit...");

    let leaf_base = bytes_to_field(&leaf_hash);
    let root_base = bytes_to_field(&root_hash);
    let nullifier_base = compute_nullifier_from_fields(leaf_base, root_base);
    let nullifier = field_to_bytes(nullifier_base);

    info!("Computing deterministic nullifier");
    println!("Computing deterministic nullifier...");
    println!("Nullifier: {}", hex::encode(nullifier));
    debug!("Nullifier: {}", hex::encode(nullifier));

    let circuit = SetMembershipCircuit {
        leaf: leaf_base,
        root: root_base,
        nullifier: nullifier_base,
        siblings: merkle_proof.siblings.iter().map(bytes_to_field).collect(),
        leaf_index,
    };

    let public_inputs = vec![leaf_base, root_base, nullifier_base];

    info!("Generating ZK proof (this may take a while)...");
    println!("Generating ZK proof (this may take a while)...");
    let params: Params<_> = Params::<vesta::Affine>::new(CIRCUIT_K);

    info!("Generating/caching ZK-SNARK keys");
    println!("Generating ZK-SNARK keys...");
    let (_, pk) =
        SetMembershipProver::generate_and_cache_keys(&params).context("Failed to generate keys")?;

    let zkp_proof = SetMembershipProver::generate_proof(&pk, &params, circuit, &public_inputs)
        .context("Failed to create proof")?;

    info!(
        "ZK proof generated successfully, size: {} bytes",
        zkp_proof.len()
    );
    println!("ZK proof generated, size: {} bytes", zkp_proof.len());

    let public_inputs = PublicInputs {
        leaf: hex::encode(leaf_hash),
        root: hex::encode(root_hash),
        nullifier: hex::encode(nullifier),
    };

    let merkle_siblings: Vec<String> = merkle_proof.siblings.iter().map(hex::encode).collect();

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("System time is before Unix epoch")?
        .as_secs();

    debug!("Proof timestamp: {timestamp}");

    Ok(ZKProofOutput {
        merkle_root: hex::encode(merkle_tree.root),
        zkp_proof,
        public_inputs,
        leaf_index,
        timestamp,
        merkle_siblings,
    })
}

fn write_proof(output_path: &PathBuf, output: &ZKProofOutput) -> Result<()> {
    info!("Writing proof to: {}", output_path.display());
    println!("Writing proof to: {}", output_path.display());

    let parent_dir = output_path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("Output file has no parent directory"))?;

    if !parent_dir.exists() {
        return Err(anyhow::anyhow!(
            "Output directory does not exist: {}",
            parent_dir.display()
        ));
    }

    let json_output =
        serde_json::to_string_pretty(output).context("Failed to serialize proof to JSON")?;

    if output_path.exists() {
        eprintln!(
            "Warning: Overwriting existing file: {}",
            output_path.display()
        );
    }

    fs::write(output_path, json_output).context("Failed to write proof file")?;

    println!("Proof successfully generated and saved!");
    println!("Merkle Root: {}", output.merkle_root);
    println!("Nullifier: {}", output.public_inputs.nullifier);
    Ok(())
}

fn main() -> Result<()> {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let args = Args::parse();
    let private_key = read_private_key()?;
    validate_private_key(&private_key)?;

    info!("Parsing private key...");
    let wallet: LocalWallet = private_key
        .parse()
        .with_context(|| "Failed to parse private key: invalid format".to_string())?;
    let prover_address = format!("{:x}", wallet.address());
    info!("Prover address: 0x{prover_address}");
    println!("Prover address: 0x{prover_address}");

    let addresses = load_and_validate_addresses(&args.accounts_file)?;
    let (leaf_hashes, leaf_index) = process_addresses(&addresses, &prover_address)?;
    let output = generate_proof_output(&leaf_hashes, leaf_index)?;
    write_proof(&args.output, &output)?;

    Ok(())
}
