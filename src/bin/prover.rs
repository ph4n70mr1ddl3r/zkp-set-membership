use anyhow::{Context, Result};
use clap::Parser;
use ethers::signers::{LocalWallet, Signer};
use halo2_proofs::poly::commitment::Params;
use pasta_curves::vesta;
use sha3::{Digest, Sha3_256};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use zkp_set_membership::{
    circuit::{bytes_to_field, SetMembershipCircuit, SetMembershipProver},
    merkle::MerkleTree,
    types::ZKProofOutput,
    utils::validate_and_strip_hex,
    CIRCUIT_K,
};

const MAX_ACCOUNTS_FILE_SIZE: u64 = 10 * 1024 * 1024; // 10MB
const ADDRESS_HEX_LENGTH: usize = 40;

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

fn address_to_bytes(address: &str) -> Result<[u8; 32]> {
    let address_hex = validate_and_strip_hex(address, ADDRESS_HEX_LENGTH)?;

    let bytes = hex::decode(address_hex).context("Failed to decode address from hex")?;

    if bytes.len() != 20 {
        return Err(anyhow::anyhow!("Address bytes length mismatch"));
    }

    let mut full_bytes = [0u8; 32];
    full_bytes[12..32].copy_from_slice(&bytes);
    Ok(full_bytes)
}

fn validate_private_key(private_key: &str) -> Result<()> {
    validate_and_strip_hex(private_key, 64)?;
    Ok(())
}

fn compute_nullifier(address_bytes: &[u8; 32], merkle_root: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(address_bytes);
    hasher.update(merkle_root);
    hasher.finalize().into()
}

fn main() -> Result<()> {
    let args = Args::parse();

    println!("Loading accounts from: {:?}", args.accounts_file);

    let accounts_content =
        fs::read_to_string(&args.accounts_file).context("Failed to read accounts file")?;

    let content_size = accounts_content.len() as u64;
    if content_size > MAX_ACCOUNTS_FILE_SIZE {
        return Err(anyhow::anyhow!(
            "Accounts file too large: {} bytes (max {} bytes)",
            content_size,
            MAX_ACCOUNTS_FILE_SIZE
        ));
    }

    let addresses: Vec<String> = accounts_content
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| line.trim().to_string())
        .collect();

    if addresses.is_empty() {
        return Err(anyhow::anyhow!(
            "No valid addresses found in accounts file '{}'",
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

    let prover_normalized =
        validate_and_strip_hex(&format!("0x{}", prover_address_str), 40)?.to_lowercase();

    let mut leaf_hashes = Vec::new();
    let mut leaf_index = None;

    for (i, address) in addresses.iter().enumerate() {
        let address_bytes = address_to_bytes(address)?;
        leaf_hashes.push(address_bytes);

        let addr_normalized = validate_and_strip_hex(address, 40)?.to_lowercase();
        if addr_normalized == prover_normalized {
            leaf_index = Some(i);
            println!("Found prover address at index {}", i);
        }
    }

    let leaf_index = leaf_index.context(format!(
        "Prover address '{}' not found in accounts file '{}'. Make sure your private key corresponds to an address in the set.",
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
    let nullifier_base = bytes_to_field(&nullifier);

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

    let zkp_proof = SetMembershipProver::generate_proof(&params, circuit, public_inputs)
        .context("Failed to create proof")?;

    println!("ZK proof generated, size: {} bytes", zkp_proof.len());

    let mut vk_map = HashMap::new();
    vk_map.insert("leaf".to_string(), hex::encode(leaf_hash));
    vk_map.insert("root".to_string(), hex::encode(root_hash));
    vk_map.insert("nullifier".to_string(), hex::encode(nullifier));

    let merkle_siblings: Vec<String> = merkle_proof.siblings.iter().map(hex::encode).collect();

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("System time is before Unix epoch")?
        .as_secs();

    let output = ZKProofOutput {
        merkle_root: hex::encode(merkle_tree.root),
        nullifier: hex::encode(nullifier),
        zkp_proof,
        verification_key: vk_map,
        leaf_index,
        timestamp,
        merkle_siblings,
    };

    println!("Writing proof to: {:?}", args.output);
    let json_output =
        serde_json::to_string_pretty(&output).context("Failed to serialize proof to JSON")?;

    fs::write(&args.output, json_output).context("Failed to write proof file")?;

    println!("Proof successfully generated and saved!");
    println!("Merkle Root: {}", output.merkle_root);
    println!("Nullifier: {}", output.nullifier);

    Ok(())
}
