use anyhow::{anyhow, Context};
use clap::Parser;
use ethers::signers::{LocalWallet, Signer};
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(short, long, default_value = "1000")]
    count: usize,

    #[arg(short, long, default_value = "test_accounts.txt")]
    output_file: PathBuf,
}

fn generate_random_ethereum_addresses(count: usize) -> Vec<String> {
    let mut addresses = Vec::with_capacity(count);
    for _ in 0..count {
        let wallet = LocalWallet::new(&mut rand::thread_rng());
        addresses.push(format!("0x{:x}", wallet.address()));
    }
    addresses
}

fn validate_addresses(addresses: &[String]) -> bool {
    addresses.iter().all(|addr| {
        addr.len() == 42
            && addr.starts_with("0x")
            && addr[2..].chars().all(|c| c.is_ascii_hexdigit())
    })
}

fn check_duplicates(addresses: &[String]) -> bool {
    let unique_count: std::collections::HashSet<_> = addresses.iter().collect();
    unique_count.len() == addresses.len()
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let count = args.count;
    let output_file = args.output_file;

    if count == 0 {
        return Err(anyhow!("Count must be greater than 0"));
    }
    if count > 1_000_000 {
        return Err(anyhow!("Count must be less than 1,000,000 (got {})", count));
    }

    println!("Generating {} random Ethereum addresses...", count);
    let addresses = generate_random_ethereum_addresses(count);

    if !validate_addresses(&addresses) {
        return Err(anyhow!("Generated invalid addresses"));
    }

    if !check_duplicates(&addresses) {
        return Err(anyhow!("Generated duplicate addresses"));
    }

    println!("Writing addresses to {}...", output_file.display());

    if output_file.exists() {
        eprintln!(
            "Warning: Overwriting existing file: {}",
            output_file.display()
        );
    }

    let mut file = File::create(&output_file)
        .with_context(|| format!("Failed to create output file: {}", output_file.display()))?;
    for address in &addresses {
        writeln!(file, "{}", address).context("Failed to write address to file")?;
    }

    println!("Successfully generated {} addresses", count);
    println!("First 5 addresses:");
    for (i, addr) in addresses.iter().take(5).enumerate() {
        println!("  {}: {}", i + 1, addr);
    }

    println!("\nValidation checks:");
    println!("  ✓ All addresses are valid");
    println!("  ✓ No duplicate addresses found");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_addresses_valid() {
        let addresses = vec![
            "0x742d35Cc6634C0532925a3b844Bc454e4438f44e".to_string(),
            "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed".to_string(),
        ];
        assert!(validate_addresses(&addresses));
    }

    #[test]
    fn test_validate_addresses_invalid_length() {
        let addresses = vec!["0x123456".to_string()];
        assert!(!validate_addresses(&addresses));
    }

    #[test]
    fn test_validate_addresses_invalid_prefix() {
        let addresses = vec!["1234567890123456789012345678901234567890".to_string()];
        assert!(!validate_addresses(&addresses));
    }

    #[test]
    fn test_validate_addresses_invalid_hex() {
        let addresses = vec!["0x123456789012345678901234567890123456789z".to_string()];
        assert!(!validate_addresses(&addresses));
    }

    #[test]
    fn test_check_duplicates_no_duplicates() {
        let addresses = vec![
            "0x742d35Cc6634C0532925a3b844Bc454e4438f44e".to_string(),
            "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed".to_string(),
        ];
        assert!(check_duplicates(&addresses));
    }

    #[test]
    fn test_check_duplicates_with_duplicates() {
        let addresses = vec![
            "0x742d35Cc6634C0532925a3b844Bc454e4438f44e".to_string(),
            "0x742d35Cc6634C0532925a3b844Bc454e4438f44e".to_string(),
        ];
        assert!(!check_duplicates(&addresses));
    }

    #[test]
    fn test_generate_random_ethereum_addresses() {
        let count = 10;
        let addresses = generate_random_ethereum_addresses(count);

        assert_eq!(addresses.len(), count);
        assert!(validate_addresses(&addresses));
        assert!(check_duplicates(&addresses));
    }

    #[test]
    fn test_generate_random_ethereum_addresses_unique() {
        let count = 100;
        let addresses = generate_random_ethereum_addresses(count);

        assert_eq!(addresses.len(), count);
        let unique_count: std::collections::HashSet<_> = addresses.iter().collect();
        assert_eq!(unique_count.len(), count);
    }
}
