use ethers::signers::{LocalWallet, Signer};
use std::fs::File;
use std::io::Write;

fn generate_random_ethereum_addresses(count: usize) -> Vec<String> {
    let mut addresses = Vec::new();
    for _ in 0..count {
        let wallet = LocalWallet::new(&mut rand::thread_rng());
        addresses.push(format!("{:?}", wallet.address()));
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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let count = 1000;
    let output_file = "test_accounts.txt";

    println!("Generating {} random Ethereum addresses...", count);
    let addresses = generate_random_ethereum_addresses(count);

    if !validate_addresses(&addresses) {
        return Err("Generated invalid addresses".into());
    }

    if !check_duplicates(&addresses) {
        return Err("Generated duplicate addresses".into());
    }

    println!("Writing addresses to {}...", output_file);
    let mut file = File::create(output_file)?;
    for address in &addresses {
        writeln!(file, "{}", address)?;
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
