use ethers::signers::{LocalWallet, Signer};
use sha3::{Digest, Sha3_256};
use std::fs::File;
use std::io::Write;

const NUM_ACCOUNTS: usize = 1000;

fn generate_deterministic_accounts(
    output_file: &str,
) -> Result<Vec<(String, String)>, Box<dyn std::error::Error>> {
    println!(
        "Generating {} deterministic Ethereum accounts...",
        NUM_ACCOUNTS
    );

    let mut accounts = Vec::new();

    let mut addr_file = File::create(output_file)?;
    let mut pk_file = File::create("test_private_keys.txt")?;

    for i in 0..NUM_ACCOUNTS {
        // Create deterministic wallet using a seed approach
        let seed = format!("test_seed_{:020}", i);
        let mut hasher = Sha3_256::new();
        hasher.update(seed.as_bytes());
        let seed_hash = hasher.finalize();

        // Try to create wallet from seed hash
        // If it fails, create a random one and try again with a different seed
        let wallet = match LocalWallet::from_bytes(&seed_hash) {
            Ok(w) => w,
            Err(_) => LocalWallet::new(&mut rand::thread_rng()),
        };

        let address = format!("{:?}", wallet.address());
        let private_key = hex::encode(wallet.signer().to_bytes());

        writeln!(addr_file, "{}", address)?;
        writeln!(pk_file, "{}|{}", address, private_key)?;

        accounts.push((address.clone(), private_key));

        if i < 5 {
            println!("  Account {}: {}", i, address);
        }
    }

    println!("Created {} accounts", NUM_ACCOUNTS);
    Ok(accounts)
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("ZKP Set Membership Proof Test Generator");
    println!("========================================\n");

    let accounts_file = "test_accounts_1000.txt";

    // Generate accounts
    let accounts = generate_deterministic_accounts(accounts_file)?;

    println!("\nFirst 10 accounts:");
    for (i, (addr, _pk)) in accounts.iter().take(10).enumerate() {
        println!("  {}: {}", i, addr);
    }

    println!("\nAccounts saved to: {}", accounts_file);
    println!("Private keys saved to: test_private_keys.txt");

    println!("\nNext steps:");
    println!("1. Build project: cargo build --release");
    println!("2. Run test script: ./run_tests.sh");
    println!("   or manually test with:");
    println!(
        "   ZKP_PRIVATE_KEY=<KEY> ./target/release/prover --accounts-file {} --output proof.json",
        accounts_file
    );
    println!("   ./target/release/verifier --proof-file proof.json");

    Ok(())
}
