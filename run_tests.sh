#!/bin/bash

# Test script for ZKP set membership proof system
# This script generates dummy accounts, creates proofs for multiple accounts,
# and verifies each proof

set -e

echo "========================================="
echo "ZKP Set Membership Proof Test Suite"
echo "========================================="
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test configuration
ACCOUNTS_FILE="test_accounts_1000.txt"
NUM_ACCOUNTS=1000
NUM_PROOFS_TO_TEST=5
PROOF_DIR="test_proofs"

echo -e "${YELLOW}Step 1: Generating ${NUM_ACCOUNTS} dummy Ethereum accounts...${NC}"
cargo run --bin generate_accounts --release 2>&1 | grep -E "Generating|Writing|Successfully|addresses"

if [ ! -f "${ACCOUNTS_FILE}" ]; then
    echo -e "${RED}Error: Accounts file not generated${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Accounts generated successfully${NC}"
echo ""

# Get private keys from generated accounts
echo -e "${YELLOW}Step 2: Extracting private keys from generated accounts...${NC}"

# We need to generate wallets to get private keys - let's create a test helper
cat > test_utils.rs << 'EOF'
use ethers::signers::{LocalWallet, Signer};
use std::fs::File;
use std::io::{BufRead, BufReader};
use rand::Rng;
use std::collections::HashMap;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let accounts_file = "test_accounts_1000.txt";
    let mut rng = rand::thread_rng();
    
    let file = File::open(accounts_file)?;
    let reader = BufReader::new(file);
    let addresses: Vec<String> = reader.lines()
        .filter_map(|line| line.ok())
        .collect();
    
    println!("Loaded {} addresses", addresses.len());
    
    // Generate matching wallets and store private keys
    let mut wallet_map: HashMap<String, String> = HashMap::new();
    let mut attempts = 0;
    
    while wallet_map.len() < addresses.len() && attempts < addresses.len() * 10 {
        let wallet = LocalWallet::new(&mut rng);
        let addr = format!("{:?}", wallet.address());
        
        if addresses.contains(&addr) && !wallet_map.contains_key(&addr) {
            let private_key = hex::encode(wallet.signer().to_bytes());
            wallet_map.insert(addr, private_key);
            println!("Found match: {} -> {}", addr, private_key);
        }
        attempts += 1;
    }
    
    println!("Matched {} addresses", wallet_map.len());
    
    // Save first few private keys for testing
    let mut private_keys_file = File::create("test_private_keys.txt")?;
    for (addr, pk) in wallet_map.iter().take(5) {
        writeln!(private_keys_file, "{}|{}", addr, pk)?;
    }
    
    Ok(())
}
EOF

echo -e "${YELLOW}Step 3: Creating a simpler test approach...${NC}"
# Instead of trying to match random wallets, let's create deterministic wallets
cat > create_test_data.rs << 'EOF'
use ethers::signers::{LocalWallet, Signer};
use std::fs::File;
use std::io::Write;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let num_accounts = 1000;
    
    let mut addresses_file = File::create("test_accounts_1000.txt")?;
    let mut private_keys_file = File::create("test_private_keys.txt")?;
    
    println!("Creating {} deterministic accounts...", num_accounts);
    
    for i in 0..num_accounts {
        // Create deterministic wallet from seed
        let seed = format!("test_seed_{}", i);
        let wallet = LocalWallet::from_bytes(&sha3::Sha3_256::digest(seed.as_bytes()))?;
        let address = format!("{:?}", wallet.address());
        let private_key = hex::encode(wallet.signer().to_bytes());
        
        writeln!(addresses_file, "{}", address)?;
        writeln!(private_keys_file, "{}|{}", address, private_key)?;
        
        if i < 5 {
            println!("Account {}: {}", i, address);
        }
    }
    
    println!("Created {} accounts", num_accounts);
    
    Ok(())
}
EOF

# Compile and run the deterministic account generator
rustc --edition 2021 create_test_data.rs -L target/release/deps --extern ethers=target/release/deps/libethers-*.rlib --extern sha3=target/release/deps/libsha3-*.rlib -o create_test_data 2>/dev/null || {
    echo -e "${YELLOW}Creating accounts via alternative method...${NC}"
    
    # Simpler approach: just create accounts and track them
    cat > gen_accounts.py << 'PYEOF'
import json
from eth_account import Account

num_accounts = 1000

with open('test_accounts_1000.txt', 'w') as addr_file, \
     open('test_private_keys.txt', 'w') as pk_file:
    
    print(f"Creating {num_accounts} accounts...")
    
    for i in range(num_accounts):
        acct = Account.create()
        address = acct.address
        private_key = acct.key.hex()
        
        addr_file.write(f"{address}\n")
        pk_file.write(f"{address}|{private_key}\n")
        
        if i < 5:
            print(f"Account {i}: {address}")
    
    print(f"Created {num_accounts} accounts")
PYEOF

    python3 gen_accounts.py
}

if [ -f "${ACCOUNTS_FILE}" ]; then
    num_lines=$(wc -l < "${ACCOUNTS_FILE}")
    echo -e "${GREEN}✓ Created ${num_lines} accounts${NC}"
else
    echo -e "${RED}Error: Accounts file not found${NC}"
    exit 1
fi

echo ""

# Create proof directory
mkdir -p "${PROOF_DIR}"

echo -e "${YELLOW}Step 4: Generating proofs for ${NUM_PROOFS_TO_TEST} random accounts...${NC}"

# Read private keys and generate proofs
head -n ${NUM_PROOFS_TO_TEST} test_private_keys.txt | while IFS='|' read -r address private_key; do
    echo ""
    echo -e "${YELLOW}Generating proof for address: ${address}${NC}"
    
    proof_file="${PROOF_DIR}/proof_$(echo ${address} | cut -c1-8).json"
    
    # Generate proof
    cargo run --bin prover --release \
        --accounts-file "${ACCOUNTS_FILE}" \
        --private-key "0x${private_key}" \
        --output "${proof_file}" 2>&1 | tail -5
    
    if [ -f "${proof_file}" ]; then
        echo -e "${GREEN}✓ Proof saved to ${proof_file}${NC}"
    else
        echo -e "${RED}✗ Failed to create proof${NC}"
        exit 1
    fi
done

echo ""

echo -e "${YELLOW}Step 5: Verifying all generated proofs...${NC}"
proof_count=0
verified_count=0

for proof_file in ${PROOF_DIR}/proof_*.json; do
    if [ -f "${proof_file}" ]; then
        proof_count=$((proof_count + 1))
        echo ""
        echo "Verifying: ${proof_file}"
        
        if cargo run --bin verifier --release -- --proof-file "${proof_file}" 2>&1 | grep -q "PASSED"; then
            echo -e "${GREEN}✓ Proof verification PASSED${NC}"
            verified_count=$((verified_count + 1))
        else
            echo -e "${RED}✗ Proof verification FAILED${NC}"
        fi
    fi
done

echo ""
echo "========================================="
echo "Test Results Summary"
echo "========================================="
echo "Total proofs generated: ${proof_count}"
echo "Proofs verified: ${verified_count}"

if [ ${proof_count} -eq ${NUM_PROOFS_TO_TEST} ] && [ ${verified_count} -eq ${proof_count} ]; then
    echo -e "${GREEN}✓ ALL TESTS PASSED!${NC}"
    echo ""
    echo "Successfully generated and verified ${NUM_PROOFS_TO_TEST} ZKP set membership proofs"
    echo "from a dataset of ${NUM_ACCOUNTS} Ethereum accounts."
    exit 0
else
    echo -e "${RED}✗ SOME TESTS FAILED${NC}"
    exit 1
fi
