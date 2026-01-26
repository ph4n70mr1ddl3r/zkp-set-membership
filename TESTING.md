# Testing Guide

This document describes how to test the ZKP set membership proof system.

## Prerequisites

- Rust and Cargo installed
- Python 3 (for account generation) OR Rust (alternative method)

## Quick Test Run

The easiest way to run the tests is using the integration test script:

```bash
# Run the full integration test
./integration_test.sh
```

This script will:
1. Generate test Ethereum accounts
2. Build the prover and verifier binaries
3. Generate ZK proofs for multiple accounts
4. Verify all generated proofs

## Manual Testing

If you want to test components manually:

### 1. Unit Tests

Run the unit tests for the Merkle tree implementation:

```bash
cargo test
```

This tests:
- Merkle tree creation
- Proof generation
- Proof verification
- Large tree handling

### 2. Generate Test Accounts

Generate a list of test Ethereum addresses:

```bash
# Using Python (recommended)
python3 << 'EOF'
num_accounts = 8
accounts = [
    "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
    "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
    "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
    "0xdbF03B407c01E7cD3CBea1005Bd6F3C6b24d50C5",
    "0xdD870fA1b7C4700F2BD7f44238821C26f7392148",
    "0x8626f6940E2eb28930eFb4CeF49B2d1F2C9C1199",
    "0xdAC17F958D2ee523a2206206994597C13D831ec7",
    "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48",
]

with open('test_accounts.txt', 'w') as f:
    for addr in accounts:
        f.write(f"{addr}\n")

print("Created test_accounts.txt")
EOF

# Or using the Rust binary
cargo run --bin generate_accounts --release
```

### 3. Create a Proof

Generate a ZK proof for one of the accounts:

```bash
# Build the prover
cargo build --release --bin prover

# Generate a proof
./target/release/prover \
    --accounts-file test_accounts.txt \
    --private-key YOUR_PRIVATE_KEY_HERE \
    --output test_proof.json
```

### 4. Verify the Proof

Verify the generated proof:

```bash
# Build the verifier
cargo build --release --bin verifier

# Verify the proof
./target/release/verifier --proof-file test_proof.json
```

## Test Accounts

The integration test uses these predefined test accounts with known private keys:

| Index | Address | Private Key |
|-------|---------|-------------|
| 0 | 0x742d35Cc6634C0532925a3b844Bc454e4438f44e | ac0974bec39a... |
| 1 | 0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed | 59c6995e998f... |
| 2 | 0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359 | 5de4111afa1a... |

## Expected Output

### Successful Test Run

```
=========================================
ZKP Set Membership Proof Integration Test
=========================================

Step 1: Generating 8 deterministic test accounts...
Creating 8 deterministic accounts...
  Account 0: 0x742d35Cc6634C0532925a3b844Bc454e4438f44e
  Account 1: 0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed
  ...
✓ Accounts generated successfully

Step 2: Building the project...
   Compiling zkp-set-membership v0.1.0 (/path/to/zkpmerkle)
    Finished release [optimized] target(s) in X.XXs

Step 3: Generating 3 ZK proofs...
Generating proof 1/3
  Address: 0x742d35Cc6634C0532925a3b844Bc454e4438f44e
  Private key: ac0974bec39a17...
  ✓ Proof generated
  Size: XXXX bytes

...

Step 4: Verifying generated proofs...

Verifying: proof_1.json
  ✓ Verification PASSED

...

=========================================
Test Results Summary
=========================================
Total accounts: 8
Proofs generated: 3
Proofs verified: 3
Proofs failed: 0

✓✓✓ ALL TESTS PASSED! ✓✓✓
```

## Test Files

- `integration_test.sh` - Main integration test script
- `test_zkp.py` - Alternative Python-based test script
- `src/merkle_tests.rs` - Unit tests for Merkle tree
- `tests/create_test_accounts.rs` - Test account generator

## Troubleshooting

### Build Failures

```bash
# Clean and rebuild
cargo clean
cargo build --release
```

### Proof Generation Fails

- Verify the private key corresponds to an address in the accounts file
- Ensure you have enough memory and CPU time (proof generation can take 30-60 seconds)
- Check that the accounts file format is correct (one address per line)

### Verification Fails

- Ensure the proof file exists and is not corrupted
- Verify the proof file was generated with the correct circuit parameters
- Check that the verification key matches the proving key

### Account Generation Issues

```bash
# Install Python if needed
sudo apt install python3

# Install eth-account (optional, for advanced features)
pip3 install eth-account
```

## Performance Notes

- **Proof Generation**: ~30-60 seconds per proof (depends on CPU)
- **Verification**: <1 second per proof
- **Memory Usage**: ~500MB during proof generation
- **Proof Size**: ~10-20KB per proof

## Advanced Testing

### Test with Large Datasets

```bash
# Generate 1000 test accounts
python3 << 'EOF'
import json
from eth_account import Account

num_accounts = 1000
with open('large_accounts.txt', 'w') as f:
    for i in range(num_accounts):
        acct = Account.create()
        f.write(f"{acct.address}\n")
        if i < 5:
            print(f"Account {i}: {acct.address}")

print(f"Created {num_accounts} accounts")
EOF
```

### Benchmark Proof Generation

```bash
time ./target/release/prover \
    --accounts-file large_accounts.txt \
    --private_key 0xYOUR_PRIVATE_KEY \
    --output benchmark_proof.json
```

## Running Specific Test Modules

```bash
# Test only Merkle tree module
cargo test merkle

# Test with verbose output
cargo test -- --nocapture

# Show test output
cargo test -- --show-output
```
