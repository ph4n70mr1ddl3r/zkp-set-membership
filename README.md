# ZKP Set Membership Proof

A Rust implementation of zero-knowledge proof for Ethereum account set membership using Halo2 and Merkle trees. This system allows a prover to demonstrate knowledge of a private key corresponding to an Ethereum address in a predefined set without revealing which address.

## Features

- **Merkle Tree**: Efficient commitment to a set of Ethereum addresses
- **ZK-SNARK Proof**: Halo2-based zero-knowledge proof system using Pasta curves
- **Deterministic Nullifier**: Unique identifier derived from private key and Merkle root
- **Privacy-Preserving**: Prove membership without revealing the specific address
- **JSON Output**: Standardized proof format for verification

## Architecture

### Components

 1. **Merkle Tree Module** (`src/merkle.rs`)
    - Binary Merkle tree implementation
    - Proof generation and verification
    - Poseidon hash for efficient in-circuit verification

  2. **ZK-SNARK Circuit** (`src/circuit.rs`)
    - Set membership circuit using Halo2
    - Poseidon hash integration
    - Pallas/Vesta curve support

3. **Prover Binary** (`src/bin/prover.rs`)
   - CLI interface for proof generation
   - Takes accounts file and private key as input
   - Outputs JSON proof with Merkle root, nullifier, and ZK proof

4. **Verifier Binary** (`src/bin/verifier.rs`)
   - CLI interface for proof verification
   - Validates ZK proof against verification key
   - Reports verification status

## Installation

### Prerequisites

- Rust 1.70 or later
- Cargo package manager

### Build

```bash
# Clone or navigate to the project directory
cd zkpmerkle

# Build both binaries
cargo build --release
```

The binaries will be available at:
- `target/release/prover`
- `target/release/verifier`

## Usage

### 1. Create Accounts File

Create a text file with one Ethereum address per line:

```bash
cat > accounts.txt <<EOF
0x742d35Cc6634C0532925a3b844Bc454e4438f44e
0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed
0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359
0x8626f6940E2eb28930eFb4CeF49B2d1F2C9C1199
EOF
```

### 2. Generate Proof

```bash
# Using development build
cargo run --bin prover -- \
    --accounts-file accounts.txt \
    --private-key YOUR_PRIVATE_KEY_HERE \
    --output proof.json

# Using release build
./target/release/prover \
    --accounts-file accounts.txt \
    --private-key YOUR_PRIVATE_KEY_HERE \
    --output proof.json
```

**Arguments:**
- `-a, --accounts-file <FILE>`: Path to file containing Ethereum addresses (one per line)
- `-p, --private-key <KEY>`: Private key of the prover's Ethereum account (hex format)
- `-o, --output <FILE>`: Output JSON file path (default: `proof.json`)

**Note:** The private key must correspond to an address in the accounts file.

### 3. Verify Proof

```bash
# Using development build
cargo run --bin verifier -- --proof-file proof.json

# Using release build
./target/release/verifier --proof-file proof.json
```

**Arguments:**
- `-f, --proof-file <FILE>`: Path to the JSON proof file

## Output Format

The proof is saved as a JSON file with the following structure:

```json
{
  "merkle_root": "a1b2c3d4...",
  "nullifier": "e5f6g7h8...",
  "zkp_proof": [bytes],
  "verification_key": {
    "vk": [bytes]
  },
  "leaf_index": 2,
  "timestamp": 1706140800
}
```

### Fields

- **merkle_root**: Root hash of the Merkle tree containing all addresses
- **nullifier**: Deterministic identifier derived from private key and Merkle root (prevents proof reuse)
- **zkp_proof**: Serialized ZK-SNARK proof bytes
- **verification_key**: Verification key needed to verify the proof
- **leaf_index**: Index of the prover's address in the Merkle tree
- **timestamp**: Unix timestamp when proof was generated

## Security Considerations

### Private Key Security
- Never commit private keys to version control
- Use environment variables or secure key management systems
- The private key is only used locally for proof generation

### Nullifier Properties
- Deterministic: Same private key and Merkle root always produce the same nullifier
- Binding: Cannot generate a valid nullifier without the private key
- Prevents double-spending: Verifiers can track nullifiers to prevent reuse

### Proof Privacy
- The ZK proof does not reveal which address in the set corresponds to the prover
- Only proves membership, not identity
- Nullifier allows tracking without revealing identity

## Implementation Details

### Merkle Tree
- Binary tree structure
- Poseidon hash function for efficient in-circuit verification
- Support for arbitrary power-of-two leaf counts
- Efficient proof generation and verification

### ZK-SNARK Circuit
- Based on Halo2 proving system
- Uses Pallas curve for arithmetic
- Uses Vesta curve for polynomial commitments
- **Poseidon hash for efficient hashing in-circuit**
- **Merkle path verification enforces set membership**
- **Nullifier computed as H(leaf || root) using Poseidon hash**
- Circuit degree: k=12 (provides 4096 rows)
- Public input constraints enforce cryptographic consistency

### Nullifier Generation
```
nullifier = Poseidon_Hash(leaf || merkle_root)
```

This ensures:
- Deterministic output for same inputs
- Binding to both private key and specific set
- No collisions for different (private_key, merkle_root) pairs

## Example Workflow

```bash
# 1. Create accounts file
cat > accounts.txt <<EOF
0x742d35Cc6634C0532925a3b844Bc454e4438f44e
0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed
0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359
EOF

# 2. Generate proof (assuming you own the address at index 1)
./target/release/prover \
    --accounts-file accounts.txt \
    --private-key 0x4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318 \
    --output proof.json

# 3. Verify proof
./target/release/verifier --proof-file proof.json
```

## Development

### Running Tests

```bash
# Unit tests
cargo test

# Integration tests (recommended)
./integration_test.sh

# See TESTING.md for comprehensive testing guide
```

### Linting

```bash
cargo clippy
```

### Formatting

```bash
cargo fmt
```

## Dependencies

- `halo2-proofs`: Zero-knowledge proof system
- `halo2-gadgets`: Cryptographic gadgets for Halo2
- `pasta-curves`: Elliptic curves (Pallas and Vesta)
- `ethers`: Ethereum utilities and signing
- `serde`/`serde_json`: JSON serialization
- `clap`: Command-line argument parsing
- `hex`: Hex encoding/decoding
- `anyhow`/`thiserror`: Error handling

## Limitations

- Number of accounts must be a power of 2 for optimal Merkle tree construction
- Proof generation can be CPU-intensive for large sets
- Circuit parameters (k=12) limit proof complexity

## License

This project is provided as-is for educational and research purposes.

## References

- [Halo2 Documentation](https://zcash.github.io/halo2/)
- [Ethereum Addresses](https://docs.ethers.org/v6/api/address/)
- [Merkle Trees](https://en.wikipedia.org/wiki/Merkle_tree)
- [Zero-Knowledge Proofs](https://en.wikipedia.org/wiki/Zero-knowledge_proof)
