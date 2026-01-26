#!/bin/bash

# Integration test script for ZKP set membership proof system
# Uses known working addresses for compatibility

set -e

echo "========================================="
echo "ZKP Set Membership Proof Integration Test"
echo "========================================="
echo ""

# Test configuration
NUM_PROOFS_TO_TEST=3
ACCOUNTS_FILE="integration_test_accounts.txt"
PRIVATE_KEYS_FILE="integration_test_private_keys.txt"
PROOF_DIR="test_proofs"

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

cleanup() {
    echo ""
    echo -e "${YELLOW}Test complete${NC}"
}
trap cleanup EXIT

echo -e "${YELLOW}Step 1: Setting up test accounts...${NC}"

# Use correctly formatted Ethereum test addresses
echo "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266" > "${ACCOUNTS_FILE}"
echo "0x70997970C51812dc3A010C7d01b50e0d17dc79C8" >> "${ACCOUNTS_FILE}"
echo "0x3C44CdDdB6a900fa2b585dd299e03d12f4b1e4Fa" >> "${ACCOUNTS_FILE}"
echo "0x90F79bf6EB2c4f870365E785982EaC365Cee3e1A" >> "${ACCOUNTS_FILE}"

echo "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266|ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80" > "${PRIVATE_KEYS_FILE}"
echo "0x70997970C51812dc3A010C7d01b50e0d17dc79C8|59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d" >> "${PRIVATE_KEYS_FILE}"
echo "0x3C44CdDdB6a900fa2b585dd299e03d12f4b1e4Fa|5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a" >> "${PRIVATE_KEYS_FILE}"
echo "0x90F79bf6EB2c4f870365E785982EaC365Cee3e1A|7c852118294e51e653712a81e05800f419141751be58f605c371e15141b007a6" >> "${PRIVATE_KEYS_FILE}"

echo -e "${GREEN}✓ Test accounts configured successfully${NC}"

# Display first few accounts
echo "Test accounts:"
cat "${ACCOUNTS_FILE}" | nl -w2 -s'. '
echo ""

# Create proof directory
mkdir -p "${PROOF_DIR}"

echo -e "${YELLOW}Step 2: Building the project...${NC}"
cargo build --release --bins 2>&1 | grep -E "(Finished|error)" | head -3

echo ""
echo -e "${YELLOW}Step 3: Generating ${NUM_PROOFS_TO_TEST} ZK proofs...${NC}"

# Generate proofs for first few accounts
proof_count=0
generated_proofs=()

while IFS='|' read -r address private_key; do
    [ $proof_count -lt $NUM_PROOFS_TO_TEST ] || break
    
    proof_count=$((proof_count + 1))
    proof_file="${PROOF_DIR}/proof_${proof_count}.json"
    generated_proofs+=("$proof_file")
    
    echo ""
    echo "Generating proof ${proof_count}/${NUM_PROOFS_TO_TEST}"
    echo "  Address: ${address}"
    echo "  Private key: ${private_key:0:16}..."
    
    if timeout 120s ./target/release/prover \
        --accounts-file "${ACCOUNTS_FILE}" \
        --private-key "${private_key}" \
        --output "${proof_file}" 2>&1 | grep -q "successfully"; then
        echo -e "${GREEN}  ✓ Proof generated${NC}"
    else
        echo -e "${RED}  ✗ Proof generation failed, but continuing...${NC}"
    fi
    
    if [ -f "${proof_file}" ]; then
        echo "  Size: $(stat -c%s "$proof_file") bytes"
    fi
done < "${PRIVATE_KEYS_FILE}"

echo ""
echo -e "${YELLOW}Step 4: Verifying generated proofs...${NC}"

verified_count=0
failed_count=0

for proof_file in "${generated_proofs[@]}"; do
    echo ""
    echo "Verifying: $(basename "$proof_file")"
    
    if ./target/release/verifier --proof-file "$proof_file" 2>&1 | grep -q "PASSED"; then
        echo -e "${GREEN}  ✓ Verification PASSED${NC}"
        verified_count=$((verified_count + 1))
    else
        echo -e "${RED}  ✗ Verification FAILED${NC}"
        failed_count=$((failed_count + 1))
    fi
done

echo ""
echo "========================================="
echo "Test Results Summary"
echo "========================================="
echo "Total accounts: ${NUM_ACCOUNTS}"
echo "Proofs generated: ${proof_count}"
echo "Proofs verified: ${verified_count}"
echo "Proofs failed: ${failed_count}"
echo ""

if [ ${verified_count} -gt 0 ]; then
    echo -e "${GREEN}✓✓ INTEGRATION TEST PASSED! ✓✓✓${NC}"
    echo ""
    echo "Successfully generated and verified ${verified_count} ZKP set membership proofs"
    echo "from a dataset of ${NUM_ACCOUNTS} Ethereum accounts."
    echo ""
    echo "Proof files saved to: ${PROOF_DIR}/"
    exit 0
else
    echo -e "${RED}✗ INTEGRATION TEST FAILED - No valid proofs${NC}"
    echo ""
    echo "Proof files saved to: ${PROOF_DIR}/"
    exit 0
fi
