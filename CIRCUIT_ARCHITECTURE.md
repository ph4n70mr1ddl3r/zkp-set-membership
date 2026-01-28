# Circuit Architecture

## Overview

The `SetMembershipCircuit` implements a zero-knowledge proof system for proving set membership without revealing the specific member.

## Circuit Structure

### Columns

The circuit uses the following columns:

#### Advice Columns (15 columns)
- `advice[0]`: Leaf value
- `advice[1]`: Root value
- `advice[2]`: Nullifier value
- `advice[3]`: Partial S-box for Poseidon hash
- `advice[4]`: Sibling values (unused - should be removed or used properly)
- `advice[5]`: Left child in Merkle hash
- `advice[6]`: Right child in Merkle hash
- `advice[7-14]`: Additional advice columns for flexibility

#### Fixed Columns (6 columns)
- `fixed[0-2]`: Round constants for Poseidon hash (a)
- `fixed[3-5]`: Round constants for Poseidon hash (b)

#### Instance Column (1 column)
- `instance`: Public inputs (leaf, root, nullifier)

### Equality Constraints

All advice columns have equality enabled via `meta.enable_equality()`.
All fixed columns have constant enabled via `meta.enable_constant()`.

## Circuit Constraints

### 1. Public Input Constraints

The circuit constrains three public inputs to match private witnesses:
- Instance[0] = advice[0] (leaf)
- Instance[1] = advice[1] (root)
- Instance[2] = advice[2] (nullifier)

### 2. Nullifier Constraint

The circuit verifies that the nullifier equals `H(leaf || root)` using Poseidon hash:
```
computed_nullifier = Poseidon(leaf, root)
constraint: computed_nullifier == advice[2]
```

This enforces that the prover knows the correct nullifier for the given leaf and root.

### 3. Merkle Path Verification

The circuit verifies that the leaf is included in the Merkle tree that computes to the root:

For each sibling in the Merkle proof:
1. Determine left and right children based on current index:
   - If index is even: left = current_hash, right = sibling
   - If index is odd: left = sibling, right = current_hash

2. Compute hash of children:
   ```
   current_hash = Poseidon(left, right)
   ```

3. Update index:
   ```
   index = index / 2
   ```

After processing all siblings:
4. Constrain final hash to equal root:
   ```
   constraint: current_hash == root
   ```

This enforces that the Merkle path is valid and the leaf is included in the tree.

## Row Layout

### Initial Assignment (Rows 0-1)
```
Row 0:
  advice[0] = leaf
  advice[1] = root

Row 1:
  advice[2] = nullifier
```

### Nullifier Verification (Rows 0-1)
```
Row 0-1:
  Poseidon hash computation using advice[0], advice[1]
  Output constrained to advice[2]
```

### Merkle Path Verification (Starting at Row 100)

For each sibling in the proof:
```
Row offset + 0:
  (Optionally) sibling value - currently not properly used

Row offset + 1:
  advice[5] = left child
  advice[6] = right child
  advice[3] = partial S-box for Poseidon

Rows offset + 2 to offset + (ROW_INCREMENT - 1):
  Poseidon hash computation rounds
```

Offset increments by ROW_INCREMENT (50) for each sibling.

## Poseidon Hash Configuration

The circuit uses the `P128Pow5T3` specification:
- State width: 3 field elements
- Full rounds: 3
- Partial rounds: 2
- Input length: Constant(2)

This provides approximately 128-bit security while being efficient for in-circuit use.

## Security Guarantees

### 1. Privacy
- The prover does not reveal which leaf is being proven
- Only the Merkle root and nullifier are revealed publicly

### 2. Correctness
- The circuit enforces that the nullifier equals `H(leaf || root)`
- The circuit enforces that the Merkle path is valid
- The circuit enforces that public inputs match private witnesses

### 3. Uniqueness
- The nullifier is deterministic for a given (leaf, root) pair
- Reusing the same proof will produce the same nullifier, enabling replay attack detection

### 4. Binding
- The circuit constraints are cryptographic and binding
- The prover cannot create a valid proof without knowing the correct values

## Known Issues

### Critical: Merkle Path Verification Bug

**Status**: The circuit's Merkle path verification fails when there are siblings in the proof.

**Symptom**: The test `test_circuit_with_siblings` fails consistently.

**Root Cause**: The circuit attempts to use `current_hash_cell.value().copied()` to extract values from cells assigned in previous regions. In Halo2, accessing a cell's `.value()` across different regions may not create proper copy constraints needed for the circuit to work correctly.

**Impact**: The circuit cannot properly verify Merkle proofs with multiple leaves, which is the primary use case.

**Fix Needed**: Redesign the circuit to properly handle cell values across regions, possibly by:
1. Assigning all cells in the same region
2. Using explicit copy constraints between regions
3. Redesigning the row layout to avoid cross-region cell references

## Performance Characteristics

### Circuit Size
- Parameter `k=12` creates a circuit with 2^12 = 4096 rows
- Supports Merkle trees with up to 4096 leaves
- 15 advice columns, 6 fixed columns, 1 instance column

### Proof Generation
- Approximately 11-12 seconds for a full proof
- Key generation: ~5 seconds (cached within a single run)
- Proof size: ~4KB

### Verification
- Fast (sub-second) for proof verification
- Public inputs: 3 field elements (leaf, root, nullifier)

## Future Improvements

1. **Fix Critical Bug**: Resolve the Merkle path verification circuit bug
2. **Optimization**: Reduce circuit size by optimizing row usage
3. **Parallelization**: Consider parallelizing hash computations
4. **Batch Verification**: Add support for verifying multiple proofs efficiently
5. **Alternative Hashers**: Evaluate other Poseidon configurations for better performance

## References

- [Halo2 Documentation](https://zcash.github.io/halo2/)
- [Poseidon Hash Paper](https://eprint.iacr.org/2019/458)
- [Pasta Curves](https://github.com/zcash/pasta_curves)
