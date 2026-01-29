# Circuit Visualization and Architecture

## Overview

This document provides visual representations of the ZKP Set Membership circuit architecture to aid in understanding, auditing, and maintaining the codebase.

## Circuit Structure

### Column Allocation

```
┌─────────────────────────────────────────────────────────────┐
│                    ADVICE COLUMNS (15)                      │
├─────┬─────┬─────┬─────┬─────┬─────┬─────┬─────┬─────┬───────┤
│  0  │  1  │  2  │  3  │  4  │  5  │  6  │ 7-14│ ... │  14   │
├─────┼─────┼─────┼─────┼─────┼─────┼─────┼─────┼─────┼───────┤
│leaf │root │null │pbox │sib0 │left0│right│ ... │ ... │  ...  │
├─────┼─────┼─────┼─────┼─────┼─────┼─────┼─────┼─────┼───────┤
│     │     │     │     │sib1 │left1│right│     │     │       │
│     │     │     │     │ ... │ ... │ ... │     │     │       │
└─────┴─────┴─────┴─────┴─────┴─────┴─────┴─────┴─────┴───────┘

Column Purposes:
- 0: Leaf value (private witness)
- 1: Merkle root (public input)
- 2: Nullifier (public input)
- 3: Partial S-box for Poseidon hash
- 4: Sibling values (Merkle path)
- 5: Left inputs for hash computation
- 6: Right inputs for hash computation
- 7-14: Additional working columns for Poseidon

┌─────────────────────────────────────────────────────────────┐
│                    FIXED COLUMNS (6)                        │
├─────┬─────┬─────┬─────┬─────┬─────┬─────┬─────┬─────┬───────┤
│  0  │  1  │  2  │  3  │  4  │  5  │ ... │ ... │ ... │  ...  │
├─────┼─────┼─────┼─────┼─────┼─────┼─────┼─────┼─────┼───────┤
│rc_a0│rc_a1│rc_a2│rc_b0│rc_b1│rc_b2│     │     │     │       │
└─────┴─────┴─────┴─────┴─────┴─────┴─────┴─────┴─────┴───────┘

Column Purposes:
- 0-2: Round constants A (Poseidon)
- 3-5: Round constants B (Poseidon)

┌─────────────────────────────────────────────────────────────┐
│                   INSTANCE COLUMN (1)                       │
├─────┬─────┬─────┬─────┬─────┬─────┬─────┬─────┬─────┬───────┤
│  0  │  1  │  2  │ ... │     │     │     │     │     │       │
├─────┼─────┼─────┼─────┼─────┼─────┼─────┼─────┼─────┼───────┤
│leaf │root │null │     │     │     │     │     │     │       │
└─────┴─────┴─────┴─────┴─────┴─────┴─────┴─────┴─────┴───────┘

Public Inputs:
- 0: Leaf value (committed in-circuit)
- 1: Merkle root (committed in-circuit)
- 2: Nullifier (committed in-circuit)
```

## Constraint Flow

### 1. Nullifier Computation Constraint

```
┌─────────────────────────────────────────────────────────────┐
│              NULLIFIER COMPUTATION FLOW                     │
└─────────────────────────────────────────────────────────────┘

Inputs:
┌─────────┐     ┌─────────┐
│  Leaf   │     │  Root   │
│(advice0)│     │(advice1)│
└────┬────┘     └────┬────┘
     │               │
     └───────┬───────┘
             │
     ┌───────▼───────┐
     │  Poseidon     │
     │    Hash       │
     │  (in-circuit) │
     └───────┬───────┘
             │
     ┌───────▼───────┐
     │   Nullifier   │
     │  (computed)   │
     └───────┬───────┘
             │
             ▼
┌──────────────────────────────────┐
│  Constraint: computed_nullifier  │
│          ==                      │
│       provided_nullifier         │
│         (advice2)                │
└──────────────────────────────────┘

Mathematical Constraint:
  nullifier == H(leaf || root)
```

### 2. Merkle Path Verification Flow

```
┌─────────────────────────────────────────────────────────────┐
│              MERKLE PATH VERIFICATION FLOW                  │
└─────────────────────────────────────────────────────────────┘

For each level i from 0 to depth-1:

         Level i                    Level i+1
   ┌─────────────────┐         ┌─────────────────┐
   │  current_hash   │         │  parent_hash    │
   │   (advice)      │         │   (computed)    │
   └────────┬────────┘         └────────┬────────┘
            │                           ▲
            │                           │
            │         ┌─────────────────┘
            │         │
            │    ┌────┴────┐
            └───►│ Hash    │◄───┐
                 │ Function│    │
                 │Poseidon │    │
                 └────┬────┘    │
                      │         │
        ┌─────────────┤         │
        │             │         │
   ┌────┴────┐   ┌────┴────┐    │
   │  Left   │   │  Right  │    │
   │ (advice5)│   │(advice6)│   │
   └─────────┘   └─────────┘    │
                                 │
            ┌────────────────────┘
            │
       ┌────┴────┐
       │Sibling  │
       │(advice4)│
       └─────────┘

Selection Logic:
  if index % 2 == 0 (left child):
    left = current_hash, right = sibling
  else (right child):
    left = sibling, right = current_hash
  
  index = index / 2 (move to parent level)
```

### 3. Complete Circuit Data Flow

```
┌─────────────────────────────────────────────────────────────┐
│                 SET MEMBERSHIP CIRCUIT                      │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│  INPUT ASSIGNMENT REGION (rows 0-1)                         │
├─────────────────────────────────────────────────────────────┤
│ Row 0:                                                      │
│   advice[0] = leaf_value        (private witness)          │
│   advice[1] = merkle_root       (public input)             │
├─────────────────────────────────────────────────────────────┤
│ Row 1:                                                      │
│   advice[2] = nullifier         (public input)             │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│  NULLIFIER COMPUTATION REGION                               │
├─────────────────────────────────────────────────────────────┤
│ Poseidon hash chip:                                         │
│   hash(leaf, root) → computed_nullifier                    │
│                                                             │
│ Constraint:                                                 │
│   computed_nullifier == nullifier (advice[2])              │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│  MERKLE PATH VERIFICATION REGIONS (per sibling)            │
├─────────────────────────────────────────────────────────────┤
│ For each sibling at offset 100 + i*50:                     │
│                                                             │
│ Row offset:                                                 │
│   advice[4] = sibling[i]        (private witness)          │
│   advice[5] = left[i]           (computed)                 │
│   advice[6] = right[i]          (computed)                 │
│                                                             │
│ Poseidon hash:                                              │
│   hash(left, right) → current_hash                         │
│                                                             │
│ Update:                                                     │
│   current_hash = new_hash                                   │
│   index = index / 2                                         │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│  FINAL CONSTRAINTS                                          │
├─────────────────────────────────────────────────────────────┤
│ Constraint:                                                 │
│   current_hash == merkle_root (advice[1])                  │
│                                                             │
│ Public Input Enforcement:                                   │
│   instance[0] == advice[0]  (leaf)                         │
│   instance[1] == advice[1]  (root)                         │
│   instance[2] == advice[2]  (nullifier)                    │
└─────────────────────────────────────────────────────────────┘
```

## Constraint Gates

### Gate Structure

```
┌─────────────────────────────────────────────────────────────┐
│                    CONSTRAINT GATES                         │
└─────────────────────────────────────────────────────────────┘

1. Equality Gates (Copy Constraints):
   ┌─────────────────────────────────────────────────────┐
   │  instance[0] === advice[0]  (leaf commitment)       │
   │  instance[1] === advice[1]  (root commitment)       │
   │  instance[2] === advice[2]  (nullifier commitment)  │
   │  computed_nullifier === advice[2]                   │
   │  final_hash === advice[1]  (Merkle root)           │
   └─────────────────────────────────────────────────────┘

2. Poseidon Hash Gates:
   ┌─────────────────────────────────────────────────────┐
   │  For each hash computation:                         │
   │    - State initialization                           │
   │    - Full rounds (3 rounds)                         │
   │    - Partial rounds (2 rounds)                      │
   │    - Output extraction                              │
   │                                                     │
   │  Constraints enforced by halo2_gadgets PoseidonChip │
   └─────────────────────────────────────────────────────┘

3. Selection Gates (Merkle Path):
   ┌─────────────────────────────────────────────────────┐
   │  For each level:                                    │
   │    left = (index % 2 == 0) ? current : sibling     │
   │    right = (index % 2 == 0) ? sibling : current    │
   │                                                     │
   │  Note: Currently implemented as value assignment    │
   │  with proper constraints on hash inputs             │
   └─────────────────────────────────────────────────────┘
```

## Security Properties

```
┌─────────────────────────────────────────────────────────────┐
│                SECURITY GUARANTEES                          │
└─────────────────────────────────────────────────────────────┘

✓ Knowledge of Leaf: Prover must know the leaf value
  Constraint: leaf committed as public input

✓ Knowledge of Root: Prover must know the Merkle root
  Constraint: root committed as public input

✓ Membership Proof: Prover must provide valid Merkle path
  Constraint: hash chain must resolve to root

✓ Nullifier Consistency: Nullifier must be H(leaf || root)
  Constraint: computed == provided in-circuit

✓ Non-replayability: Same leaf+root always produces same nullifier
  Property: Deterministic hash function

✓ Zero-Knowledge: Siblings and leaf index remain private
  Property: Witness values not exposed in public inputs
```

## Circuit Parameters

```
┌─────────────────────────────────────────────────────────────┐
│                    CIRCUIT PARAMETERS                       │
└─────────────────────────────────────────────────────────────┘

K = 12
  - Circuit rows: 2^12 = 4096
  - Maximum tree depth: 12 levels
  - Maximum leaves: 4096

Column Counts:
  - Advice columns: 15
  - Fixed columns: 6
  - Instance columns: 1

Region Offsets:
  - Initial input assignment: row 0
  - Nullifier computation: row 1
  - Merkle siblings start: row 100
  - Row increment per sibling: 50

Poseidon Configuration:
  - State width: 3
  - Full rounds: 3
  - Partial rounds: 2
  - Specification: P128Pow5T3
```

## Verification Flow

```
┌─────────────────────────────────────────────────────────────┐
│              VERIFIER WORKFLOW                              │
└─────────────────────────────────────────────────────────────┘

1. Parse Proof:
   ┌─────────────┐
   │ proof.json  │──► ZKProofOutput structure
   └─────────────┘

2. Validate Structure:
   ┌─────────────────────────────────────┐
   │ ✓ Non-empty fields                  │
   │ ✓ Timestamp in valid range          │
   │ ✓ Valid hex encoding                │
   │ ✓ Correct byte lengths              │
   │ ✓ Nullifier == H(leaf || root)     │
   └─────────────────────────────────────┘

3. Verify ZK-SNARK:
   ┌─────────────────────────────────────┐
   │ Load proving params (K=12)          │
   │ Load verifying key                  │
   │ Verify proof with public inputs:    │
   │   - leaf                            │
   │   - root                            │
   │   - nullifier                       │
   └─────────────────────────────────────┘

4. Check Nullifier:
   ┌─────────────────────────────────────┐
   │ Check against nullifiers.txt        │
   │ If new: record for replay detection │
   │ If exists: reject (double-spend)   │
   └─────────────────────────────────────┘
```

## Performance Characteristics

```
┌─────────────────────────────────────────────────────────────┐
│               PERFORMANCE METRICS                           │
└─────────────────────────────────────────────────────────────┘

Proof Generation:
  - Time complexity: O(depth) per hash computation
  - Space complexity: O(2^K) circuit size
  - Typical time: ~1-30 seconds (depends on tree depth)

Proof Verification:
  - Time complexity: O(1) constant time
  - Typical time: ~10-100 milliseconds

Key Generation:
  - One-time setup per circuit parameter K
  - Can be cached for performance

Circuit Size:
  - Base overhead: ~100 rows
  - Per sibling: ~50 rows
  - Maximum siblings: ~80 (with K=12)
```

## Common Patterns

### Adding a New Constraint

```rust
// Example: Adding an equality constraint
layouter.assign_region(
    || "constraint name",
    |mut region| {
        region.constrain_equal(cell_a, cell_b)
    },
)?;
```

### Using the Poseidon Chip

```rust
// Initialize the hash chip
let poseidon_hash = PoseidonHash::<...>::init(
    PoseidonChipType::construct(config),
    layouter.namespace(|| "init hash"),
)?;

// Compute hash
let result = poseidon_hash.hash(
    layouter.namespace(|| "compute hash"),
    [input_a, input_b],
)?;
```

### Assigning Values Across Regions

```rust
// Values can be used across regions through their cells
let cell_a = layouter.assign_region(
    || "region 1",
    |mut region| {
        region.assign_advice(
            || "value",
            config.advice[0],
            0,
            || Value::known(value),
        )
    },
)?;

// Use in another region via constrain_equal or copy constraints
layouter.assign_region(
    || "region 2",
    |mut region| {
        region.constrain_equal(cell_a.cell(), other_cell.cell())
    },
)?;
```
