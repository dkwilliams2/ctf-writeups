# Merkle Tree Tampering – CTF Writeup

**Category:** Cryptography
**Files:** `corrupted-tree.json`, `audit_paths.json`

## The Challenge

A ledger of 8 transactions is protected by a Merkle tree. Someone tampered with one entry, so the tree's root hash no longer matches the trusted `expected_root`. The goal is to find the bad record and reconstruct what it should be.

## Background

**SHA-256** turns any input into a fixed 64-character hex fingerprint. Changing even one character of the input produces a completely different hash, and the hash can't be reversed back into the input.

A **Merkle tree** hashes each record into a *leaf*. Pairs of hashes are then hashed together, level by level, until a single **root** hash is left. Changing one record changes every hash on its path up to the root.

```
                     root
              /               \
         L2[0]                 L2[1]
        /     \               /     \
    L1[0]     L1[1]       L1[2]     L1[3]
    /  \      /  \        /  \      /  \
   0    1    2    3      4    5    6    7     <- leaves (transactions)
```

An **audit path** is the list of sibling hashes needed to recompute the root from a single leaf.

In this tree:
- leaf hash = `sha256(data)`
- parent hash = `sha256(left_hex + right_hex)` (the two hex strings joined, then hashed)

## Solution

### Step 1: Find the tampered leaf

Rehash each leaf's `data` and compare it with its stored `hash`:

```bash
python3 -c "
import json, hashlib
tree = json.load(open('corrupted-tree.json'))
for leaf in tree['levels'][0]['nodes']:
    actual = hashlib.sha256(leaf['data'].encode()).hexdigest()
    print(leaf['index'], 'OK' if actual == leaf['hash'] else '<-- TAMPERED')
"
```

```
0 OK
1 OK
2 OK
3 OK
4 OK
5 <-- TAMPERED
6 OK
7 OK
```

Leaf 5's text no longer matches its stored hash. The text was changed, but the original hash was left in place.

Leaf 5's data: `tx:0x8f64f7fd633dbdde->0x131ca3766e4d58e7:9.7261`

### Step 2: Read the audit path

```bash
grep -A 6 '"leaf_index": 5' audit_paths.json
```

```json
"leaf_index": 5,
"leaf_hash": "42d9bf34bffe15cb8c09a9352d16b35f02213bec2f2e35420e5e7553ccb518db",
"path": [
  "05a738ebfed33488d78a59bb3cc1c5cc57fdeec44893093c756d937b6cc948c2",
  "c7d8d7bffe4cbcbba079395c4c8e7b23856abcaa711bd1bc71f7b23aba44748d",
  "68dbae903fe5b88ae3d415d42ddebe2f30cf3c8a245ec691c68b652fe3d2731b"
]
```

- `path[0]` is the **sibling** (leaf 4, since leaves pair up as 0+1, 2+3, 4+5, 6+7).
- `path[1]` is the sibling at the next level up (the 6+7 pair).

You can confirm the sibling by hashing leaf 4's data:

```bash
echo -n 'tx:0x2f244f58d669cbee->0x3772a077021721a2:65.3899' | sha256sum
# 05a738ebfed33488d78a59bb3cc1c5cc57fdeec44893093c756d937b6cc948c2
```

(`-n` stops `echo` from adding a newline, which would change the hash.)

### Step 3: Work out which field was tampered with

The format is `tx:SENDER->RECEIVER:AMOUNT`. A hash can't be reversed, but you can guess the original text and check each guess.

- SENDER and RECEIVER are 16 hex characters each (about 1.8 × 10¹⁹ possibilities), which is too many to guess.
- AMOUNT has 4 decimal places, so every value from 0 to 999.9999 is only 10 million guesses.

Keep the sender and receiver fixed and try every amount:

```bash
python3 -c "
import hashlib
target = '42d9bf34bffe15cb8c09a9352d16b35f02213bec2f2e35420e5e7553ccb518db'
prefix = 'tx:0x8f64f7fd633dbdde->0x131ca3766e4d58e7:'
for i in range(10000000):
    amt = f'{i/10000:.4f}'.rstrip('0').rstrip('.')
    if hashlib.sha256((prefix + amt).encode()).hexdigest() == target:
        print('Original amount:', amt); break
"
# Original amount: 9.726
```

The amount was changed from **9.726** to **9.7261**.

### Step 4: Rebuild the corrected tree

Restored record: `tx:0x8f64f7fd633dbdde->0x131ca3766e4d58e7:9.726`

```bash
echo -n 'tx:0x8f64f7fd633dbdde->0x131ca3766e4d58e7:9.726' | sha256sum
# 42d9bf34bffe15cb8c09a9352d16b35f02213bec2f2e35420e5e7553ccb518db
```

Corrected parent = `sha256(leaf4_hash + leaf5_hash)`:

```bash
echo -n '05a738ebfed33488d78a59bb3cc1c5cc57fdeec44893093c756d937b6cc948c242d9bf34bffe15cb8c09a9352d16b35f02213bec2f2e35420e5e7553ccb518db' | sha256sum
# c1e753564f883378ea3d96231fd26d769e44eb4ced1dcede9c5483036251564c
```

This matches the sibling listed in the audit paths for leaves 6 and 7. The tampered tree stored `f3e7c3f9…` here instead.

Hashing up the rest of the path gives `cc6762838c949d734c4f3016ba13c4956f7548cfc07396b59ba95c1f7216716a`, which equals `expected_root`. The fix is confirmed.

## Automated Solve

`solve.py` runs every step above:

```bash
python3 solve.py corrupted-tree.json audit_paths.json
```

## Answers

| # | Question | Answer |
|---|---|---|
| Q1 | Index of the corrupted leaf | `5` |
| Q2 | Audit path hash at index 1 | `c7d8d7bffe4cbcbba079395c4c8e7b23856abcaa711bd1bc71f7b23aba44748d` |
| Q3 | Sibling hash of the corrupted leaf | `05a738ebfed33488d78a59bb3cc1c5cc57fdeec44893093c756d937b6cc948c2` |
| Q4 | Tampered field | `AMOUNT` (9.726 → 9.7261) |
| Q5 | Correct hash of the corrupted leaf | `42d9bf34bffe15cb8c09a9352d16b35f02213bec2f2e35420e5e7553ccb518db` |
| Q6 | Parent hash in the corrected tree | `c1e753564f883378ea3d96231fd26d769e44eb4ced1dcede9c5483036251564c` |

## Takeaways

- Rehashing leaves and comparing them with the stored hashes pinpoints edited records.
- Audit paths come from the honest tree, so they're a trusted reference for internal nodes.
- Hashes can't be reversed, but small, predictable fields (like amounts) can be recovered by brute force.
