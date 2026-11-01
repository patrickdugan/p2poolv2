# M15: the joined statement at scale

Measured 2026-11-01 on `zk-clearing-m15` (from `c4122f50`), on an AMD Ryzen AI 9 365 under WSL2
Ubuntu 24.04 with a 19 GB VM. Other sessions' jobs ran on the machine at the same time (load
average 3 to 13), so wall-clock times are upper bounds. Toolchain: circom 2.2.2, snarkjs 0.7.5,
circomlib 2.0.5, circomlibjs 0.1.7 (pinned by `groth16/package-lock.json`), Node 22.12, CPython
3.12. The setup is the insecure deterministic one of `GROTH16.md`, on M6's prepared power-20
phase-1 file, and the keys are public demo keys. All prove times are snarkjs; rapidsnark was not
built.

Numbers marked *est.* are arithmetic on measurements, not runs. Everything else was run.

## What this milestone answers

M10 joins M4's signatures to M5's membership proofs for 16 flat slots. M11 puts the signatures on
M6's tree behind one hashed public input. Joined naively, a sale costs 5,621 constraints in M11's
circuit and 11,438 in M5's membership proof, so 1,024 sales come to 17.5 million. Four results:

1. **A dense tree over the window's outputs proves the same fact at 4,417 constraints per sale
   instead of 11,438** (binary nodes, 17 levels), or **2,775** with eight-way nodes (6 levels).
   The tree is a Poseidon tree over the anchor's live outputs in key order. Its leaf holds the
   outpoint, the owner, the units and the root height, so a position the prover names cannot make
   a different output pass. Positions must rise across the batch's sale slots, which refuses a
   repeated output at 19 constraints a slot; M5's tree has no such check (sections 1 and 2).
2. **The joined circuit works at 16×4, 32×8 and 64×8, behind one public input, with the root in
   the hashed statement.** Measured end to end with `groth16/run.sh`: 64×8 is 688,135 constraints
   with the binary tree and 583,110 with the eight-way tree, and proves in 34 s and 6.1 GiB
   (section 5). With M5's tree 32×8 is 591,866 constraints and 64×8 is 1,136,282, over the
   2^20 ceiling.
3. **Fourteen invalid inputs are refused at the rule they break**: a signer that is not the
   registered owner, an output that is spent, expired or immature, a forged position, a repeated
   output, slots out of order, a hole among the active slots, a wrong root, a bad order signature
   and a statement hash without the root. Each is refused in the template that checks the rule
   (section 7).
4. **1,024 sales come to 10.3 million constraints (binary) or 8.6 million (eight-way), against
   17.5 million, *est.*** Phase-1 power 24 instead of 25. The eight-way tree misses power 23
   (8,388,608) by 2.7% (section 8).

## 1. The membership statement

**The set.** It is M5's set (`OWNERSHIP.md` section 1.4, items 1 to 5): outputs on the chain
ending at the anchor, unspent at it, P2TR, worth at least `min_units`, with a root height inside
the window `[h + 1 - PAYOUT_DEPTH + M, h + 1 - COINBASE_MATURITY]`. Item 6, M5's slot rule that
keeps a sparse tree shallow, is dropped. A dense tree has no slots to lose, so every output that
meets items 1 to 5 is a leaf. In its place the set has a capacity, `radix ^ levels`.

**The order.** The leaves are sorted by `key`, the outpoint's field id (`smt.outpoint_id`, the
`saleId` of the circuits), strictly ascending. The position of an output is its rank. An output
that is not in the set has no position.

**The hashes**, in circomlib's `Poseidon(n)`:

    leaf   = Poseidon(key, owner, units, root_height)       4 inputs
    node   = Poseidon(child_0, ..., child_{r-1})            r = 2^radixBits inputs
    empty  = a leaf of 0; nodes above empty leaves hash their children like any other node

The tree has `levels` levels of nodes and so `radix ^ levels` positions. `owner` is
`smt.owner_field`: the registered order key hash of the output's address (M10), else M5's address
id. `ownership/window_tree.py` builds the tree and matches circomlibjs: `window_vectors.json`
holds circomlibjs's Poseidon outputs for 4 and 8 inputs and the roots, leaf hashes and paths of
eight trees (binary with 0, 1, 11, 16 and 9 leaves, radix 4, and radix 8 at 3 and 6 levels).

| | Nodes | Levels | Positions | M5's live set (119,953) |
|---|---|---|---|---|
| Binary | `Poseidon(2)` | 17 | 131,072 | fills 91.5% |
| Eight-way | `Poseidon(8)` | 6 | 262,144 | fills 45.8% |

**The circuit.** `ownership/circuits/window_sale.circom` defines `WindowSales(saleSlots,
radixBits, levels)`. For every active sale slot it checks:

- `leaf = Poseidon(saleId, sellerId, units, rootHeight)`. `units` and `rootHeight` are private
  and fixed by the tree, as in M5.
- A private `position` is split into digits by `Num2Bits`, least significant first. At each level
  the node's `r` children are private inputs; the circuit checks that the child at the digit is
  the running hash (a binary tree of `Mux1`, `r - 1` constraints) and hashes the children into the
  next running hash. At the top, `enabled * (hash - windowRoot) === 0`.
- Across slots, `WindowOrder` on each neighbouring pair: the active slots are a prefix
  (`active[s] * (1 - active[s-1]) === 0`), and `position[s] - position[s-1] - 1` fits in
  `radixBits * levels` bits when the slot is active, which holds exactly when it is not negative.

Padding slots carry zeros and a consistent dummy path, and the root check is off for them.

**Standalone cost**, measured (circom `--O2`, one slot and sixteen):

| Membership proof | Constraints per slot | Of which | Sixteen slots |
|---|---|---|---|
| M5, `SMTVerifier`, 40 levels | 11,438 | 40 × 247 + 1,558 | 183,008 |
| Window, binary, 17 levels | **4,417** | 17 × 241 (`Poseidon(2)` 240 + one select) + 17 digit bits + leaf `Poseidon(4)` 297 + 6 | 70,957 |
| Window, eight-way, 6 levels | **2,775** | 6 × 409 (`Poseidon(8)` 402 + 7 selects) + 18 digit bits + 297 + 6 | 44,700 |
| `WindowOrder`, per neighbouring pair | 19 binary, 20 eight-way | prefix 1, gate 1, `Num2Bits(17 or 18)` | 15 pairs: 285, 300 |

The 6 is the boolean rule, four padding rules and the root check. The binary slot is 38.6% of
M5's, and the eight-way slot 24.3%.

**The same circuit on a production-size tree.** `bench_window.py` builds a tree of 119,953
synthetic outputs, and `window_sale_n1` takes one of its leaves as a valid witness. The witness
satisfies the R1CS and proves in 0.78 s (setup 12.25 s on the power-20 file, verify 0.42 s), and
the proof's first public signal is the build's root. A wrong owner is refused in `WindowSale`, and
a position one off in `WindowLevel`. The eight-way circuit accepts its valid witness and refuses
the same two (`results/production-tree-one-slot.txt`).

## 2. What it proves, and what it does not, against M5's tree

**It proves**, for every active sale slot: a leaf `(saleId, sellerId, units, rootHeight)` is in
the tree with root `windowRoot`, and across the batch the sale slots name leaves at strictly
rising positions. With `sellerId` shared with M11's signature check (section 4), the key that
signed the order is the key hash that the tree stores as the owner of the sold output, with the
output's units and root height.

| | M5's sparse tree | Window tree |
|---|---|---|
| Where the path comes from | The bits of `saleId`, inside the circuit (`Num2Bits_strict`, 515 constraints) | A private `position`; the leaf holds `saleId` |
| One value per outpoint | By construction: the path is a function of the key, so any root holds at most one value for it | By the builder's rule: a root that holds one outpoint at two positions, with two owners, would pass. Watchers' rebuild catches it |
| The same output in two sale slots | Not checked (`OWNERSHIP.md` 7.3) | Refused: positions must rise (19 constraints a slot), given one position per outpoint |
| Outputs left out | Those that lose a slot (39 low key bits): 0.69 a year in today's set, each for at most 14 days | None. A capacity limit instead; past it `min_units` is raised |
| Levels paid | 40 whatever the leaf's depth | Exactly 17 (binary) or 6 (eight-way) |
| Exclusion proofs | Yes (the circuit does not use them) | No |
| Update | Incremental: about 35 Poseidon evaluations a share | Rebuilt from the sorted set for each anchor |
| Proof a seller carries | About 18 siblings on average, 582 B | 17 siblings, 544 B (binary); 42 siblings, 1,344 B (eight-way) |
| Constraints per sale slot | 11,438 | 4,436 (binary), 2,795 (eight-way), with the order check |

**What position freedom does and does not cost.** Naming a position does not help a prover pass a
leaf that is not in the tree: the path has to hash to `windowRoot`, and the leaf it starts from
holds the outpoint. The fixtures try the strongest forgery, the real path at the output's position
with the claimed leaf spliced in, which passes every selection check and fails at the root. An
empty position holds 0, and a sale's leaf is a Poseidon output, so no sale matches an empty
position. What the circuit cannot see is a root that holds a repeated outpoint, which breaks the
"one position per outpoint" that the order check relies on. Sorting by key makes that checkable
with one scan of the leaf list, and it is the first thing a watcher does.

**What neither proves.** Everything `OWNERSHIP.md` section 7 and `JOINED.md` section 7 list
stands. The circuit does not know that `windowRoot` is the root of a canonical anchor or that
it was built correctly from the sharechain and the registry. A sold output can be spent after the
anchor; closing that gap depends on a lock that sharechain validation would have to enforce, which
this milestone neither assumes to exist nor checks. The escrow outpoint and the payout script are
field encodings, as in M4.

## 3. What watchers recompute

1. **The set**, as in `OWNERSHIP.md` 7.2: replay the confirmed chain to the anchor
   (`SharechainUtxo.eligible`), with the registry (`JOINED.md` 2 and 3).
2. **The order**: sort by `saleId`, and refuse a set with a repeated key (`KeysNotAscending`) or
   with more outputs than the circuit's capacity (`CapacityExceeded`).
3. **The tree**: one leaf hash per output and one node hash per node. They publish
   `(anchor, root, leaf count, min_units)` and refuse to presign a root they do not reproduce.
4. **The proofs they serve**: a seller asks for the position and children of an outpoint.

The rebuild replaces M5's per-share update. Measured by `bench_window.py` on 119,953 synthetic
outputs, CPython, one loaded core:

| Tree | Poseidon evaluations | Seconds |
|---|---|---|
| M5's sparse tree, from scratch | 412,575 (172,669 `Poseidon(2)` + 239,906 `Poseidon(3)`) | 112.9 |
| Window, binary | 239,932 (119,953 `Poseidon(4)` + 119,979 `Poseidon(2)`) | 97.0 |
| Window, eight-way | 137,099 (119,953 `Poseidon(4)` + 17,146 `Poseidon(8)`) | 93.1 |

M5 section 3.3 puts incremental maintenance at about 35 evaluations a share, about 302,000 a day
at the 10 s target (*est.*). A watcher that publishes one batch root a day rebuilds the binary tree
once, at 239,932 evaluations, where M5's tree takes about 302,000 to follow that day's shares. An
incrementally maintained dense tree (append-only in creation order, spends zeroed) was not built.

Capacity is the new limit. M5's "4 splits per share" load (section 3.3) settles near 298,000
leaves, *est.*, past both 131,072 and 262,144. At that load a watcher raises `min_units`
(`OWNERSHIP.md` 3.4), or the circuit takes 19 binary levels (+484 constraints a slot, *est.*) or 7
eight-way levels (+412).

## 4. The joined circuit

`circuits/clearing_tree_owned.circom` instantiates M11's `SignedClearingTree` and a membership
template, and wires them to the same `activeSale`, `saleId` and `sellerId`, as M10 does for the
flat circuit. A sale passes only if the key that signed its order is the key hash that the tree
stores as the owner of the sold output. Two wrappers share the signed tree:
`OwnedSignedTreeWindow` (the window tree) and `OwnedSignedTreeSmt` (M5's, for the comparison).

**The statement** gains one value, the ownership root, at the end:

    statement     = [saleCommitment, escrowCommitment, batchHeight, totalPayout,
                     funding[], feeBudget[], refund[], buyerId[], ownershipRoot]     5 + 4B values
    statementHash = PoseidonChunked(statement)

The proof still has one public signal, `statementHash`, and the verifying key is 2,930 to 2,932
bytes of JSON, the shape of M11's. The root is a private input bound by the hash. A committee that
reproduces the root recomputes the hash from the 5 + 4B values (`statement_joined_tree.js`), and a
proof made for another root has another hash. At B = 8 the statement has 37 values, so
`PoseidonChunked` ends in a chunk of one value. The root costs 249 constraints there and 15 at
B = 4.

**One change to M11's file.** `SignedClearingTree` takes a fourth parameter, `extraValues`, and an
`extra[extraValues]` input appended to the hashed statement. M11's three circuits pass 0, which
declares no signal. `signed_tree_16x4` compiles to the same R1CS and symbol file as on branch
`zk-clearing-m11` (`fd8823c2`), sha256 `d58a0716…` and `8aab9175…`, and `signed_tree_64x8` to the
same as at `c4122f50`, `9ff782a0…` and `7d2c5960…` (`results/m11-circuit-unchanged.txt`).
`signedtree/cost_split.sh` passes the 0 as well.

## 5. Results

Reproduce one column (section 11). `run_size.sh` calls `groth16/run.sh` with `FIXTURES`,
`STATEMENT_JS` and `CIRCUIT_DIR`, then the checks that belong to the join. The raw outputs are in
`results/run-<kind>_<S>x<B>.txt`.

Every circuit passes every check:

- the valid witness satisfies the R1CS and the proof verifies;
- the proof's public signal equals circomlibjs's `statementHash` over the full statement (the
  last of its 21 or 37 values is the tree's root);
- the re-split batch (other outputs, same totals) proves a different `statementHash`;
- every invalid input is refused by the witness calculator, 14 for the window circuits and 9 for
  M5's (section 7), each in the template the manifest names, and the pure-Python model of the
  membership and order rules predicts the same template;
- a changed public signal, a public signal written as `x + r`, and a forged `.wtns` are rejected
  (the forged witness fails the R1CS at constraint 180,121, 360,162, 672,834, 153,864, 307,649,
  567,809, 292,172 and 584,245, in the order of the table);
- a batch with the last quarter of the sale slots and the last buyer slot unused satisfies the R1CS.

| | Binary 16×4 | Binary 32×8 | Binary 64×8 | Eight-way 16×4 | Eight-way 32×8 | Eight-way 64×8 | M5 16×4 | M5 32×8 | M5 64×8 |
|---|---|---|---|---|---|---|---|---|---|
| Constraints | 183,893 | 367,783 | **688,135** | 157,636 | 315,270 | **583,110** | 295,944 | 591,866 | 1,136,282 (sum of parts) |
| Per sale slot | 11,493 | 11,493 | 10,752 | 9,852 | 9,852 | 9,111 | 18,496 | 18,496 | 17,754 |
| Compile | 27.4 s, 1.57 GiB | 39.5 s, 1.98 GiB | 74.9 s, 3.02 GiB | 19.7 s, 1.78 GiB | 30.8 s, 1.94 GiB | 59.0 s, 2.97 GiB | 33.2 s, 1.93 GiB | 59.4 s, 2.81 GiB | not run |
| Phase 2 (setup + beacon) | 89.2 s, 2.10 GiB | 173.3 s, 3.47 GiB | 331.4 s, 5.56 GiB | 95.1 s, 2.17 GiB | 189.4 s, 3.49 GiB | 405.5 s, 5.98 GiB | 114.5 s, 3.03 GiB | 238.8 s, 5.03 GiB | not run |
| Proving key | 128.1 MB | 256.0 MB | 480.8 MB | 148.1 MB | 296.2 MB | 561.1 MB | 198.1 MB | 396.0 MB | not run |
| Witness (wasm), 3 runs | 1.4 to 2.0 s | 2.8 to 3.2 s | 4.6 to 5.2 s | 1.2 to 1.6 s | 2.3 to 3.3 s | 5.4 to 5.8 s | not run | not run | not run |
| **Prove (snarkjs)**, in `run.sh` | **11.5 s**, 3.18 GiB | **23.9 s**, 4.53 GiB | **34.1 s**, 6.10 GiB | **10.4 s**, 3.11 GiB | **21.0 s**, 4.49 GiB | **33.6 s**, 5.88 GiB | **31.5 s**, 4.17 GiB | **24.9 s**, 5.83 GiB | not run |
| Prove, two repeats on the same zkey | 7.0, 8.6 s | 16.9, 27.0 s | 41.7, 51.9 s | 7.1, 14.7 s | 21.3, 24.5 s | 30.5, 42.3 s | not run | not run | not run |
| Verify (snarkjs CLI) | 0.88 s | 0.92 s | 1.51 s | 0.88 s | 0.86 s | 0.80 s | 1.79 s | 0.90 s | not run |
| Proof, public signals | 256 B, 1 | 256 B, 1 | 256 B, 1 | 256 B, 1 | 256 B, 1 | 256 B, 1 | 256 B, 1 | 256 B, 1 | not run |
| Verifying key sha256 | `3f5a4e32…` | `30aada6c…` | `fef19648…` | `b95aabf3…` | `8c9e4638…` | `b19f63d0…` | `5c9920f3…` | `4cf3ddf9…` | not run |

Reading the table:

- **The ceiling.** Both window trees fit 64×8 inside 2^20 = 1,048,576 (66% and 56%). M5's tree
  stops at 32×8 (56%); its 64×8 is 108% of the ceiling. 128×8 fits none of the three: M11's
  760,801 plus 128 slots of membership is 1.33 M (binary) and 1.12 M (eight-way), *est.*
- **Read the prove times as a range.** The `run.sh` figure is one run. The two repeats ran later
  under a different load and are 0.6 to 1.5 times it. M5's 16×4 proof (31.5 s) is slower than its
  32×8 proof (24.9 s) because the machine was busier then. The repeats of the two M5 circuits did
  not run: the VM ran out of memory during that step, after all eight runs had finished.
- **Memory.** The largest process was the prover at 64×8: 6.10 GiB (binary) and 5.88 GiB
  (eight-way). Phase 2 peaked at 5.98 GiB.
- **Against M11.** M11's 64×8 is 404,001 constraints and 22.3 s in `run.sh`. The binary
  membership adds 284,134 constraints (+70%) and the eight-way 179,109 (+44%).
- **The 16×4 binary run** had its join checks repeated on the finished build, after the refusal
  check was corrected to skip circomlib's helper templates (its first pass named `Num2Bits`, the
  helper inside `WindowOrder`). Its compile, setup, prove and verify were not repeated. The other
  seven runs used the corrected check.
- circom panicked with `SystemTimeError` on several compiles when the VM's clock stepped back;
  rerunning the same command compiled the same circuit.

## 6. Where the constraints go

`cost_split.sh` compiles each part as its own main and adds them up:

    joined = M11's circuit + S × membership + (S - 1) × order + the root in the statement hash

At all eight compiled circuits the sum equals the compiled whole exactly (difference 0), so the
64×8 count of M5's circuit, 1,136,282, is the sum of its parts (`results/cost-split-*.txt`).

| Part | 16×4 | 32×8 | 64×8 | 1,024×8 (*est.*) |
|---|---|---|---|---|
| M11's circuit | 112,921 | 225,601 | 404,001 | 5,756,001 |
| The root in the statement hash | 15 | 249 | 249 | 249 |
| Binary: membership (4,417 a slot) | 70,672 | 141,344 | 282,688 | 4,523,008 |
| Binary: order (19 a pair) | 285 | 589 | 1,197 | 19,437 |
| **Binary total** | **183,893** | **367,783** | **688,135** | **10,298,695** |
| Eight-way: membership (2,775 a slot) | 44,400 | 88,800 | 177,600 | 2,841,600 |
| Eight-way: order (20 a pair) | 300 | 620 | 1,260 | 20,460 |
| **Eight-way total** | **157,636** | **315,270** | **583,110** | **8,618,310** |
| M5: membership (11,438 a slot) | 183,008 | 366,016 | 732,032 | 11,712,512 |
| **M5 total** | **295,944** | **591,866** | **1,136,282** | **17,468,762** |

The 1,024×8 column takes its first row from `signedtree/results/cost-split-1024x8-est.txt`, the
sum of M11's compiled parts; the other rows are the measured per-slot costs times 1,024 and 1,023.

Per sale slot at 64×8 (rounded; M11's split is in `SIGNED_TREE.md`):

| | Seller signature | Buyer signatures, spread | Rest of M11's circuit | Membership | Order and root | Per slot |
|---|---|---|---|---|---|---|
| M5's tree | 4,852 | 626 | 835 | 11,438 | 4 | 17,754 |
| Binary | 4,852 | 626 | 835 | 4,417 | 23 | 10,752 |
| Eight-way | 4,852 | 626 | 835 | 2,775 | 24 | 9,111 |

## 7. The fixtures

`make_joined_tree.py` builds the world and `sign_tree.js` signs it. The world is
`joined/make_joined.py`'s: 201 synthetic blocks at the sim depths of `real_store.py` (maturity
20, payout depth 100, expiry margin 4), so the window at the anchor is root heights 105 to 181
and holds 77 outputs. Ten miners take the coinbases in turn. At height 150 a share transaction
moves Dave's output to Carol. Every miner but Zed registers an order key (BIP340, demo keys),
which leaves 69 outputs that a registered key can sell. A batch of S sales sells the S lowest of
them in tree order, so sale slot s names the output at the s-th lowest position, signed by its
owner's registered key. M5's tree over the same set has 77 leaves and a deepest leaf at depth 12;
the circuit still pays 40 levels. Every secret is a demo key derived from a public label.

Accepted by every circuit:

| Input | What it is |
|---|---|
| `valid` | S sales, each with the registered key; proves and verifies |
| `resplit` | Same totals and prices, sold from the outputs one position higher; proves a different `statementHash` |
| `padded` | The last quarter of the sale slots and the last buyer slot unused; satisfies the R1CS |
| `valid_duplicate_output_two_slots` (M5's circuits only) | Slots 3 and 4 sell the same output, each validly signed. M5's tree accepts it |

Refused, each breaking one rule. The last column is the first template of the join or of M11's
signed tree in the witness calculator's error chain:

| Input | What changed from `valid` | Refused in | In M5's circuits |
|---|---|---|---|
| `signer_not_registered_owner` | Slot 0 is signed by a key that no address registered | `WindowSale`, root check | `SMTVerifier` |
| `signer_is_another_registered_seller` | Slot 0 is signed by another registered seller's key | `WindowSale` | `SMTVerifier` |
| `unregistered_owner_output` | Zed signs for his own output; his address never registered | `WindowSale` | `SMTVerifier` |
| `output_spent_before_anchor` | Dave, the registered owner, sells the output spent at height 150 | `WindowSale` | `SMTVerifier` |
| `output_expired` | A registered owner sells an output of root height 104, one below the window | `WindowSale` | `SMTVerifier` |
| `output_immature` | A registered owner sells the tip's own coinbase output | `WindowSale` | `SMTVerifier` |
| `wrong_window_root` (`wrong_utxo_root`) | The root one higher, with the hash consistent | `WindowSale` | `SMTVerifier` |
| `position_disagrees_with_path` | The last slot's real leaf and path under the position one above its own | `WindowLevel`, selection check | |
| `member_leaf_at_wrong_position` | The last slot's real leaf spliced into the path of the position one above | `WindowSale` | |
| `duplicate_output_two_slots` | Slots 3 and 4 sell one output, each validly signed | `WindowOrder` | accepted |
| `slots_out_of_position_order` | Slots 3 and 4 swapped; both memberships hold | `WindowOrder` | |
| `hole_in_active_slots` | An unused sale slot between active ones | `WindowOrder` | |
| `bad_order_signature` | Slot 0's order signature `S` + 1 | `EdDSAPoseidonVerifier` | same |
| `statement_hash_omits_root` | The public hash is M11's, over the statement without the root | `SignedClearingTree` | same |

A sale of an output that is not in the set takes the last active slot and the first free
position, and the other slots keep their order, so only the membership rule is broken. Every
variant is also predicted by a pure-Python model of the membership and order rules
(`test_make_joined_tree.py`), and `run_size.sh` fails if the circuit and the model disagree.

## 8. 1,024 sales (*est.*)

Not a run. A 1,024-sale batch is far above what this VM holds.

| | M5's tree (the naive join) | Binary window | Eight-way window |
|---|---|---|---|
| Constraints | **17,468,762** | **10,298,695** | **8,618,310** |
| Per sale slot | 17,059 | 10,057 | 8,416 |
| Against the naive join | | −7,170,067 (−41.0%) | −8,850,452 (−50.7%) |
| Phase-1 power | 25 (2^25 = 33,554,432) | 24 (2^24 = 16,777,216) | 24 |
| Phase-1 file | about 38.7 GB | about 19.3 GB | about 19.3 GB |
| Compile | about 1,750 s, 53 to 83 GiB | about 1,120 s, 34 to 45 GiB | about 870 s, 34 to 44 GiB |
| Phase 2 (setup + beacon) | about 7,050 s, 119 to 149 GiB | about 4,960 s, 68 to 83 GiB | about 5,990 s, 81 to 88 GiB |
| Proving key | about 11.7 GB | about 7.2 GB | about 8.3 GB |
| **Prove (snarkjs)** | about 730 s (one run), 101 to 172 GiB | **about 510 to 620 s**, 53 to 91 GiB | **about 450 to 500 s**, 48 to 87 GiB |
| Verify, proof, public signals | about 1 s, 256 B, 1 | about 1 s, 256 B, 1 | about 1 s, 256 B, 1 |
| Signatures' share of the circuit | 28.7% | 48.6% | 58.1% |

For reference, M11's circuit alone (no ownership) is 5,756,001 constraints at power 23.

Basis:

- **Constraints**: M11's 1,024×8 sum of parts, plus 249 for the root, plus 1,024 times the
  membership and 1,023 times the order check (section 6). The same sum is exact at the eight
  compiled sizes.
- **Phase-1 power**: the smallest power with 2^power at or above the constraint count.
- **Times**: the largest measured run of the same kind (688,135, 583,110 or 591,866 constraints)
  scaled by the constraint ratio (14.97, 14.78, 29.51). The prove range runs from the lowest
  observed time of that circuit to the median of its three figures; M5's has one figure.
- **Memory**: from the two largest measured sizes of the kind, the slope up to proportional to
  the constraint count. Measured memory grew more slowly than the constraint count, which is why
  each is a range. The prover's slope runs from 5.1 to 9.3 KiB a constraint for the binary tree.

## 9. Reading

- **The membership proof was the cost, and now it is about as large as the signature.** In M11 the
  signatures were 87% of the circuit. With M5's tree and 1,024 sales they are 28.7%. With the
  binary window tree they are 48.6%, with the eight-way tree 58.1%.
- **A wider node buys 37% of the membership proof.** `Poseidon(8)` hashes three bits for 402
  constraints, against 720 for three `Poseidon(2)`. The price is proof size for the seller (1,344 B
  against 544 B).
- **Power 23 is out of reach for this design.** The eight-way tree at 8,618,310 constraints is
  229,702 over 2^23. M11's circuit takes 5,756,001 of the 8,388,608, which leaves 2,570 a slot for
  membership and order; the eight-way slot with its order check is 2,795.
- **The next lever is the shared top of the tree.** Sorted positions mean the sold leaves'
  paths share their upper nodes. At 1,024 sales the top ten levels of a 17-level path cost
  10 × 242 × 1,024 = 2.48 M constraints in this circuit, 24% of the total, *est.* A circuit that
  hashes those levels once would save less than that, because each slot still has to select its
  node from the shared top. It was not designed here.
- **The distinctness check is new, not paid for by M5's design.** M5's tree accepts a repeated
  output in two sale slots (`valid_duplicate_output_two_slots` above). The window tree refuses it
  for 19 or 20 constraints a slot.
- **Only the hash goes on chain.** As in M11 and M3, the verifier side sees one public input. The
  committee needs the 5 + 4B values of the statement before it presigns.

## 10. Not run, not covered

- **1,024 sales** are estimated only (section 8).
- **M5's tree at 64×8** has no compiled count: its compile attempts reached 5.5 GiB and ended in
  circom's clock panic, and 5.5 GiB is above this VM's budget for the step. Its count is the sum of
  the compiled parts, exact at the eight circuits that did compile. It was not set up or proved.
- **Repeats of the M5 proofs** did not run (section 5), and M5's witness times were not taken.
- **BitVM.** No scenario was run on these proofs. The Rust template that recomputes M3's hash
  would take 5 + 4B values and M11's `PoseidonChunked` shape. That is not shown by a run.
- **The registry in motion.** M10's rotation fixture was not repeated. The trees take the registry
  as a map from address to key hash, as in M10, and `test_window_tree.py` checks that the leaves
  carry it.
- **A real node store.** `real_store.py` was not wired to the window tree. The fixtures build it
  from `SharechainUtxo`, the replay `real_store.py` uses, over 201 synthetic blocks. The circuit
  does not depend on the number of leaves, and the one-slot circuit was run against a tree of
  119,953 synthetic leaves.
- **Incremental maintenance** of the window tree, and a proof of its update, are not built.
- **Non-spend after the anchor, the canonical anchor, and the registry's correctness** are as in
  `OWNERSHIP.md` section 7 and `JOINED.md` section 7. The setup is insecure and the keys are
  public demo keys.
- **rapidsnark** was not built, so every prove time is snarkjs.

## 11. Tests, files, reproduce

From the repository root, with python3 (the suites write no bytecode with `-B`):

```sh
python3 -B -m unittest discover -s research/zk_clearing/ownership    # 132: M5's and M10's 99, 33 for the window tree
python3 -B -m unittest discover -s research/zk_clearing/joinedtree   # 17: the world, every variant's predicted refusal
python3 -B -m unittest discover -s research/zk_clearing/joined       # 17
python3 -B -m unittest discover -s research/zk_clearing/signed       # 5
python3 -B -m unittest discover -s research/zk_clearing/signedtree   # 13
python3 -B -m unittest discover -s research/zk_clearing/scaling      # 4
(cd research/zk_clearing && python3 -B -m unittest discover -s .)    # 45
```

One joined circuit end to end (`<kind>` is `bin`, `r8` or `smt`; `PTAU` is a prepared phase-1 file
of power 20 or more):

```sh
POWER=20 PTAU=/path/to/pot20_final.ptau \
  bash research/zk_clearing/joinedtree/run_size.sh <kind> <sale slots> <buyer slots> /tmp/zkc-joined-tree
```

The parts, compile only, and the production-size trees:

```sh
WHOLE_BIN=688135 WHOLE_R8=583110 \
  bash research/zk_clearing/joinedtree/cost_split.sh 64 8 <node_modules> /tmp/zkc-split-64
python3 research/zk_clearing/ownership/bench_window.py build --radix-bits 1 --write-input /tmp/window-in
python3 research/zk_clearing/ownership/bench_window.py build --radix-bits 3
python3 research/zk_clearing/ownership/bench_window.py build --sparse
```

The circomlibjs fixtures (needs the pinned npm packages):

```sh
node research/zk_clearing/ownership/gen_window_vectors.js <node_modules> research/zk_clearing/ownership/window_vectors.json
node research/zk_clearing/ownership/extract_poseidon_constants.js <node_modules> research/zk_clearing/ownership/poseidon_bn254.json
```

`poseidon_bn254.json` gains the constants for 4 and 8 inputs; those for 2 and 3 are unchanged.

| File | Role |
|---|---|
| `ownership/window_tree.py`, `test_window_tree.py` | The dense tree, its builder from `SharechainUtxo`, and 33 tests against circomlibjs |
| `ownership/window_vectors.json`, `gen_window_vectors.js` | circomlibjs's Poseidon and trees |
| `ownership/smt.py`, `poseidon_bn254.json`, `extract_poseidon_constants.js` | `poseidon_n` for 4 and 8 inputs; the constants |
| `ownership/circuits/window_sale.circom` | `WindowSales`; `window_sale_n1`, `_n16`, `_r8_n1`, `_r8_n16` are the standalone mains |
| `ownership/bench_window.py` | The production-size build and its circuit inputs |
| `circuits/clearing_tree_owned.circom` | `OwnedSignedTreeWindow` and `OwnedSignedTreeSmt` |
| `circuits/clearing_tree_signed.circom`, `signedtree/circuits/*`, `signedtree/cost_split.sh`, `signedtree/SIGNED_TREE.md` | The one change, `extraValues` |
| `joinedtree/circuits/owned_tree_{bin,r8,smt}_{16x4,32x8,64x8}.circom` | The mains |
| `joinedtree/make_joined_tree.py`, `sign_tree.js`, `statement_joined_tree.js`, `fixtures.sh` | The world, the signing, the statement hash with the root, the `run.sh` hook |
| `joinedtree/run_size.sh`, `cost_split.sh`, `test_make_joined_tree.py` | The run and its checks, the parts, 17 tests |
| `joinedtree/results/` | Raw outputs of the runs, the splits and the tree builds |
