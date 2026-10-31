# M5: sharechain ownership

Measured 2026-11-01 on `zk-clearing-m5` (from `zk-clearing-roadmap` at `6778e29e`). The code
references are to this repository at that commit.

- **Machine:** AMD Ryzen AI 9 365, WSL2 Ubuntu 24.04, shared with other jobs while these runs
  went, so wall-clock times are upper bounds.
- **Toolchain:** circom 2.2.2, Node 22.12.0, snarkjs 0.7.5, circomlib 2.0.5 and circomlibjs
  0.1.7 (pinned by `../groth16/package-lock.json`), CPython 3.12.
- **Setup: INSECURE.** One deterministic beacon contribution, as in `../groth16/run.sh`. Anyone
  can forge proofs against these keys. The runs measure circuits and test constraints.

Numbers marked *est.* are arithmetic on measurements, not runs. Everything else was run.

## What this milestone answers

The roadmap asks for a proof that each sold `saleId` is an unspent sharechain output owned by the
seller's `miner_address`, without changing P2Poolv2 consensus. Three results:

1. **A membership proof against a published root is cheap to build and exact to check.** The
   tree is a Poseidon sparse Merkle tree whose roots equal circomlibjs's after every operation
   and whose proofs circomlib's `SMTVerifier` accepts. One membership proof costs 11,438
   constraints at 40 levels, of which 247 per level and 1,558 fixed. Sixteen cost 183,008. The
   v1 circuit plus sixteen is 192,012 constraints, *est.* The on-chain verifier is unchanged
   apart from one more public input.
2. **The root says what was true at an anchor. It cannot say what stays true.** A seller can
   spend the output after the anchor. No root, however built, rules that out. The closing
   measure is a sharechain-side lock of each sold output before the Bitcoin payout (section 7).
3. **A wrong root cannot be disproved inside BitVM.** BitVM disproves a failed proof
   verification, not a false statement about another chain. A wrong root is caught when watchers
   refuse to presign the batch graph (section 7). The roadmap carries that
   as a trust assumption.

## 1. The sharechain UTXO set, from the code

P2Poolv2 keeps no UTXO set. `transaction_store.rs:588` says so (the `SpendsIndex` is used
"instead of an UTXO set"), and `store-schema.md` §9b says the index "replaces the old
`UnspentOutputs` set". The set below is derived from the rules the node enforces.

### 1.1 What creates outputs

| Source | Outputs | Where |
|---|---|---|
| Share coinbase, the first transaction of every share block | vout 0: one share, `SHARE_VALUE` = 1 BTC = 100,000,000 units, paid to the P2TR script of the header's `miner_address`. vout 1: a zero-value BIP141 witness-commitment `OP_RETURN` | `shares/transactions/coinbase.rs:14`, `:61-93`, `:97-109` |
| Share transaction, any other transaction in the block | Any outputs. Validation requires at least one output, values within `MAX_MONEY`, scripts that pass `bitcoinconsensus::verify` against the spent outputs, and inputs worth at least the outputs. Nothing sets a dust floor or a fee | `shares/validation/mod.rs:637-666`, `:708-739`, `:743-775`, `:809-864` |

- **The coinbase is a function of the header.** `validate_body_matches_header` rebuilds it from
  `miner_address`, the bitcoin header's hash and the witness root, and rejects any other
  (`shares/validation/mod.rs:1087-1096`). Its input script carries the weak block hash, so its
  txid is unique per share (`coinbase.rs:78-85`).
- **`miner_address` must be P2TR.** `validate_miner_address` (`validation/mod.rs:878-887`, called
  at `:1149` and `:1202`) requires witness version 1 with a 32-byte program. A share address is
  that program in bech32m (`docs/architecture/address-format.md`).
- **Today the set is the coinbase outputs only.** The share builder passes an empty list of
  other transactions (`shares/handle_stratum_share.rs:36-39`, where a comment marks collecting
  share-chain transactions as unwritten), and `pruning.md:499` says share transactions "do not
  exist yet". The validation and storage paths for them are in place.
- **Every stored block writes its outputs**, forks and uncles included. `add_sharechain_txs`
  writes one `Outputs` row per output, `{txid}:{vout}` to `StoredTxOut { tx_out, is_coinbase,
  coinbase_root_height }` (`store/transaction_store.rs:45-55`, `:476-524`). A row is not set
  membership: a spend also needs its source transaction in a confirmed block
  (`transaction_store.rs:407-439`, called from `:1102-1133`). An uncle's coinbase outputs are
  therefore never spendable.
- **`coinbase_root_height`.** A coinbase output gets its block's height
  (`transaction_store.rs:504-509`). Any other output gets the minimum over its inputs
  (`:531-563`). It is the height of the oldest coinbase in the output's ancestry. In this
  document it is the output's *root height*.

### 1.2 What spends them, and when they expire

Let `h` be the height of the spending block (parent height + 1,
`shares/validation/mod.rs:1405-1419`). `COINBASE_MATURITY` is 6,048, `PPLNS_WINDOW_SHARES`
120,960 and `PAYOUT_DEPTH` 127,008 (`accounting/payout/sharechain_pplns/pplns_window.rs:53`,
`:40`, `:62`).

| Rule | Condition | Where |
|---|---|---|
| Exists | an `Outputs` row for the outpoint | `transaction_store.rs:299-304` |
| Not expired | `root_height >= h - PAYOUT_DEPTH` (saturating) | `validation/mod.rs:1420`; `transaction_store.rs:308-316` |
| Mature | a coinbase output needs `h - root_height >= COINBASE_MATURITY`. Other outputs have no maturity rule | `transaction_store.rs:317-325` |
| Unspent on the confirmed branch | no `SpendsIndex` row. `SpendsIndex` is written for the non-coinbase inputs of confirmed blocks and cleared on reorg-out. Checked again when a block is confirmed | `transaction_store.rs:337-381`, `:634-672`, `:1102-1133`; `store/organise/confirmed.rs:376-394` |
| Source confirmed | each input's source txid is in a confirmed block or earlier in the same block | `transaction_store.rs:407-439` |
| No double spend inside a block | one outpoint, one input | `shares/share_block/share_transaction.rs:84-115` |
| Scripts, values, sigops | `bitcoinconsensus::verify`; inputs >= outputs; sigop budget | `validation/mod.rs:637-775` |

The expiry test is pinned by `test_validate_prevouts_expires_coinbase_roots_below_payout_depth`
(`validation/mod.rs:3845`). A spend never changes an output: it removes the outpoint and creates
new ones, each with the oldest root among the inputs. Spending the share at root `r` into a new
output keeps that output's expiry at `r + PAYOUT_DEPTH`.

**What this means for a window of roots.** A non-coinbase output exists only after its coinbase
ancestor was spent, which is at least `COINBASE_MATURITY` blocks after the root. So every
non-coinbase output has `root_height <= h - COINBASE_MATURITY` for any block that can spend it,
and the maturity rule only ever excludes immature coinbase outputs. An output is spendable by a
block at height `H` exactly when it is unspent and

    H - PAYOUT_DEPTH  <=  root_height  <=  H - COINBASE_MATURITY

a window of 120,961 root heights, which is `PPLNS_WINDOW_SHARES + 1`.

### 1.3 What a share header commits to

It commits to the block's transactions and to nothing about state.

- **Header fields** (`shares/share_block/mod.rs:59-106`): `prev_share_blockhash`, `uncles`,
  `miner_bitcoin_address`, `miner_address`, `bitcoin_header`, `bits`, `time`, donation and fee,
  `bitcoin_height`, and `coinbase_proof`. No field holds a UTXO root, a spend set or any other
  state root.
- **The proof of work binds them through the commitment.** `ShareCommitment`
  (`shares/share_commitment.rs:31-74`) digests the same fields (`:224-240`). Its hash is the last
  output of the bitcoin coinbase, shown by `CoinbaseProof` against the bitcoin header's merkle
  root (`shares/coinbase_proof.rs:61-83`, `:131-140`).
- **The only transaction commitment is the witness root.** `share_witness_root` is the BIP141
  witness merkle root over the wtxids of the block's non-coinbase transactions, with an all-zero
  leaf for the coinbase (`coinbase.rs:128-140`). The share coinbase follows from it. The
  header's transaction merkle root is computed, not carried (`share_block/mod.rs:412-425`).
- **What a header does prove.** That a transaction, so an output, was created in a block that
  carries proof of work: a merkle path to `share_witness_root`.
- **What it does not.** That the output is unspent, that the block's transactions are valid
  (scripts and values are checked by nodes, not by work, which is the assumevalid trust model of
  `pruning.md:99`), or who owns an output at a height. A light client cannot decide any of these.

### 1.4 The accumulator set

The set a published root commits to, for an anchor block `A` of height `h` on the confirmed chain:

1. the output's transaction is in a block on the chain ending at `A`;
2. no transaction in a block on that chain spends it;
3. its script is P2TR, so it has a share address; anything else, such as the coinbase
   `OP_RETURN`, is not a leaf;
4. `units >= min_units`, a dust floor that is a policy of the accumulator, not a consensus rule
   (0 in the base case, section 3.4);
5. `h + 1 - PAYOUT_DEPTH + M <= root_height <= h + 1 - COINBASE_MATURITY`, with the expiry
   margin `M` = 1,008 shares (2.8 hours at the 10 s target). The upper bound drops immature
   coinbase outputs. The lower bound drops outputs about to expire, so every leaf stays
   spendable for `M` more blocks after the anchor;
6. no *older* output meeting 1 to 5 has the same low 39 key bits. The oldest by
   `(block height, transaction index, vout)` keeps the slot. This bounds leaf depth at 39 (see
   section 3.2).

Leaf encoding, shared with the v1 circuit's identities (`witness.py` `field_id`):

    key   = field_id("share_outpoint", "<txid>:<vout>")            txid in display form, as outpoint_key
    value = Poseidon(field_id("seller_share_address", <share address>), units, root_height)
    leaf  = Poseidon(key, value, 1)         branch = Poseidon(left, right)         empty = 0

`units` is the output value in satoshis (100,000,000 for a coinbase output). The key is the same
`saleId` the committed v1 circuit hashes, and the owner is its `sellerId`.

The files:

| File | Role |
|---|---|
| `utxo_set.py` | The rules of 1.1 and 1.2 as code (`SharechainUtxo`), the definition of 1.4 as a pure function (`snapshot`), and an incremental `Accumulator`. `test_utxo_set.py` checks that the incremental tree equals the snapshot after every block of random workloads, including workloads where most outputs collide on a slot |
| `smt.py` | Poseidon, the sparse Merkle tree, membership and exclusion proofs, the identities, and a share-address encoder. `test_smt.py` replays circomlibjs's own operation sequence and compares every root and proof |
| `circuits/owned_sale.circom` | The ownership circuit (section 4) |
| `bench_smt.py`, `gen_inputs.py`, `run.sh` | The measurements, the circuit inputs, and the end-to-end circuit run |

**Reading a node's store.** Everything the accumulator needs is inside the retention window
`PRUNE_DEPTH`. An in-window output has `root_height >= h + 1 - PAYOUT_DEPTH` and was created at
or after its root, so it sits in a block less than `PAYOUT_DEPTH` below the tip. The rows are
`Outputs` (`StoredTxOut` carries the value, script, `is_coinbase` and root height), the confirmed
`BlockHeight` entries, `BlockTxids`, and the transactions' inputs for spends at an earlier
anchor. `SpendsIndex` alone answers only "spent at the tip", because it stores no spending
height. `utxo_set.py` replays blocks, which is the same data.

## 2. The tree, and how it matches circomlib

- **Hashing.** `leaf = Poseidon(key, value, 1)` (three inputs), `branch = Poseidon(left, right)`,
  empty = 0, as in circomlib's `smthash_poseidon.circom`. A path is the key's bits least
  significant first. A subtree holding one leaf is that leaf, so the shape depends on the key set
  and not on insertion order. A branch with an empty child still hashes it as 0.
- **Poseidon.** `poseidon_bn254.json` holds the round constants and MDS matrices for 2 and 3
  inputs, extracted from the pinned circomlibjs by `extract_poseidon_constants.js`.
  `poseidon_reference` follows `poseidon_reference.js`. The unrolled `poseidon2` and `poseidon3`
  are what the tree uses and are tested against the reference.
- **Parity with circomlibjs.** `circomlibjs_vectors.json`, written by `gen_vectors.js`, holds nine
  Poseidon outputs and a scripted sequence of 57 operations on circomlibjs's own SMT: 50 inserts
  (random keys, pairs sharing 1, 7, 20 and 33 low bits, the key 0 and the key `r - 1`), 2
  updates and 5 deletes. All 57 roots after each operation equal ours. The 45 membership proofs
  and 8 exclusion proofs from circomlibjs's `find` equal ours, including exclusion proofs that end
  in an empty slot and ones that end on another leaf.
- **Parity with the circuit.** circom's `SMTVerifier` accepts proofs built by `smt.py`, including a
  leaf at depth 39 (section 4.4).
- **Speed.** CPython: 432 µs per two-input hash and 602 µs per three-input hash (this machine,
  loaded). circomlibjs's wasm Poseidon on Node 22: 87 µs and 112 µs.

## 3. Measurements on a synthetic workload

### 3.1 Assumptions

Every number in 3.2 to 3.4 rests on these.

| Assumption | Value |
|---|---|
| Consensus constants | `COINBASE_MATURITY` 6,048; `PAYOUT_DEPTH` 127,008; 10 s share target, so 8,640 shares a day |
| Accumulator | expiry margin 1,008; dust floor 0; P2TR outputs only; slot cap 39 (40 levels); window of 119,953 root heights |
| Per share | one coinbase, whose vout 0 is a leaf from maturity on. The `OP_RETURN` is not a leaf |
| History before the measured blocks | 135,057 blocks (heights 0 to 135,056), 200 synthetic owners. The window is full and the oldest roots have already left, so the live set starts at 119,953 |
| Keys | SHA-256 field ids of the outpoint strings, so keys are uniform. No adversary |
| Transfers | each is one transaction that spends a random unspent tracked output in the window and creates `c` outputs to random owners, splitting the units equally |
| "Today" | 0 transfers per share. This is what the node builds now (1.1) |
| "1 per share" | 1 transfer per share with `c` = 1, so each output is transferred about once in its 14-day life |
| "4 per share" | 4 transfers per share with `c` = 2, so each output is split about 4 times and the set grows |
| Measured blocks | 600 per scenario. After each block the watcher's `root` is computed, as it would be for publication |
| Machine | CPython 3.12, one core, shared with other jobs. Hash counts do not depend on the machine |
| Limits that cap a worst case | 99 non-coinbase transactions and 200 KiB per share block (`validation/mod.rs:169-171`) |

### 3.2 Tree depth

**Leaf depth.** In a tree of random keys the mean leaf depth is `log2 n + 1.33`, and the deepest
leaf is about `2 log2 n`. Measured by 60 random trees per size (the depth is computed from key
order; `test_smt.py` checks that against real trees):

| Leaves | `log2 n` | Mean leaf depth | Deepest leaf: min / median / max |
|---|---|---|---|
| 16,384 | 14.0 | 15.33 | 25 / 28 / 40 |
| 119,953 (today) | 16.9 | 18.20 | 31 / 34 / 38 |
| 179,929 | 17.5 | 18.79 | 32 / 35 / 43 |
| 359,859 | 18.5 | 19.79 | 34 / 37 / 42 |
| 1,048,576 | 20.0 | 21.33 | 38 / 40 / 45 |

The accumulated tree after the 600 measured blocks (119,953 leaves, "today") has mean leaf depth
18.2 and deepest leaf 34. Sampled proofs carry 18.25 siblings on average (99th percentile 24,
maximum 29).

**Depth the circuit needs.** `SMTVerifier` pays for every level whatever the leaf's depth, so the
circuit width is set by the deepest leaf, not the mean. One more than the deepest leaf is the
number of levels. A typical 120,000-leaf snapshot has its deepest leaf at 31 to 38, and the
chance of a deeper one falls by half per extra level. Rule 6 of 1.4 turns that tail into a
policy: two live outputs that share their low `max_depth` bits cannot both be leaves, and the
older keeps the slot. This table is arithmetic (*est.*), not a run:

| Levels | `max_depth` | Conflicts a year, today | Live outputs without a slot, today | Conflicts a year, 3x live set | Grinding cost to force one |
|---|---|---|---|---|---|
| 32 | 31 | 176 | 2.8e-5 (about 3 of 120,000) | 1,585 | 2^31 SHA-256 |
| 36 | 35 | 11 | 1.8e-6 | 99 | 2^35 |
| **40** | **39** | **0.69** | **1.1e-7** | **6.2** | **2^39** |
| 44 | 43 | 0.043 | 6.8e-9 | 0.39 | 2^43 |

"3x live set" is 359,859 live outputs and 3 new tracked outputs per share. A conflict leaves one
output out of the batch path until the older one is spent or expires, at most 14 days; its owner
can re-spend it to a new outpoint at once. Forcing a conflict on a chosen output needs a
colliding outpoint created before the victim's, which is only possible within the interval
between the victim's transaction being public and its confirmation. It denies one output the
batch path and costs the attacker about 2^39 hashes inside that interval. It cannot take an
output or its value.

**Decision.** 40 levels, a leaf depth of at most 39. Each level costs 247 constraints, so 32 levels
would save 1,976 constraints per proof (17%) at the price of a conflict every other day.

### 3.3 Cost per share, proof size

Measured by `bench_smt.py cost` at production parameters, 600 blocks per scenario. A share's
update is the insert of one leaf (the coinbase output that has just matured), the removal of one
leaf (the oldest root leaving), and a delete and `c` inserts per transfer.

| Scenario | Leaves | Tree edits per share | Poseidon2 | Poseidon3 | Python per share, mean / p99 |
|---|---|---|---|---|---|
| Today, no transfers | 119,953 | 2 | 32.9 | 2.0 | 15.0 / 24.1 ms |
| 1 whole-share transfer per share | 119,953 | 4 | 61.8 | 4.0 | 26.2 / 33.5 ms |
| 4 splits per share | 119,953 to 122,347 after 600 blocks | 14 | 195.7 | 18.0 | 96.8 / 122.9 ms |

- **One edit.** An insert is one Poseidon3 for the leaf value, one for the leaf hash, and about 16
  Poseidon2 up its path. A delete is about 16 Poseidon2. Hashes are deferred until the root is
  read, so a block hashes each dirty node once, which is why a block of 14 edits costs 14
  Poseidon2 per edit instead of 16.
- **Budget.** A share arrives every 10 s. Today's 35 hashes are 15 ms in CPython, 0.15% of a core.
  With circomlibjs's wasm Poseidon (87 and 112 µs) they are about 3 ms, *est.*
- **Steady state of the splitting scenario.** The measured set had not settled. If transfers pick
  leaves at random, the set settles at `t(c-1) / ln(1 + t(c-1))` times the window, which is 2.49
  for `t(c-1)` = 4: about 298,000 leaves, *est.* A tree that size has a mean leaf depth of about
  19.5 and a deepest leaf near 37.
- **Building from scratch.** The 119,953-leaf tree takes 172,962 Poseidon2 and 239,906 Poseidon3
  (the value and the leaf hash per leaf), 412,868 hashes, 3.44 per leaf. In CPython: 86 s to
  replay 135,057 blocks, which includes the value hashes, and 142 s to hash the tree. With the
  wasm Poseidon that is about 41 s, *est.*
- **Membership proof size.** Mean 18.25 siblings, 584 bytes at 32 bytes each (555 bytes with a
  bitmap for the zero siblings). The circuit takes a fixed 40 siblings, 1,280 bytes, plus the
  leaf's `units` and `root_height`, as private inputs.

### 3.4 Set size under load, and the dust floor

Consensus bounds the set only through the block limits. A share block holds at most 99
non-coinbase transactions and 200 KiB, which is at most about 4,700 P2TR outputs of 43 bytes
(*est.*). Anyone who mines shares can include such a block, and nothing sets a dust floor
(`validate_transactions`, `validation/mod.rs:809-864`). A miner with 1% of the pool's shares
could add about 5.6 million leaves over the window, *est.* (`0.01 x 119,953 x 4,700`). Depth
barely moves (about 22 mean, under the 39 cap), but the update for one such block is about
100,000 hashes, about 10 s of wasm Poseidon, *est.*, which is a full core for a watcher.

`min_units` bounds it. Transactions never create value (inputs are at least outputs,
`validation/mod.rs:769`), so the live units are at most 100,000,000 times the coinbase outputs in
the window, and the leaves at most that divided by `min_units`:

| `min_units` | Most leaves, *est.* |
|---|---|
| 0 (off) | bounded only by the block limits |
| 1,000,000 (1% of a share) | 12.1 million |
| 10,000,000 (10%) | 1.2 million |

`test_utxo_set.py` covers the floor. The value is a watcher policy, and a sale of a smaller
output is out of the batch path.

## 4. The ownership circuit

### 4.1 Statement

`circuits/owned_sale.circom` defines `OwnedSale(nLevels)` and `OwnedSales(slots, nLevels)`. For
each active slot `s` it proves, with circomlib's `SMTVerifier` in inclusion mode:

    tree(utxoRoot)[ saleId[s] ] = Poseidon( sellerId[s], units[s], rootHeight[s] )

`saleId` and `sellerId` are the field ids that `accounting16x4_committed.circom` hashes into its
`saleCommitment`, so a combined circuit wires them straight across. `units` and `rootHeight` are
private. The tree fixes them, so a prover cannot pick them. A padding slot (`activeSale` 0) must
name nothing and its membership check is off.

`owned_sale_n1.circom` and `owned_sale_n16.circom` are the mains, at 40 levels. Public inputs are
`utxoRoot`, `activeSale`, `saleId` and `sellerId`, which gives 4 for one slot and 49 for sixteen.
Private inputs are `units`, `rootHeight` and 40 siblings per slot, 42 for one slot and 672 for
sixteen.

### 4.2 Constraints

Measured, circom 2.2.2 with `--O2`. One slot against the number of levels:

| Levels | 8 | 16 | 24 | 32 | **40** | 48 |
|---|---|---|---|---|---|---|
| Constraints | 3,534 | 5,510 | 7,486 | 9,462 | **11,438** | 13,414 |

The two mains:

| Circuit | Constraints | Wires | Public / private inputs | Compile |
|---|---|---|---|---|
| `owned_sale_n1` (1 slot, 40 levels) | 11,438 | 11,473 | 4 / 42 | 7.7 s, 310 MiB |
| `owned_sale_n16` (16 slots, 40 levels) | 183,008 | 183,538 | 49 / 672 | 37 s, 1.0 GiB |

That is 1,558 fixed plus 247 per level, and sixteen slots cost exactly sixteen times one. The
parts, compiled alone: `Poseidon(2)` 240, `Poseidon(3)` 261, `Num2Bits_strict` 515. A level is one
`Poseidon(2)` plus 7 constraints of path logic. The fixed part is two `Poseidon(3)` (the stored
value and the leaf hash, 522), two `Num2Bits_strict` (the key and the verifier's old-key input,
1,030) and 6 of slot checks.

### 4.3 Proving one slot

`run.sh` runs the one-slot circuit through an insecure deterministic Groth16 setup (power 14):

| | `OwnedSales(1, 40)` |
|---|---|
| Phase 1 (new, beacon, prepare) | 138 s, 490 MiB |
| Phase 2 (setup, beacon) | 43 s, 509 MiB |
| Proving key | 6,827,214 B |
| Verifying key | 3,477 B JSON; sha256 `01b27a5b…dbfecb97b`, identical in two runs |
| Prove (snarkjs CLI) | 2.2 s, 772 MiB (3.0 s in an earlier run) |
| Verify (snarkjs CLI) | 1.3 s, 307 MiB |
| Proof | 256 B, 4 public signals |

These ran on a machine shared with other proving jobs, so the times are upper bounds. The phase 1
and 2 times are long for a 2^14 setup for the same reason. The sixteen-slot circuit is compiled
and its witnesses are checked, but it is not proved.

### 4.4 What was checked

Valid witnesses are satisfied by the R1CS (`snarkjs wtns check`); each invalid input is refused by
the witness calculator at the constraint named.

| Input | Result | Rejected at |
|---|---|---|
| A typical leaf | accepted | |
| The deepest leaf, depth 39 | accepted, and proves and verifies | |
| A padding slot | accepted | |
| Wrong owner (`sellerId` of another seller) | rejected | root check, `ForceEqualIfEnabled` |
| Wrong `units`, wrong `rootHeight` | rejected | root check |
| Wrong `saleId` for the siblings | rejected | root check |
| Non-member, siblings from circomlibjs's exclusion proof | rejected | root check |
| Non-member claiming a member's path | rejected | root check |
| A tampered sibling, or a wrong `utxoRoot` | rejected | root check |
| An output spent since the root (proof against the root after the spend) | rejected | root check |
| A leaf at depth 40, one level too deep | rejected | `SMTLevIns`, last sibling non-zero |
| A padding slot that names an output | rejected | `OwnedSale`, padding rule |
| `activeSale` = 2 | rejected | `OwnedSale`, boolean rule |
| Sixteen slots: wrong owner in slot 9, non-member in slot 3, padding slot 15 naming an output | each rejected | as above |

After proving: a `utxoRoot` or a `sellerId` public signal changed by one does not verify; a
signal written as `x + r` is rejected by snarkjs; a forged witness fails the R1CS check at
constraint 270, and the proof made from it does not verify. The spent-output row is the freshness
boundary: a proof for the root before a spend does not verify against the root after it, so a
proof is as fresh as the root it names.

### 4.5 What the circuit does not do

- It does not know the anchor `A`, or that `utxoRoot` is `root(T(A))` (7.2).
- It says nothing about the output after the anchor (7.3).
- It does not check that the seller authorised the sale, or tie `units` to the price or to a
  seller payout script. Those are M4.
- It does not check that two slots name different outputs (7.3).

## 5. The v1 circuit plus sixteen membership proofs

| | Constraints | Public inputs | Basis |
|---|---|---|---|
| v1 `accounting16x4_committed` | 9,004 | 17 in, 1 out | measured, `GROTH16.md` |
| 16 membership proofs at 40 levels | 183,008 | 49 on their own; 1 more (`utxoRoot`) in a combined circuit | measured |
| Combined | about 192,000 | 19 | *est.*: the sum. `saleId` and `sellerId` are shared signals, so the join adds no constraints |
| Powers of tau | 2^18 (262,144) | | *est.*. 2^17 is too small |

- **Prover.** About 21 times v1's constraints. At v1's measured rate (0.85 s for 9,004 constraints)
  that is about 18 s. At this run's rate on a shared machine (2.2 s for 11,438) it is about 36 s,
  *est.* The proving key is about 115 to 225 MB at the two measured sizes per constraint
  (0.6 KB here, 1.2 KB for v1), *est.*
- **On Bitcoin.** The Groth16 verifier's cost does not depend on the constraint count. It depends
  on the number of public inputs. M1 measured about 4 hashed intermediates and about 10 MB of
  disprove leaves per public input (68 and 175 MB for 17 more). One more input costs about 4 and
  about 10 MB, *est.*, and zero if the root is folded into M3's single statement hash. The
  ownership proof is a prover-side cost, not a chain-side one.
- **The ratio.** Ownership is 95% of the combined constraints. The clearing arithmetic is small
  next to it, so batch size in M6 is set by membership, not by the sale arithmetic.

## 6. Where the cost goes, and what trims it

All *est.* except the compiled Poseidon sizes. None is built.

| Change | Per proof | 16 proofs | Cost |
|---|---|---|---|
| Today, circomlib `SMTVerifier`, 40 levels | 11,438 | 183,008 | |
| A purpose-built inclusion verifier: no old-leaf inputs, and the key as 253 bits without the alias check (`saleId` is below 2^253 by construction) | about 10,660 (-777) | about 170,600 | a new template; the tree and the proofs are unchanged |
| 32 levels | 9,462 (-1,976) | 151,400 | a conflict every other day (3.2) |
| An 8-ary tree: 14 levels of `Poseidon(8)` (402) plus selection | about 6,700 | about 107,000 | new tree, new verifier, new watcher code; 98 siblings per proof |

A level costs 240 of the 247 constraints for its hash. Hashing wider nodes spends less per bit of
depth: `Poseidon(2)` is 240 per bit, `Poseidon(4)` 297 for two bits (149 per bit), `Poseidon(8)` 402
for three (134), `Poseidon(16)` 609 for four (152). The radix-8 row assumes about 16 constraints
for selecting the child.

## 7. Freshness and non-spend

### 7.1 What the root anchors

A batch statement carries `(A, h_A, R)`: an anchor block hash on the confirmed chain, its height,
and `R = root(T(A))`, the root of the set defined in 1.4. The circuit takes `R` as a public input
and proves membership against it. It never sees `A`. The link from `A` to `R` is a claim by
whoever published `R`, and the link from `R` to the sale list is the proof.

### 7.2 Who builds the root

- **Watchers.** Anyone running a P2Poolv2 node can run the `Accumulator`: apply each confirmed
  block, read `root`, publish `(A, h_A, R, leaf count)`. It needs the public sharechain data a
  node already holds and no consensus change, new P2P message or new column family. Per share
  it costs the figures in 3.3.
- **Agreement is the check.** `T(A)` is a pure function of the chain, so two honest watchers
  with the same `A` compute the same `R`. `test_utxo_set.py` checks that the incremental
  accumulator equals the from-scratch snapshot after every block. A published root that differs
  from a watcher's own is a wrong root.
- **Serving proofs.** A watcher answers "give me the siblings for this outpoint" from its tree.
  The seller needs the siblings, its own `units` and `root_height` (both visible in the
  `Outputs` row), and nothing secret.

### 7.3 What is fresh and what is not

| Fact | Fresh? |
|---|---|
| The outpoint existed and was unspent at `A` | Yes: the root encodes every spend up to `A` |
| It will still be spendable when the sale executes | Against expiry, yes for `M` = 1,008 blocks after `A`: every leaf has `root_height >= h_A + 1 - PAYOUT_DEPTH + M` (1.4) |
| It is still unspent when the sale executes | **No.** Nothing after `A` is in the root |
| The seller authorised this sale | No. A signature over the order is M4 |
| The same outpoint is sold once in the batch | No. Two slots can carry the same `saleId`. v1 does not check it either (the "Replay" row of `GROTH16.md`). Strictly increasing `saleId` across slots would cost about 16 range comparisons of 253 bits, about 4,000 constraints, *est.* |

The gap is a race. Between `A` and delivery the seller can spend the output to another address,
and doing so costs one share transaction. A buyer who pays against the root alone can end up with
no share.

### 7.4 Closing the gap

In order of preference. None is built here.

1. **Lock before payout.** Each sold output is first moved on the sharechain into a lock output
   (taproot, claimable by the batch's buyer with a secret that the Bitcoin payout reveals, and
   refundable to the seller after a timeout, as `docs/atomic-swap/htlc_scripts.md` lays out).
   The statement then proves the *lock* outpoint is in the set at an anchor at least `k` blocks
   after the lock confirmed, with the lock key as `sellerId`. The seller cannot spend a locked
   output except by the refund path after the timeout, so non-spend after the anchor becomes a
   property of the lock script, not of the root. It costs one sharechain transaction per sale. A
   share block carries up to 99 non-coinbase transactions (`TXS_COUNT_LIMIT` = 100,
   `validation/mod.rs:171`), about 855,000 a day at the 10 s target, against the 10,000 offers of
   the M7 workload.
2. **A seller bond** in the escrow graph, forfeited when the sale does not deliver. This prices
   the race and does not close it.
3. **A fresh check at settlement.** The committee reads the outpoint's status at the tip just
   before releasing the payout. This is a trusted read.

### 7.5 A wrong root and BitVM

BitVM2 can disprove one thing: that a Groth16 proof fails to verify for the public inputs it was
asserted with. The operator can assert a root that is not `root(T(A))` together with a perfectly
valid proof of membership in it. The verifier accepts, and no Bitcoin script can recompute `T(A)`
because the sharechain is not on Bitcoin. The 127,008 headers alone would be 127 MB at the
stored size of about 1 KB each (`pruning.md`), and validity of share transactions is checked by
nodes, not by work (1.3).

So a wrong root is not challengeable in BitVM. It is stopped before funds move:

| Failure | Caught by | When |
|---|---|---|
| The proof does not verify for the asserted public inputs | any challenger, BitVM disprove (M1) | after kickoff |
| The root differs from `root(T(A))`: a leaf for an output the seller does not own, or a spent one | each watcher on the committee compares the root with its own | before the committee presigns the batch graph |
| The anchor `A` is not on the canonical chain | the same comparison | before presigning, and again at settlement (7.4, item 3) |
| An output is spent after `A` | the lock (7.4, item 1) | when the lock confirms |

This adds a duty to the committee beyond BitVM2's usual assumption that one member is honest: that
member must also run a sharechain watcher and refuse to sign a root it does not reproduce. The
committee is not yet real (M8), so this is a named dependency. Two steps would shrink it, neither
cheap:

- **Prove the update.** A recursive or folding proof of the tree update over the retained blocks
  would make `R` a proven function of the blocks. Per share the update is about 35 Poseidon
  evaluations, or about 8,400 constraints (32.9 x 240 + 2 x 261), *est.* That removes
  the watcher's arithmetic from the trust base. The tree update still takes the blocks'
  validity on trust, because script and value checks (`bitcoinconsensus`) are far beyond a
  circuit.
- **Commit the root in headers** (section 8).

## 8. The alternative: a UTXO commitment in share headers

It is a consensus change, so it is out of scope here and is recorded as a design option.

- **What it is.** A 32-byte `utxo_root` in `ShareCommitment` (`share_commitment.rs:31-74`) and
  `ShareHeader`, digested by `commitment_digest` (`:168-197`), with validators recomputing the
  root after each block and rejecting a mismatch.
- **What it buys.** `R` becomes bound to the proof of work, so a membership proof needs only
  headers, and "wrong root" turns into an invalid-header question that every node already
  decides. The watcher trust of 7.5 drops to the assumevalid-style trust of the chain itself.
- **What it costs.** Every node maintains the tree: about the per-share work in 3.3, and a
  tree of about 240,000 nodes at 64 bytes each, about 15 MB, *est.* Old headers do not carry the
  field, so it is a fork of the share chain, and the commitment layout is hashed into the
  bitcoin coinbase of every share.
- **Order.** The roadmap's rule stands: upstream sees this only after M2 to M4 show the proof
  has a job. Section 5 shows what the proof costs; section 7 shows what it still cannot do
  without the commitment.

## 9. The reorg window

- **Which chain.** The accumulator follows the confirmed chain, the branch with the most work
  that passed validation. `SpendsIndex` is written only for confirmed blocks and cleared on
  reorg-out (`confirmed.rs:324`). A fork that outweighs the confirmed chain replaces it from the
  fork point (`confirmed.rs:186-260`), and its blocks are re-checked against the spends the
  reorg produces.
- **How deep reorgs go.** Routine forks are uncles, at most `MAX_UNCLES_DEPTH` = 3 deep
  (`store/dag_store.rs:19`). The node refuses a reorg whose fork point is below the prune target,
  about 29.4 days, and `pruning.md:506` says the limit must tighten to about
  `PAYOUT_DEPTH + PRUNE_INTERVAL`, about 14.7 days, once share transactions exist. The chain
  therefore tolerates reorgs far deeper than an anchor policy accepts.
- **Anchor depth.** A root for an anchor on a branch that loses is void, and an output the seller
  spent only on the winning branch shows as unspent in the old root. Policy: build the batch
  against an anchor at least `k` blocks below the confirmed tip, and for the lock design require
  the lock transaction `k` deep. For an attacker with share `q` < 1/2 of the pool's work, the
  chance of undoing a block `k` deep is about `(q/(1-q))^k` (Nakamoto), *est.*: with `k` = 360
  (one hour, `PRUNE_INTERVAL`) it is below 1e-30 at `q` = 0.45. A pool's work is far smaller
  than Bitcoin's, so `q` is a pool-internal share and `k` is a pool-specific choice, not a
  measured one.
- **Cost of a reorg.** Applying or undoing a block is the per-share update of 3.3. A reorg of
  depth `d` costs `d` times that, *est.*: for `d` = 360, about 12,600 Poseidon evaluations (35 per
  share), about 1.3 s with circomlibjs's wasm Poseidon. The watcher keeps the last `d` blocks' deltas or
  rebuilds from the fork point with `SharechainUtxo`.
- **After presigning.** A batch graph is presigned for one `R`. If its anchor reorgs out after
  that, the batch is no worse off than the non-spend race of 7.3, which the lock closes once the
  lock transaction is `k` deep.

## 10. Reproduce

The raw outputs behind the tables are in `results/`: `cost.json` (3.3), `depth.txt` (3.2),
`conflicts.json` (3.2) and `circuit-run.txt` (section 4).

```sh
# unit tests (pure Python, about 4 s)
python3 -m unittest discover -s research/zk_clearing/ownership

# workload measurements (about 15 minutes; --scale 40 for a half-minute smoke run)
python3 research/zk_clearing/ownership/bench_smt.py depth --trials 60
python3 research/zk_clearing/ownership/bench_smt.py cost
python3 research/zk_clearing/ownership/bench_smt.py conflicts

# circuits: compile 1 and 16 slots, valid and invalid witnesses, prove and verify one slot
bash research/zk_clearing/ownership/run.sh /tmp/zkc-ownership

# regenerate the circomlibjs fixtures (needs the pinned npm packages)
node research/zk_clearing/ownership/gen_vectors.js <node_modules> research/zk_clearing/ownership/circomlibjs_vectors.json
node research/zk_clearing/ownership/extract_poseidon_constants.js <node_modules> research/zk_clearing/ownership/poseidon_bn254.json
```
