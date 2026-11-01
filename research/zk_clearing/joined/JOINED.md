# M10: ownership and signatures in one statement

Measured 2026-11-01 on `zk-clearing-m10` (from `zk-clearing-integration` at `9fc8dc96`), on an AMD
Ryzen AI 9 365 under WSL2 Ubuntu 24.04. The machine was shared with two other proving jobs while
these runs went, so wall-clock times are upper bounds. The toolchain is M0's (circom 2.2.2,
snarkjs 0.7.5, circomlib 2.0.5, circomlibjs 0.1.7, Node 22, CPython 3.12). The setup is the
insecure deterministic one from GROTH16.md, on a prepared 2^20 phase-1 file, and the keys are
public demo keys.

Numbers marked *est.* are arithmetic on measurements, not runs. Everything else was run.

## What this milestone answers

M4 checks, inside the circuit, that each sold share carries a valid order signature by a
BabyJubjub key whose hash is the `sellerId`. M5 checks that each sold `saleId` is a leaf of a
sharechain tree whose owner is the `sellerId`. Neither says that the BabyJubjub key has anything to
do with the key that controls the share's `miner_address`. M4 left that to "a registration outside
the circuit"; this milestone builds it and proves both checks in one statement.

1. **A registration binds an order key to a share address.** The key that controls the address
   (a P2TR output key) signs, with BIP340, the hash `Poseidon(Ax, Ay)` of the order key, under a
   domain tag, the network, the address and a sequence number. The highest valid sequence for an
   address wins, which is how a key is rotated. This is checked outside the circuit, by anyone who
   builds the tree (section 2).
2. **The tree stores the registered key hash as the owner.** A leaf whose address registered
   gets `Poseidon(Ax, Ay)` as its owner. Any other leaf keeps M5's address id, which no order key
   hashes to (section 3).
3. **One circuit proves both.** `clearing16x4_owned.circom` instantiates M4's `SignedClearing`
   and M5's `OwnedSales` unchanged and wires them to the same `saleId`, `sellerId` and
   `activeSale`. It has 291,792 constraints, which is M4's plus M5's sixteen proofs, with no
   constraint added by the join (section 4).
4. **The join is enforced.** Ten fixtures run through the witness calculator, and a proof
   verifies. A sale whose signing key is not the registered owner of the sold output is refused in
   the membership check, and so is one that a rotation has made stale (section 5).

## 1. What a proof says

Public inputs: M4's (per-buyer amounts, buyer IDs, batch height) and one more, `utxoRoot`. The
outputs are M4's two commitments.

- **Proven**, for every committed sale:
  - a valid order signature by a BabyJubjub key `K`, for that exact share, price, buyer, payout
    script and expiry (M4);
  - `sellerId = Poseidon(Ax, Ay)` of `K`;
  - the sold output is a leaf of the tree with root `utxoRoot`, and the owner stored in that leaf
    is `sellerId` (M5), together with its `units` and `rootHeight`.
- **So**: the key that signed each order is the key whose hash is stored as the owner of the sold
  output. A registration is what puts that hash there: whoever built the tree decided that the key
  controlling the output's address had registered it.
- **Private**: the orders, the signatures, the keys, and each sold leaf's `units`, `rootHeight`
  and siblings. A verifier learns the root and the totals, not which outputs sold.

What this adds over M4 and M5 proved separately: M4 accepts any key for `sellerId`, and M5 accepts
any `sellerId` that matches a leaf, so two separate proofs could name different keys. The joined
circuit uses one `sellerId` for both checks, so a signature only counts if it is by the key that
the tree names as the owner.

## 2. Registration

`ownership/register.py`. A registration is five fields:

| Field | Meaning |
|---|---|
| `network` | `mainnet`, `testnet4`, `signet` or `regtest` |
| `address` | the share address (`smt.share_address`) whose output key signs |
| `orderKeyHash` | `Poseidon(Ax, Ay)` of the BabyJubjub order key, 32 bytes big-endian |
| `sequence` | unsigned 64-bit integer |
| `signature` | BIP340 Schnorr signature, 64 bytes |

The signed message is a BIP340 tagged hash:

    message  = tagged_hash("p2poolv2/zk-clearing/order-key-registration/v1", preimage)
    preimage = len(network) || network || len(address) || address || key_hash || sequence

with one-byte lengths, ASCII strings, a 32-byte big-endian `key_hash` and an 8-byte big-endian
`sequence`. The signature is verified against the 32-byte x-only key that the address encodes
(`smt.decode_share_address`). In JSON:

```json
{"network":"signet","address":"sp2pool1p…","orderKeyHash":"<64 hex>","sequence":1,"signature":"<128 hex>"}
```

Rules a watcher applies (`Registry`):

- The registration is refused unless the network is known, the address is a lowercase share
  address of that network (witness version 1, 32-byte key, valid bech32m checksum), the key hash
  is a nonzero field element, the sequence fits 64 bits, and the signature verifies.
- A registry is for one network and refuses registrations for another.
- For one address the highest sequence wins. A replay of an older registration changes nothing.
- Two different key hashes at the same highest sequence leave the address unregistered until a
  higher sequence arrives. Only the address's own key can make that. The result does not depend on
  the order in which registrations arrive.
- The signing key is the one whose x-only public key is the address's output key. For a key-path
  P2TR output that is the key that signs spends. A script-path-only output has no such key and
  cannot register.

The BIP340 code follows the BIP's reference implementation and is checked against its test
vectors (four signing vectors reproduced byte for byte, and a fifth verified). It is not
constant-time and is meant for verifying public registrations and for tests.

Replay across networks is closed in two places. The address string carries the network's prefix,
so a registration relabelled `mainnet` fails to parse as a mainnet address. The same output key
re-encoded as a mainnet address fails the signature, because the signed bytes contain the network
and the address as strings.

## 3. The tree with registered owners

`utxo_set.py` takes an optional `registry` (share address to key hash) in `build_tree` and in the
incremental `Accumulator`; `smt.owner_field` picks the owner.

    owner = registry[address]            if the address registered
          = field_id(address)            otherwise (M5's owner id)
    leaf  = Poseidon(saleId, Poseidon(owner, units, rootHeight), 1)

- **Which outputs are in the tree does not depend on the registry.** Only leaf values do. Without
  a registry the tree is M5's, and all of M5's tests pass unchanged.
- **Unregistered outputs are in the tree and cannot be sold through the joined circuit.** Their
  owner is a SHA-256 truncation, and finding an order key whose `Poseidon(Ax, Ay)` equals it is a
  Poseidon preimage problem. A seller registers before the anchor to be able to sell.
- **Rotation is one update per tracked output.** `Accumulator.set_owner_key` rewrites the leaves
  of the address that are in the tree, and the result equals a snapshot built with the new
  registry (`test_registered_owners.py` checks this after every block of random workloads and
  across a rotation).
- **The root is now a function of the sharechain and of the registry.** Two watchers agree on a
  root only if they agree on the registrations they accepted. Registrations are public and
  signed, so the agreement check of M5 section 7.2 becomes: same anchor, same set of valid
  registrations.

## 4. The circuit

`circuits/clearing16x4_owned.circom` includes `signed_clearing.circom` and
`ownership/circuits/owned_sale.circom` and instantiates `SignedClearing(16, 4)` and
`OwnedSales(16, 40)`. The wrapper declares the same inputs, forwards them, and passes
`activeSale`, `saleId` and `sellerId` to both. `utxoRoot` is the last public input, so the public
signals are those of `clearing16x4_signed` followed by it.

**One refactor of M4's file.** circom allows one `main` across a set of includes, and
`clearing16x4_signed.circom` held its templates and its main. The templates moved unchanged to
`circuits/signed_clearing.circom`, and `clearing16x4_signed.circom` is now an include and the
main. The compiled R1CS and symbol file are byte-identical before and after (sha256
`572f5cd5…1cac3a` and `11daa872…a61d2de`), so M4's keys and numbers stand. `signed/sign.js`
likewise exposes its signing kit as a module (`createSigner`), and its eight M4 fixtures are
byte-identical to those of the previous version.

## 5. Results

Reproduce, from the repository root, in WSL (`PTAU` is a prepared phase-1 file of power 19 or
more; this run reused M6's 2^20 file):

```sh
PTAU=/path/to/pot20_final.ptau POWER=20 bash research/zk_clearing/joined/run.sh /tmp/zkc-owned
```

`joined/run.sh` calls `groth16/run.sh` with `FIXTURES=joined/fixtures.sh` and
`COMMIT_JS=signed/commit_signed.js`, then runs the checks that belong to the join. The raw output
is `results/run.txt`.

| | M4 `clearing16x4_signed` | M5 `owned_sale_n16` | M10 `clearing16x4_owned` |
|---|---|---|---|
| Constraints | 108,784 | 183,008 | **291,792** |
| Wires | 108,571 | 183,538 | 292,060 |
| Public inputs + outputs | 18 + 2 | 49 + 0 | 19 + 2 |
| Private inputs | 301 | 672 | 973 |
| Compile | 16.6 s, 1.23 GiB | 37 s, 1.0 GiB | 35.5 s, 1.87 GiB (24.8 s in the first run) |
| Phase 1 | power 17, 491 s | | reused M6's 2^20 file |
| Phase 2 (setup + beacon) | 91.0 s, 1.51 GiB | | 144 s, 2.92 GiB (151 s, 3.09 GiB) |
| Proving key | 78.2 MB | | 195,816,462 B |
| Verifying key sha256 | `74905f3c…9b1af55166` | | `837f9d10…29ced`, identical in both runs |
| Prove (snarkjs) | 10.15 s, 2.22 GiB | not proved | **11.8 s, 4.09 GiB** (35.1 s, 3.74 GiB in the first run) |
| Verify (snarkjs CLI) | 1.13 s | | 0.41 s (0.98 s) |
| Proof | 256 B | | 256 B, 21 public signals |

- **Two runs.** The pipeline ran twice end to end. The second run is in the table and in
  `results/run.txt`; the first, in parentheses, ran while the machine was busier. Setup is
  deterministic, so both runs give the same verifying key. Proving is the step that moved most:
  11.8 s against 35.1 s.
- **Peak memory.** The largest process was the prover, at 4.09 GiB (4,286,632 KiB). A sampler
  summed the resident memory of every process of the run every 2 s and saw 4.00 GiB at most
  (4.12 GiB in the first run); being a sample, it is a lower bound on the true peak.
- **The join adds nothing.** 291,792 = 108,784 + 183,008 exactly. Sharing `saleId` and `sellerId`
  costs no constraint.
- **Where the constraints go.** Per sold slot: 4,989 for the signature (M4) and 11,438 for the
  membership proof (M5), 16,427 together. The rest, 28,960, is the four buyers' escrow
  signatures (19,956) and v1's arithmetic (9,004). Membership is 62.7% of the circuit. A
  1,024-slot batch at the same costs would be about 16.8 million constraints, *est.*, before
  M6's tree commitment, so M5 section 6's cheaper tree matters for that size.
- **Phase 1.** 291,792 constraints need a power of 19 (2^18 is too small), *est.* from the
  domain size.
- **On chain.** The verifier's cost follows the public inputs, not the constraints. This statement
  has one more than M4's (`utxoRoot`). M5 section 5 puts one more input at about 4 hashed
  intermediates and about 10 MB of disprove leaves, *est.*, and at zero if the root is folded into
  M3's single statement hash. Not built here.

Checks that `run.sh` makes on the proof, all passing:

- the valid witness satisfies the R1CS and the proof verifies;
- `saleCommitment` matches circomlibjs (`signed/commit_signed.js`);
- the re-split batch (different sellers, same totals) gives a different commitment;
- public signal 20 is `utxoRoot`, and equals the root of the tree built from the registry
  (`9653930120785426183349085250778095429274917165237012183994165460669403200688`);
- a changed `saleCommitment`, a changed `utxoRoot` and a signal written as `x + r` are all
  rejected;
- a forged `.wtns` fails the R1CS check at constraint 104,691, and the proof made from it does
  not verify;
- the rotated batch proves under the same keys. Its public signals differ from the unrotated
  batch's at positions 0 (`saleCommitment`, since Alice's `sellerId` changed) and 20 (`utxoRoot`)
  only.

## 6. The fixtures

`joined/fixtures.sh` builds the world (`make_joined.py`) and signs it (`sign_joined.js`, on
`signed/sign.js`'s signing kit):

- **A sharechain** of 201 blocks (heights 0 to 200) at the sim depths of `real_store.py` (maturity
  20, payout depth 100, expiry margin 4), so the window at the anchor is root heights 105 to 181.
  Ten miners take the coinbases in turn. At height 150 a share transaction spends Dave's coinbase
  output into an output paid to Carol.
- **Registrations** (BIP340, demo keys) for Alice, Bob, Carol, Dave and Eve, each with sequence 1,
  and a second one for Alice with sequence 2. Zed owns outputs and never registers. The feed that
  builds the second registry delivers the sequence 2 registration first and then replays the
  others.
- **Two trees** of 77 leaves each, built with `SharechainUtxo.build_tree` and checked against an
  incremental `Accumulator` (the second one rotated with `set_owner_key`): `T1` with Alice on her
  first key, root `9653…0688`, and `T2` after the rotation, root `1307…4002`. They differ in
  Alice's leaves only.
- **Ten inputs** for the circuit, each a complete M4 batch signed with BabyJubjub demo keys plus
  the ownership witness of its sale slots.

Accepted:

| Input | What it is | Result |
|---|---|---|
| `valid` | Alice sells her output A0 (1,200 sat to buyer 1), Bob sells B0 (1,800 to buyer 2), each with the registered key, against `T1` | satisfies the R1CS, proves, verifies |
| `resplit` | Carol sells C0 and the output Dave transferred to her, Dave sells D0 and D1; the public totals equal `valid`'s, against `T1` | satisfies the R1CS; proves a different `saleCommitment` |
| `valid_rotated` | Alice's registration is rotated (sequence 2) and she sells A0 with the second key, against `T2` | satisfies the R1CS, proves, verifies |

Refused by the witness calculator:

| Input | What changed from `valid` | Refused in |
|---|---|---|
| `order_key_not_registered_owner` (a) | Alice's slot is a validly signed order for A0 by a key that no address registered | `SMTVerifier`, the root check of `OwnedSale` |
| `output_of_another_registered_seller` (b) | Alice, a registered seller, signs an order for E0, which Eve's registered key owns | `SMTVerifier` |
| `rotated_key_sells_with_old_key` (c) | against `T2`, where Alice's address is registered to key 2, the order for A0 is signed with key 1 | `SMTVerifier` |
| `unregistered_owner_output` | Zed signs an order for his own output Z0, but his address never registered a key | `SMTVerifier` |
| `output_spent_before_anchor` | Dave, the registered owner, sells the output the sharechain spent at height 150 | `SMTVerifier` |
| `wrong_utxo_root` | `utxoRoot` one higher than the tree's | `SMTVerifier` |
| `bad_order_signature` | Alice's order signature `S` + 1: M4's rule still holds in the joined circuit | `EdDSAPoseidonVerifier`, inside `SignedClearing` |

"Refused in `SMTVerifier`" is the `ForceEqualIfEnabled` of the membership verifier's root check
(circomlib `smtverifier.circom` line 134, called from `owned_sale.circom` line 63). `run.sh`
reads the template chain out of each refusal and fails if an ownership fixture is refused anywhere
else, or if `bad_order_signature` is refused anywhere but the signature check. For each
ownership fixture `test_make_joined.py` also predicts the failing slot in pure Python (the sold
leaf's owner against the hash of the signing key), and the prediction is the slot that Alice
occupies in all five.

## 7. What the joined statement does not prove

Everything M4 and M5 list as not covered stands. Added by the join:

- **The registry is outside the proof.** The circuit shows that the leaf's owner equals the signing
  key's hash. That the owner came from a registration signed by the address's key is a fact about
  how the tree was built. A root built from a registry that holds a forged registration would
  verify. So the check is the one M5 section 7.5 puts on the root: watchers rebuild the tree from
  the sharechain and from the registrations they accepted, and refuse to presign a root they do
  not reproduce. Checking BIP340 inside the circuit is M4's option (a), about a million
  constraints per signature, *est.*, and is not built.
- **A root fixes the registry at its anchor.** A rotation reaches a batch only if the batch's
  root was built after it. A batch built on an older root still accepts the old key. This is the
  freshness question of M5 section 7.3, now with a registry in it, and the committee's refusal to
  presign a root that does not match its own registry is what answers it.
- **The order key is the selling authority.** A registration signs a key hash and nothing else; it
  does not authorise a sale. Whoever holds the order key can sign orders for every output of the
  address against any root that contains the key's hash, until the address key rotates it. The
  address key can already spend those outputs, so the registration adds no power to it.
- **Unregistered outputs cannot be sold here.** The owner of such a leaf is M5's address id, and
  no order key hashes to it. A seller has to register before the anchor of the batch it wants to
  join. This costs liveness, not safety.
- **Only key-path-controlled P2TR addresses can register**, because the registration is signed
  with the key the address encodes.
- **Tie-breaks are part of the root.** Equal sequences with different key hashes make the address
  unregistered. Watchers have to apply the same rule, as they have to apply the same window and
  slot rule.
- **Non-spend after the anchor** is as in M5 section 7: nothing here stops an owner from spending
  a sold output after the anchor. Closing that gap depends on a lock on the sharechain that
  sharechain validation would have to enforce, which this milestone neither assumes to exist nor
  checks.
- **Two slots can name the same output.** v1, M4 and M5 do not check it, and the join does not
  either. A strictly increasing `saleId` across slots would cost about 4,000 constraints, *est.*
  (M5 section 7.3).
- **The world is synthetic.** The sharechain is 201 synthetic blocks with the sim depths, the
  keys are public demo keys, and the setup is the insecure deterministic one. The circuit is
  independent of the number of leaves and of the depths; the tree builder runs against a real
  node store with `real_store.py --registry`, but no registration has been made for that store's
  addresses.

## 8. Tests

Run from the repository root:

```sh
python3 -m unittest discover -s research/zk_clearing/ownership   # 99 tests: M5's 56, 29 for BIP340 and registrations, 14 for registered owners
python3 -m unittest discover -s research/zk_clearing/joined      # 17 tests on the world and the variants
python3 -m unittest discover -s research/zk_clearing/signed       # 5 tests (one new: explicit sales in the batch spec)
```

- `test_register.py` covers BIP340 (the vectors for secret keys 3, `B7E1…CFEF`, `C90F…E5C9` and
  `0B43…1710` reproduced byte for byte, a fifth vector verified, and every change to a valid
  signature refused), the address decoder against the vectors of `address-format.md`, and the
  registration cases: a valid registration verifies; a wrong key, an altered key hash, address or
  sequence, and a replay to another network are rejected (both by relabelling and by re-encoding
  the address); the highest sequence wins whatever the arrival order; equal sequences leave the
  address unregistered.
- `test_registered_owners.py` checks that without a registry the tree is M5's, that registered
  leaves carry the key hash and the others the address id, that the incremental accumulator
  equals the snapshot after every block (across a rotation too), and that the old owner no
  longer proves.
- `test_make_joined.py` checks the world (the sold outputs are leaves owned by the registered
  keys; the spent output is not a leaf; the two trees differ in Alice's leaves only), each
  variant's predicted outcome, and that the build is deterministic.

## 9. Files

| File | Role |
|---|---|
| `ownership/register.py` | BIP340, the registration format, `Registry` |
| `ownership/smt.py`, `ownership/utxo_set.py`, `ownership/real_store.py` | `decode_share_address`, `owner_field`, and the optional `registry` in the tree builders. Without one, behaviour is M5's |
| `circuits/signed_clearing.circom` | M4's templates, moved out of `clearing16x4_signed.circom` unchanged |
| `circuits/clearing16x4_owned.circom` | the joined circuit |
| `signed/sign.js`, `signed/make_batch.py` | `createSigner` exported; `batch_spec(sales=…)` |
| `joined/make_joined.py`, `sign_joined.js`, `fixtures.sh`, `run.sh` | the world, the signing, the fixtures and the run |
| `joined/results/` | `run.txt`, the world (`world.json`) and the registrations (`registrations.json`) behind the fixtures |

Registry from the command line: `python3 research/zk_clearing/ownership/real_store.py --registry
<registry.json> …` builds the tree of a real node store with registered owners, where
`registry.json` is `Registry.to_json()`.
