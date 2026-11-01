"""Tests of the order-key registration: BIP340, the registration format and the registry.

Run from the repository root:

    python3 -m unittest discover -s research/zk_clearing/ownership

The BIP340 vectors are rows of bip-0340/test-vectors.csv. The registration tests use demo
secret keys derived from labels; they sign nothing of value.
"""

import hashlib
import itertools
import sys
import unittest
from dataclasses import replace
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import register  # noqa: E402
import smt  # noqa: E402
from register import Registration, RegistrationError, Registry  # noqa: E402


def secret(label: str) -> bytes:
    n = register.N
    return ((int.from_bytes(hashlib.sha256(f"test_register/{label}".encode()).digest(), "big") % (n - 1)) + 1).to_bytes(32, "big")


def key_hash(label: str) -> int:
    """A stand-in for Poseidon(Ax, Ay): any nonzero field element does for the registration format."""
    return smt.poseidon2(int.from_bytes(hashlib.sha256(f"order key/{label}".encode()).digest(), "big") >> 3, 7)


# (secret key, public key, aux_rand, message, signature) of bip-0340/test-vectors.csv rows 0 to 3.
SIGNING_VECTORS = [
    (
        "0000000000000000000000000000000000000000000000000000000000000003",
        "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000000",
        "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA8215"
        "25F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0",
    ),
    (
        "B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF",
        "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
        "0000000000000000000000000000000000000000000000000000000000000001",
        "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
        "6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE3341"
        "8906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A",
    ),
    (
        "C90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B14E5C9",
        "DD308AFEC5777E13121FA72B9CC1B7CC0139715309B086C960E18FD969774EB8",
        "C87AA53824B4D7AE2EB035A2B5BBBCCC080E76CDC6D1692C4B0B62D798E6D906",
        "7E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C",
        "5831AAEED7B44BB74E5EAB94BA9D4294C49BCF2A60728D8B4C200F50DD313C1B"
        "AB745879A5AD954A72C45A91C3A51D3C7ADEA98D82F8481E0E1E03674A6F3FB7",
    ),
    (
        "0B432B2677937381AEF05BB02A66ECD012773062CF3FA2549E44F58ED2401710",
        "25D1DFF95105F5253C4022F628A996AD3A0D95FBF21D468A1B33F8C160D8F517",
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
        "7EB0509757E246F19449885651611CB965ECC1A187DD51B64FDA1EDC9637D5EC"
        "97582B9CB13DB3933705B32BA982AF5AF25FD78881EBB32771FC5922EFC66EA3",
    ),
]

# Row 4 of the vectors: verification only, a message that is not 32 bytes of a signing run.
VERIFY_ONLY_VALID = (
    "D69C3509BB99E412E68B0FE8544E72837DFA30746D8BE2AA65975F29D22DC7B9",
    "4DF3C3F68FCC83B27E9D42C90431A72499F17875C81A599B566C9889B9696703",
    "00000000000000000000003B78CE563F89A0ED9414F5AA28AD0D96D6795F9C63"
    "76AFB1548AF603B3EB45C9F8207DEE1060CB71C04E80F593060B07D28308D7F4",
)


class Bip340Tests(unittest.TestCase):
    def test_public_keys_of_the_vectors(self):
        for sk, pk, *_ in SIGNING_VECTORS:
            self.assertEqual(register.pubkey_gen(bytes.fromhex(sk)).hex().upper(), pk)

    def test_signatures_of_the_vectors(self):
        for sk, pk, aux, message, signature in SIGNING_VECTORS:
            produced = register.schnorr_sign(bytes.fromhex(message), bytes.fromhex(sk), bytes.fromhex(aux))
            self.assertEqual(produced.hex().upper(), signature)
            self.assertTrue(register.schnorr_verify(bytes.fromhex(message), bytes.fromhex(pk), bytes.fromhex(signature)))

    def test_a_valid_verify_only_vector(self):
        pk, message, signature = VERIFY_ONLY_VALID
        self.assertTrue(register.schnorr_verify(bytes.fromhex(message), bytes.fromhex(pk), bytes.fromhex(signature)))

    def test_every_change_to_a_valid_signature_breaks_it(self):
        sk, pk, aux, message, signature = SIGNING_VECTORS[1]
        message, pk, signature = bytes.fromhex(message), bytes.fromhex(pk), bytes.fromhex(signature)
        self.assertTrue(register.schnorr_verify(message, pk, signature))
        self.assertFalse(register.schnorr_verify(message[:-1] + b"\x00", pk, signature))
        self.assertFalse(register.schnorr_verify(message, bytes.fromhex(SIGNING_VECTORS[2][1]), signature))
        for position in (0, 31, 32, 63):
            broken = bytearray(signature)
            broken[position] ^= 1
            self.assertFalse(register.schnorr_verify(message, pk, bytes(broken)), position)

    def test_out_of_range_and_malformed_inputs_are_refused(self):
        _, pk, _, message, signature = SIGNING_VECTORS[1]
        message, pk, signature = bytes.fromhex(message), bytes.fromhex(pk), bytes.fromhex(signature)
        too_big_s = signature[:32] + register.N.to_bytes(32, "big")
        self.assertFalse(register.schnorr_verify(message, pk, too_big_s))
        too_big_r = register.P.to_bytes(32, "big") + signature[32:]
        self.assertFalse(register.schnorr_verify(message, pk, too_big_r))
        self.assertFalse(register.schnorr_verify(message, pk, signature[:63]))
        self.assertFalse(register.schnorr_verify(message, pk[:31], signature))
        # An x with no point on the curve is not a public key.
        x = next(x for x in range(1, 100) if register._lift_x(x) is None)
        self.assertFalse(register.schnorr_verify(message, x.to_bytes(32, "big"), signature))
        # A public key with x >= p.
        self.assertFalse(register.schnorr_verify(message, register.P.to_bytes(32, "big"), signature))

    def test_secret_keys_out_of_range_are_refused(self):
        for bad in (0, register.N):
            with self.assertRaises(ValueError):
                register.pubkey_gen(bad.to_bytes(32, "big"))

    def test_the_signing_key_may_have_an_odd_y_public_point(self):
        # Both parities are exercised by the vectors; check a run of keys sign and verify.
        parities = set()
        for index in range(6):
            sk = secret(f"parity/{index}")
            point = register._point_mul(register.G, int.from_bytes(sk, "big"))
            parities.add(point[1] % 2)
            message = hashlib.sha256(bytes([index])).digest()
            signature = register.schnorr_sign(message, sk, bytes(32))
            self.assertTrue(register.schnorr_verify(message, register.pubkey_gen(sk), signature))
        self.assertEqual(parities, {0, 1})


class AddressDecodeTests(unittest.TestCase):
    VECTORS = [
        ("mainnet", "66db9f0ac8ca0a00603027b3a445da6ee2df6c0e04f8dc6f996db4e59d0e45bf",
         "p2pool1pvmde7zkgeg9qqcpsy7e6g3w6dm3d7mqwqnudcmuedk6wt8gwgklsuackff"),
        ("regtest", "66db9f0ac8ca0a00603027b3a445da6ee2df6c0e04f8dc6f996db4e59d0e45bf",
         "rp2pool1pvmde7zkgeg9qqcpsy7e6g3w6dm3d7mqwqnudcmuedk6wt8gwgkls63pz3k"),
        ("testnet4", "ac493f2130ca56cb5c3a559860cef9a84f90b5a85dfe4ec6e6067eeee17f4d2d",
         "tp2pool1p43yn7gfseftvkhp62kvxpnhe4p8epddgthlya3hxqelwactlf5kst4gevn"),
        ("signet", "a3ea4c1c5f042ae7fbd086bc7f30e2a08c8b6753c4631db7d4b1fcb3ab941900",
         "sp2pool1p504yc8zlqs4w077ss6787v8z5zxgke6nc333md75k87t82u5ryqqd9033x"),
    ]

    def test_the_address_format_vectors_decode(self):
        for network, key, address in self.VECTORS:
            self.assertEqual(smt.decode_share_address(address), (network, bytes.fromhex(key)))

    def test_decode_inverts_encode(self):
        for index in range(20):
            key = hashlib.sha256(bytes([index])).digest()
            for network in smt.SHARE_HRP:
                self.assertEqual(smt.decode_share_address(smt.share_address(key, network)), (network, key))

    def test_non_share_addresses_are_refused(self):
        address = self.VECTORS[3][2]
        cases = {
            "uppercase": address.upper(),
            "one character changed": address[:-3] + ("q" if address[-3] != "q" else "p") + address[-2:],
            "truncated": address[:-1],
            "bitcoin taproot hrp": "bc1p" + address.split("1p", 1)[1],
            "no separator": "sp2pool",
            "empty": "",
            "invalid character": address[:10] + "b" + address[11:],
        }
        for name, bad in cases.items():
            with self.assertRaises(ValueError, msg=name):
                smt.decode_share_address(bad)


class RegistrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.alice, cls.bob = secret("alice"), secret("bob")
        cls.registration = register.sign_registration(cls.alice, "signet", key_hash("alice#1"), 1, bytes(32))
        cls.other = register.sign_registration(cls.bob, "signet", key_hash("bob#1"), 1, bytes(32))

    def test_a_valid_registration_verifies(self):
        registration = self.registration
        self.assertTrue(register.verify_registration(registration))
        self.assertEqual(registration.address, smt.share_address(register.pubkey_gen(self.alice), "signet"))
        self.assertEqual(len(registration.signature), 64)

    def test_the_message_binds_every_field(self):
        base = self.registration
        messages = {
            "base": base.message(),
            "network": register.registration_message("regtest", base.address, base.key_hash, base.sequence),
            "address": register.registration_message(base.network, self.other.address, base.key_hash, base.sequence),
            "key hash": register.registration_message(base.network, base.address, base.key_hash + 1, base.sequence),
            "sequence": register.registration_message(base.network, base.address, base.key_hash, base.sequence + 1),
        }
        self.assertEqual(len(set(messages.values())), len(messages))
        self.assertTrue(all(len(m) == 32 for m in messages.values()))

    def test_the_message_is_the_documented_tagged_hash(self):
        base = self.registration
        preimage = (
            bytes([6]) + b"signet" + bytes([len(base.address)]) + base.address.encode()
            + base.key_hash.to_bytes(32, "big") + (1).to_bytes(8, "big")
        )
        tag = hashlib.sha256(register.DOMAIN_TAG.encode()).digest()
        self.assertEqual(base.message(), hashlib.sha256(tag + tag + preimage).digest())

    def test_a_signature_by_the_wrong_key_is_rejected(self):
        # Bob signs a registration that names Alice's address.
        forged_message = register.registration_message("signet", self.registration.address, key_hash("mallory"), 2)
        forged = Registration(
            "signet", self.registration.address, key_hash("mallory"), 2,
            register.schnorr_sign(forged_message, self.bob, bytes(32)),
        )
        self.assertFalse(register.verify_registration(forged))
        with self.assertRaisesRegex(RegistrationError, "does not verify"):
            register.check_registration(forged)

    def test_an_altered_key_hash_is_rejected(self):
        self.assertFalse(register.verify_registration(replace(self.registration, key_hash=key_hash("mallory"))))
        self.assertFalse(register.verify_registration(replace(self.registration, key_hash=self.registration.key_hash + 1)))

    def test_an_altered_address_is_rejected(self):
        self.assertFalse(register.verify_registration(replace(self.registration, address=self.other.address)))

    def test_an_altered_sequence_is_rejected(self):
        self.assertFalse(register.verify_registration(replace(self.registration, sequence=2)))

    def test_a_replay_to_another_network_is_rejected(self):
        replayed = replace(self.registration, network="mainnet")
        with self.assertRaisesRegex(RegistrationError, "address is for signet"):
            register.check_registration(replayed)
        # The same output key as a mainnet address: the signed network and address differ.
        mainnet_address = smt.share_address(smt.decode_share_address(self.registration.address)[1], "mainnet")
        replayed = replace(self.registration, network="mainnet", address=mainnet_address)
        with self.assertRaisesRegex(RegistrationError, "does not verify"):
            register.check_registration(replayed)
        # A registry for one network refuses another network's registration before checking it.
        with self.assertRaisesRegex(RegistrationError, "registry is mainnet"):
            Registry("mainnet").add(self.registration)

    def test_ill_formed_registrations_are_rejected(self):
        base = self.registration
        bad = {
            "unknown network": replace(base, network="testnet3"),
            "address not bech32m": replace(base, address=base.address[:-1] + "q"),
            "uppercase address": replace(base, address=base.address.upper()),
            "zero key hash": replace(base, key_hash=0),
            "key hash outside the field": replace(base, key_hash=smt.FIELD),
            "negative sequence": replace(base, sequence=-1),
            "sequence beyond 64 bits": replace(base, sequence=1 << 64),
            "short signature": replace(base, signature=base.signature[:63]),
        }
        for name, registration in bad.items():
            self.assertFalse(register.verify_registration(registration), name)
            with self.assertRaises(RegistrationError, msg=name):
                register.check_registration(registration)

    def test_json_round_trip(self):
        registration = self.registration
        data = registration.to_json()
        self.assertEqual(data["orderKeyHash"], registration.key_hash.to_bytes(32, "big").hex())
        self.assertEqual(Registration.from_json(data), registration)
        for field in ("network", "address", "orderKeyHash", "sequence", "signature"):
            broken = {k: v for k, v in data.items() if k != field}
            with self.assertRaises(RegistrationError, msg=field):
                Registration.from_json(broken)
        with self.assertRaises(RegistrationError):
            Registration.from_json(dict(data, orderKeyHash="12"))


class RegistryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.alice, cls.bob = secret("alice"), secret("bob")

    def registration(self, secret_key, label, sequence):
        return register.sign_registration(secret_key, "signet", key_hash(label), sequence, bytes(32))

    def test_rotation_the_highest_sequence_wins(self):
        first = self.registration(self.alice, "alice#1", 1)
        second = self.registration(self.alice, "alice#2", 2)
        registry = Registry("signet")
        self.assertTrue(registry.add(first))
        self.assertEqual(registry.key_hash(first.address), key_hash("alice#1"))
        self.assertTrue(registry.add(second))
        self.assertEqual(registry.key_hash(first.address), key_hash("alice#2"))
        self.assertEqual(registry.owners(), {first.address: key_hash("alice#2")})
        self.assertEqual(registry.sequence(first.address), 2)

    def test_a_replayed_older_registration_changes_nothing(self):
        first = self.registration(self.alice, "alice#1", 1)
        second = self.registration(self.alice, "alice#2", 2)
        registry = Registry("signet")
        registry.add(first)
        registry.add(second)
        self.assertFalse(registry.add(first))
        self.assertEqual(registry.key_hash(first.address), key_hash("alice#2"))

    def test_the_result_does_not_depend_on_arrival_order(self):
        regs = [
            self.registration(self.alice, "alice#1", 1),
            self.registration(self.alice, "alice#2", 2),
            self.registration(self.alice, "alice#3", 3),
        ]
        for order in itertools.permutations(regs):
            registry = Registry("signet")
            for registration in order:
                registry.add(registration)
            self.assertEqual(registry.owners(), {regs[0].address: key_hash("alice#3")}, order)

    def test_two_keys_at_the_same_sequence_leave_the_address_unregistered(self):
        a = self.registration(self.alice, "alice#a", 5)
        b = self.registration(self.alice, "alice#b", 5)
        for order in ((a, b), (b, a)):
            registry = Registry("signet")
            for registration in order:
                registry.add(registration)
            self.assertIsNone(registry.key_hash(a.address))
            self.assertEqual(registry.owners(), {})
            self.assertEqual(len(registry), 0)
            # A higher sequence resolves it.
            registry.add(self.registration(self.alice, "alice#c", 6))
            self.assertEqual(registry.key_hash(a.address), key_hash("alice#c"))

    def test_registering_the_same_key_twice_at_one_sequence_is_not_a_conflict(self):
        a = register.sign_registration(self.alice, "signet", key_hash("alice#a"), 5, bytes(32))
        again = register.sign_registration(self.alice, "signet", key_hash("alice#a"), 5, bytes([1]) * 32)
        self.assertNotEqual(a.signature, again.signature)
        registry = Registry("signet")
        registry.add(a)
        registry.add(again)
        self.assertEqual(registry.key_hash(a.address), key_hash("alice#a"))

    def test_invalid_registrations_never_enter(self):
        good = self.registration(self.alice, "alice#1", 1)
        forged = replace(self.registration(self.bob, "bob#1", 1), key_hash=key_hash("mallory"))
        registry = Registry("signet")
        with self.assertRaises(RegistrationError):
            registry.add(forged)
        rejected = registry.ingest([forged, good, replace(good, network="mainnet")])
        self.assertEqual([reason.split(" ")[0] for _, reason in rejected], ["signature", "registration"])
        self.assertEqual(registry.owners(), {good.address: good.key_hash})

    def test_distinct_addresses_are_independent(self):
        registry = Registry("signet")
        registry.add(self.registration(self.alice, "alice#1", 9))
        registry.add(self.registration(self.bob, "bob#1", 1))
        self.assertEqual(len(registry), 2)
        self.assertEqual(sorted(registry.owners()), sorted(r.address for r in registry.registrations()))

    def test_json_round_trip_keeps_the_owners(self):
        registry = Registry("signet")
        for registration in (self.registration(self.alice, "alice#1", 1), self.registration(self.alice, "alice#2", 2),
                             self.registration(self.bob, "bob#1", 1)):
            registry.add(registration)
        restored = Registry.from_json(registry.to_json())
        self.assertEqual(restored.owners(), registry.owners())
        self.assertEqual(restored.network, "signet")

    def test_an_unknown_network_is_refused(self):
        with self.assertRaises(ValueError):
            Registry("testnet3")


if __name__ == "__main__":
    unittest.main()
