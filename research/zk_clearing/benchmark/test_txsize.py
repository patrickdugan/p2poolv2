"""Check the size calculator against well-known reference transactions."""

import unittest

from txsize import (
    P2TR_KEY_IN,
    P2TR_OUT,
    P2WPKH_IN,
    P2WPKH_OUT,
    htlc_p2wsh_script,
    script_number,
    vbytes,
    weight,
)


class ReferenceSizes(unittest.TestCase):
    def test_p2wpkh_one_in_two_out(self):
        # 1-in 2-out P2WPKH with a 72-byte signature: 562 WU, 140.5 vB.
        self.assertEqual(weight([P2WPKH_IN], [P2WPKH_OUT, P2WPKH_OUT]), 562)
        self.assertEqual(vbytes([P2WPKH_IN], [P2WPKH_OUT, P2WPKH_OUT]), 141)

    def test_p2tr_key_path_one_in_one_out(self):
        # 1-in 1-out P2TR key path: 444 WU, 111 vB.
        self.assertEqual(weight([P2TR_KEY_IN], [P2TR_OUT]), 444)
        self.assertEqual(vbytes([P2TR_KEY_IN], [P2TR_OUT]), 111)

    def test_script_numbers(self):
        self.assertEqual(script_number(6), 1)  # OP_6
        self.assertEqual(script_number(144), 3)  # push 0x90 0x00
        self.assertEqual(script_number(127), 2)
        self.assertEqual(script_number(128), 3)

    def test_htlc_script_length(self):
        # IF SHA256 <32> EQUALVERIFY <33> CHECKSIG ELSE IF 2 <33> <33> 2 CHECKMULTISIG
        # ELSE <144> CSV DROP <33> CHECKSIG ENDIF ENDIF
        self.assertEqual(htlc_p2wsh_script(144), 187)


if __name__ == "__main__":
    unittest.main()
