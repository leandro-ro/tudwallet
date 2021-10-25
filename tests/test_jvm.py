# Author: Leandro Rometsch, 2021
# Email: leandro@rometsch.org
# TU Darmstadt, Chair of Applied Cryptography

import unittest
from utils.wrapper import ColdWalletWrapper


class TestJvm(unittest.TestCase):
    """Tests the connection to jpype's java virtual machine by accessing components of the imported java libraries."""

    def test_jvm_via_keygen(self):
        """
        Accesses the keygen functionality directly via the wrapper/e-wallet library.
        This will only work if the jvm is running/jpype is configured correctly.
        """
        test_key = ColdWalletWrapper().master_gen()

        sec_key = test_key.getKeySec()
        key_type = str(type(sec_key))
        key_length = len(str(sec_key.toString()))
        self.assertTrue(key_type == '<java class \'java.math.BigInteger\'>')
        self.assertTrue(key_length > 70)

        pub_key = test_key.getKeyPub()
        key_type = str(type(pub_key))
        key_length = len(str(pub_key.toString()))
        self.assertTrue(key_type == '<java class \'com.ewallet.field.util.EllipticCurvePoint\'>')
        self.assertTrue(key_length > 100)


if __name__ == '__main__':
    unittest.main()
