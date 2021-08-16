from wrapper import ColdWalletWrapper, HotWalletWrapper
import unittest


class TestJvm(unittest.TestCase):
    cw = ColdWalletWrapper()
    hw = HotWalletWrapper()

    def test_keygen(self):
        test_key = self.cw.master_gen()

        sec_key = test_key.getKeySec()
        key_type = str(type(sec_key))
        key_length = len(str(sec_key.toString()))
        self.assertTrue(key_type == '<java class \'java.math.BigInteger\'>')
        self.assertTrue(key_length > 100)

        pub_key = test_key.getKeyPub()
        key_type = str(type(pub_key))
        key_length = len(str(pub_key.toString()))
        self.assertTrue(key_type == '<java class \'com.ewallet.field.util.EllipticCurvePoint\'>')
        self.assertTrue(key_length > 100)


if __name__ == '__main__':
    unittest.main()