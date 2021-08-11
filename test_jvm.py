from wrapper import ColdWalletWrapper, HotWalletWrapper
import unittest


class TestJvm(unittest.TestCase):
    cw = ColdWalletWrapper()
    hw = HotWalletWrapper()

    def test_keygen(self):
        skey = self.cw.master_gen().getKeySec()
        self.assertTrue(skey)


if __name__ == '__main__':
    unittest.main()