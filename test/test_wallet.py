import shutil
import unittest
import wallet as tudwallet
import utils.support
import os


class TestWalletInitialization(unittest.TestCase):
    wallet = None
    folder_location = "test/testData/testWalletInitData/"
    cold_wallet_location = folder_location + "ColdWalletData/"
    hot_wallet_location = folder_location + "HotWalletData/"

    def setUp(self):
        self.wallet = tudwallet.Wallet(self.folder_location, self.folder_location)
        self.wallet.generate_master_key(overwrite=True)

    def tearDown(self):
        # Delete all data created during the test to reset for next initialization test run
        shutil.rmtree(self.folder_location)

    def test_master_public_key_generation(self):
        cw_key_path = self.cold_wallet_location + "MPK.key"
        hw_key_path = self.hot_wallet_location + "MPK.key"

        self.assertTrue(os.path.exists(cw_key_path))
        self.assertTrue(os.path.exists(hw_key_path))
        self.assertEqual(utils.support.get_public_key_from_file(cw_key_path),
                         utils.support.get_public_key_from_file(hw_key_path))

    def test_master_secret_key_generation(self):
        self.assertTrue(os.path.exists(self.cold_wallet_location + "MSK.key"))
        # The MSK should only exist inside the Cold Wallet! -> assertFalse
        self.assertFalse(os.path.exists(self.hot_wallet_location + "MSK.key"))

    def test_state_generation(self):
        cw_state_path = self.cold_wallet_location + "state.txt"
        hw_state_path = self.hot_wallet_location + "state.txt"
        self.assertTrue(os.path.exists(cw_state_path))
        self.assertTrue(os.path.exists(hw_state_path))

        cw_state = utils.support.get_dict_from_file(cw_state_path)
        hw_state = utils.support.get_dict_from_file(hw_state_path)
        self.assertEqual(len(cw_state), 1)
        self.assertEqual(len(hw_state), 1)
        self.assertEqual(cw_state.keys(), {"0"})
        self.assertEqual(hw_state.keys(), {"0"})
        self.assertEqual(cw_state, hw_state)

    def test_session_key_store(self):
        cw_session_key_store_path = self.cold_wallet_location + "SecretKeyID.key"
        hw_session_key_store_path = self.hot_wallet_location + "PublicKeyID.key"

        self.assertFalse(os.path.exists(cw_session_key_store_path))  # Should not exist without any key derived
        self.assertFalse(os.path.exists(hw_session_key_store_path))

    def test_initial_ids(self):
        self.assertEqual(len(self.wallet.get_all_ids()), 0)

    def test_overwrite(self):
        msk_key_path = self.cold_wallet_location + "MSK.key"
        original_key = utils.support.get_private_key_from_file(msk_key_path)

        self.wallet.generate_master_key(overwrite=True)
        after_overwrite_true_key = utils.support.get_private_key_from_file(msk_key_path)
        self.assertNotEqual(original_key, after_overwrite_true_key)


class TestWalletSigning(unittest.TestCase):
    def test_something(self):
        self.assertEqual(True, False)  # add assertion here


class TestWalletDerivation(unittest.TestCase):
    def test_something(self):
        self.assertEqual(True, False)  # add assertion here


class TestWalletExceptions(unittest.TestCase):
    def test_something(self):
        self.assertEqual(True, False)  # add assertion here


if __name__ == '__main__':
    unittest.main()
