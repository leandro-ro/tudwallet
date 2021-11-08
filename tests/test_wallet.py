# Author: Leandro Rometsch, 2021
# Email: leandro@rometsch.org
# TU Darmstadt, Chair of Applied Cryptography

import shutil
import unittest
import wallet as tudwallet
import utils.support
import os
from eth_account import Account
from eth_account.messages import encode_defunct


class TestWalletInitialization(unittest.TestCase):
    wallet = None
    folder_location = "tests/fixture/testWalletInitData/"
    cold_wallet_location = folder_location + "ColdWalletData/"
    hot_wallet_location = folder_location + "HotWalletData/"

    def setUp(self):
        self.wallet = tudwallet.Wallet(self.folder_location, self.folder_location)
        self.wallet.generate_master_key(overwrite=True)

    def tearDown(self):
        # Delete all data created during the tests to reset for next initialization tests run
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
    wallet = None
    folder_location = "tests/fixture/testWalletSignData/"
    test_transaction = {
        # Note that the address must be in checksum format or native bytes:
        'to': '0x82fc853256B05029b3759161B32E3460Fe4eaC77',
        'value': 10000000000000000,
        'gas': 2000000,
        'gasPrice': 2500000008,
        'nonce': 2,
        'chainId': 3,  # Ropsten Testnet ID = 3
    }

    def setUp(self):
        self.wallet = tudwallet.Wallet(self.folder_location, self.folder_location)
        self.wallet.generate_master_key(overwrite=True)
        self.wallet.public_key_derive(1)
        self.wallet.secret_key_derive(1)

        self.wallet.public_key_derive(2)
        self.wallet.secret_key_derive(2)

        self.wallet.public_key_derive(3)
        self.wallet.secret_key_derive(3)

    def tearDown(self):
        # Delete all data created during the tests to reset for next tests run
        shutil.rmtree(self.folder_location)

    def test_sign_message_one_string(self):
        test_message = "Test message"
        expected_address = self.wallet.public_key_derive(1).address

        sig = self.wallet.sign_message(test_message, 1)
        calculated_address = Account.recover_message(encode_defunct(text=test_message), (sig.v, sig.r, sig.s))

        self.assertEqual(expected_address, calculated_address.lower())

    def test_sign_message_two_string(self):
        test_message = "Test another message"
        expected_address = self.wallet.public_key_derive(2).address

        sig = self.wallet.sign_message(test_message, 2)
        calculated_address = Account.recover_message(encode_defunct(text=test_message), (sig.v, sig.r, sig.s))

        self.assertEqual(expected_address, calculated_address.lower())

    def test_sign_message_three_bytes(self):
        test_message = b'BytesTest'
        expected_address = self.wallet.public_key_derive(3).address

        sig = self.wallet.sign_message(test_message, 3)
        calculated_address = Account.recover_message(encode_defunct(primitive=test_message), (sig.v, sig.r, sig.s))

        self.assertEqual(expected_address, calculated_address.lower())

    def test_sign_transaction_one(self):
        signed_tx = self.wallet.sign_transaction(self.test_transaction, 1)
        expected_address = self.wallet.public_key_derive(1).address

        calculated_address = Account.recover_transaction(signed_tx.rawTransaction)

        self.assertEqual(expected_address, calculated_address.lower())

    def test_sign_transaction_two(self):
        signed_tx = self.wallet.sign_transaction(self.test_transaction, 2)
        expected_address = self.wallet.public_key_derive(2).address

        calculated_address = Account.recover_transaction(signed_tx.rawTransaction)

        self.assertEqual(expected_address, calculated_address.lower())

    def test_sign_with_underived_id(self):
        with self.assertRaises(Exception):
            self.wallet.sign_message("Test message", 10)

        with self.assertRaises(Exception):
            self.wallet.sign_message("Test message", -10)

        with self.assertRaises(Exception):
            self.wallet.sign_transaction(self.test_transaction, 100)

    def test_sign_with_invalid_transaction(self):
        with self.assertRaises(Exception):
            self.wallet.sign_transaction("Not a transaction", 1)


class TestWalletDerivation(unittest.TestCase):
    wallet = None
    folder_location = "tests/fixture/testDerivationData/"

    def setUp(self):
        self.wallet = tudwallet.Wallet(self.folder_location, self.folder_location)
        self.wallet.generate_master_key(overwrite=True)

    def tearDown(self):
        # Delete all data created during the tests to reset for next tests run
        shutil.rmtree(self.folder_location)

    def test_derivation_behavior(self):  # Due to ordering dependency we need to run everything in one
        all_ids = self.wallet.get_all_ids()
        self.assertEqual(len(all_ids), 0)

        self.wallet.public_key_derive()  # Should derive with id = 1 -> last_id + 1
        self.wallet.secret_key_derive()  # Should derive with id = 1 -> last derived session public key id
        all_ids = self.wallet.get_all_ids()

        self.assertEqual(len(all_ids), 1)
        self.assertTrue(1 in all_ids)

        self.wallet.public_key_derive()  # Should derive with id = 2 -> last_id + 1
        self.wallet.secret_key_derive()  # Should derive with id = 2 -> last derived session public key id
        all_ids = self.wallet.get_all_ids()

        self.assertEqual(len(all_ids), 2)
        self.assertTrue(1, 2 in all_ids)

        for i in range(3, 101):
            self.wallet.public_key_derive()  # Derive another 98 session public keys

        all_ids = self.wallet.get_all_ids()
        self.assertEqual(len(all_ids), 100)

        self.wallet.public_key_derive(200)

        with self.assertRaises(Exception):
            self.wallet.public_key_derive(150)  # Should not be possible because id = 200 derived earlier

        with self.assertRaises(Exception):
            self.wallet.public_key_derive(-10)  # Should not be possible because id is negative

        with self.assertRaises(Exception):
            self.wallet.secret_key_derive(150)  # Should not be possible because no matching public key derived


if __name__ == '__main__':
    unittest.main()
