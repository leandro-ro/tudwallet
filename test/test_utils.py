import unittest
import utils.support
import wallet as tudwallet
import os


class TestDataclasses(unittest.TestCase):
    wallet = None
    folder_location = "test/testData/testDataclassesData/"
    intended_id = 1

    def setUp(self):
        self.wallet = tudwallet.Wallet(self.folder_location, self.folder_location)
        # self.wallet.generate_master_key(overwrite=False) -> master key already created
        # self.wallet.public_key_derive(1) -> data already present
        # self.wallet.secret_key_derive(1) -> data already present

    def test_public_key(self):
        public_key = self.wallet.public_key_derive(self.intended_id)
        self.assertTrue(type(public_key) == utils.support.PublicKey)
        self.assertTrue(public_key.id == self.intended_id)
        self.assertTrue(public_key.x.startswith("0x"))
        self.assertTrue(public_key.y.startswith("0x"))
        self.assertTrue(public_key.address.startswith("0x"))

    def test_private_key(self):
        private_key = self.wallet.secret_key_derive(self.intended_id)
        self.assertTrue(type(private_key) == utils.support.PrivateKey)
        self.assertTrue(private_key.id == self.intended_id)
        self.assertTrue(private_key.key.startswith("0x"))


class TestDictProcessing(unittest.TestCase):
    folder_location = "test/testData/testDictProcessingData/"
    file_location = folder_location + "test_dict.txt"
    test_dict = {"1": 'This', "2": 'Is', "3": 'Computer', "4": "Science"}

    def setUp(self):
        if not os.path.exists(self.folder_location):
            os.makedirs(self.folder_location)

    def test_dict_storing(self):
        new_file_location = self.folder_location + "test_stored_dict.txt"
        utils.support.save_dict_to_file(new_file_location, self.test_dict)
        self.assertTrue(os.path.exists(new_file_location))
        os.remove(new_file_location)

    def test_dict_loading(self):
        received_dict = utils.support.get_dict_from_file(self.file_location)
        self.assertEqual(received_dict, self.test_dict)


class TestKeyLoading(unittest.TestCase):
    wallet = None
    folder_location = "test/testData/testKeyLoadingData/"

    def setUp(self):
        self.wallet = tudwallet.Wallet(self.folder_location, self.folder_location)
        # self.wallet.generate_master_key(overwrite=False) -> master key already created

    def test_private_key_loading(self):
        key = utils.support.get_private_key_from_file(self.folder_location + "ColdWalletData/MSK.key")
        self.assertEqual(str(key), "112357194824290667643081788596717750908569231627957702069966763736710490688244")

    def test_public_key_loading(self):
        key = utils.support.get_public_key_from_file(self.folder_location + "ColdWalletData/MPK.key")
        x = str(key.getPointX())
        y = str(key.getPointY())
        self.assertEqual(x, '65336545145707845447633548679905171498582881632582510202034999821249028325015')
        self.assertEqual(y, '13562228381135751081805438548054675439132929618183591005162696899711915154384')


if __name__ == '__main__':
    unittest.main()
