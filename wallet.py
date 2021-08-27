from wrapper import ColdWalletWrapper, HotWalletWrapper
from eth_utils import keccak
import os
from shutil import copyfile
from utils import *

MPK_FILE_NAME = "MPK.key"  # Master Public Key
MSK_FILE_NAME = "MSK.key"  # Master Secret Key
SSK_FILE_NAME = "SecretKeyID.key"  # Session Secret Keys
STATE_FILE_NAME = "state.txt"
SIG_FILE_NAME = "signature.sig"


class Wallet:
    def __init__(self, base_directory="data/"):
        if not os.path.exists(base_directory):
            os.mkdir(base_directory)

        self.cold_wallet = _ColdWallet(base_directory + "ColdWalletData/")
        self.hot_wallet = _HotWallet(base_directory + "HotWalletData/")
        self.cold_wallet_synced = False

    def generate_master_key(self, overwrite=False):
        self.cold_wallet.master_key_gen(overwrite=overwrite)

        self.cold_wallet.copy_state_to(self.hot_wallet.get_state_path())  # Transfer initial state
        self.cold_wallet.copy_mpk_to(self.hot_wallet.get_mpk_path())  # Init hot_wallet with MPK
        self.cold_wallet_synced = True  # The initial state is the same for both wallets

    def secret_key_derive(self, id=None):
        self._sync_wallets()

        if id is None:
            max_id = self.cold_wallet.get_max_id()
            sk_raw = self.cold_wallet.secret_key_derive(max_id)
            return PrivateKey(key=sk_raw, id=max_id)
        if id not in self.cold_wallet.get_ids():
            raise Exception("tudwallet - Derive session public key with ID = " + id + " first!")

        sk_raw = self.cold_wallet.secret_key_derive(id)
        return PrivateKey(key=sk_raw, id=id)

    def public_key_derive(self, id=None):
        max_id = self.hot_wallet.get_max_id()
        if id is not None:
            if max_id <= id:
                raise Exception("tudwallet - ID is lower then previous IDs. Choose ID higher than: " + str(max_id))
            next_id = id
        else:
            next_id = max_id + 1

        self.cold_wallet_synced = False
        raw_pk = self.hot_wallet.public_key_derive(next_id)
        pk = PublicKey(self._get_address(raw_pk), next_id, raw_pk["X"], raw_pk["Y"])
        return pk

    def sign_transaction(self, tx, id):
        self._id_existing(id)

        # TODO: implement
        return

    def get_all_ids(self):
        return self.hot_wallet.get_ids()

    @staticmethod
    def _get_address(public_key: dict):
        x = public_key["X"][2:]
        y = public_key["Y"][2:]
        preimage = x + y
        keccak256 = keccak(hexstr=preimage)
        return "0x" + keccak256.hex()[24:]

    def _sync_wallets(self):
        if self.cold_wallet_synced:
            return
        self.hot_wallet.copy_state_to(self.cold_wallet.get_state_path())  # Copy state of hot wallet to cold wallet
        self.cold_wallet_synced = True

    def _id_existing(self, id):
        self._sync_wallets()
        if id not in self.cold_wallet.get_ids():
            raise Exception("tudwallet - Derive session public/secret key with ID = " + id + " first!")


class _ColdWallet:
    def __init__(self, directory):
        if not os.path.exists(directory):
            os.mkdir(directory)

        self.__master_secret_file_path = directory + MSK_FILE_NAME
        self.__master_public_file_path = directory + MPK_FILE_NAME
        self.__state_file_path = directory + STATE_FILE_NAME
        self.__session_secret_file_path = directory + SSK_FILE_NAME
        self.__signature_file_path = directory + SIG_FILE_NAME
        self.__base_directory = directory

    def master_key_gen(self, overwrite=False):
        if not overwrite and os.path.exists(self.__master_secret_file_path):
            raise Exception("Master Secret Key already created. You must use this function with overwrite=True to "
                            "create a new one")
        elif overwrite:
            for root, dirs, files in os.walk(self.__base_directory):
                for file in files:
                    os.remove(os.path.join(root, file))

        cww = ColdWalletWrapper()
        key = cww.master_gen()
        state = key.getState()  # 32 Bytes

        id_state_map = {0: list(state)}  # dict is the state data structure
        save_dict_to_file(self.__state_file_path, id_state_map)  # write dict to file

        sk = key.getKeySec()
        pk = key.getKeyPub()

        # write key pair to cold wallet
        with open(self.__master_secret_file_path, 'w') as key_file:
            key_file.write(str(sk.toString()))
            key_file.close()

        with open(self.__master_public_file_path, 'w') as key_file:
            key_file.write(str(pk.getPointX().toString()) + '\n')
            key_file.write(str(pk.getPointY().toString()))
            key_file.close()

    def secret_key_derive(self, id):
        if not os.path.exists(self.__master_secret_file_path):
            raise Exception("Wallet not initialized yet. Call master_key_gen first!")

        id_state_map = get_dict_from_file(self.__state_file_path)

        key_hash_map = {}
        if os.path.exists(self.__session_secret_file_path):
            key_hash_map = get_dict_from_file(self.__session_secret_file_path)  # Init empty dict. Types: <String,
            # BigInteger>. Written to file as <String, String>
            if str(id) in key_hash_map:  # if key already derived return it directly from the key file
                return hex(int(str(key_hash_map[str(id)])))
        last_state = id_state_map[str(id - 1)]  # TODO: Check if this is correct

        master_sec_key = get_private_key_from_file(self.__master_secret_file_path)  # Type: java.math.BigInteger

        session_secret_key = ColdWalletWrapper().sk_derive(master_sec_key, str(id), last_state).getSecretKey()
        key_hash_map[str(id)] = str(session_secret_key)
        save_dict_to_file(self.__session_secret_file_path, key_hash_map)

        return hex(int(str(key_hash_map[str(id)])))

    def sign_transaction(self, tx, id):
        if not os.path.exists(self.__master_secret_file_path):
            raise Exception("Wallet not initialized yet. Call master_key_gen first!")

        session_secret_key = get_dict_from_file(self.__session_secret_file_path)[str(id)]

    def sign_message(self):
        pass

    def get_ids(self):
        id_state_map = get_dict_from_file(self.__state_file_path)
        return list(map(int, id_state_map.keys()))

    def get_max_id(self):
        if not os.path.exists(self.__state_file_path):
            raise Exception("No state file exists. Call master_key_gen first!")
        return max(self.get_ids())

    def get_state_path(self):
        return self.__state_file_path

    def copy_state_to(self, path):
        copyfile(self.__state_file_path, path)

    def copy_mpk_to(self, path):
        copyfile(self.__master_public_file_path, path)


class _HotWallet:
    def __init__(self, directory):
        if not os.path.exists(directory):
            os.mkdir(directory)

        self.__master_public_file_path = directory + MPK_FILE_NAME
        self.__state_file_path = directory + STATE_FILE_NAME

    def public_key_derive(self, id):
        if not os.path.exists(self.__master_public_file_path):
            raise Exception("Wallet not initialized yet. Call master_key_gen first!")

        id_state_map = get_dict_from_file(self.__state_file_path)
        last_state = id_state_map[str(self.get_max_id())]

        master_public_key = get_public_key_from_file(self.__master_public_file_path)
        pk = HotWalletWrapper().pk_derive(master_public_key, str(id), last_state)
        session_public_key = pk.getPublicKey()
        next_state = pk.getState()

        id_state_map[str(id)] = list(next_state)
        save_dict_to_file(self.__state_file_path, id_state_map)
        return {"X": hex(int(str(session_public_key.getPointX()))), "Y": hex(int(str(session_public_key.getPointY())))}

    def get_state_path(self):
        return self.__state_file_path

    def get_mpk_path(self):
        return self.__master_public_file_path

    def copy_state_to(self, path):
        copyfile(self.__state_file_path, path)

    def get_ids(self):
        id_state_map = get_dict_from_file(self.__state_file_path)
        return list(map(int, id_state_map.keys()))

    def get_max_id(self):
        if not os.path.exists(self.__state_file_path):
            raise Exception("No state file exists. Call master_key_gen first!")
        return max(self.get_ids())
