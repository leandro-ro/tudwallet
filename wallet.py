from shutil import copyfile

from eth_account import account
from eth_account.messages import encode_defunct
from eth_utils import keccak

from utils import *
from wrapper import ColdWalletWrapper, HotWalletWrapper

MPK_FILE_NAME = "MPK.key"  # Master Public Key
MSK_FILE_NAME = "MSK.key"  # Master Secret Key
SSK_FILE_NAME = "SecretKeyID.key"  # Session Secret Keys
SPK_FILE_NAME = "PublicKeyID.key"  # Session Public Keys
STATE_FILE_NAME = "state.txt"
SIG_FILE_NAME = "signature.sig"


class Wallet:
    def __init__(self, base_directory="data/"):
        if not os.path.exists(base_directory):
            os.mkdir(base_directory)

        self.__cold_wallet = _ColdWallet(base_directory + "ColdWalletData/")
        self.__hot_wallet = _HotWallet(base_directory + "HotWalletData/")
        self.__cold_wallet_synced = False

    def generate_master_key(self, overwrite=False):
        self.__cold_wallet.master_key_gen(overwrite=overwrite)  # Potential overwrite exception already raised here

        if overwrite:
            delete_files_in_folder(self.__hot_wallet.get_base_path())

        self.__cold_wallet.copy_state_to(self.__hot_wallet.get_state_path())  # Transfer initial state
        self.__cold_wallet.copy_mpk_to(self.__hot_wallet.get_mpk_path())  # Init hot_wallet with MPK
        self.__cold_wallet_synced = True  # The initial state is the same for both wallets

    def secret_key_derive(self, id=None):
        self._sync_wallets()

        if id is None:
            max_id = self.__cold_wallet.get_max_id()
            sk_raw = self.__cold_wallet.secret_key_derive(max_id)
            return PrivateKey(key=sk_raw, id=max_id)
        if id not in self.__cold_wallet.get_ids():
            raise Exception("tudwallet - Derive session public key with ID = " + str(id) + " first!")

        sk_raw = self.__cold_wallet.secret_key_derive(id)
        return PrivateKey(key=sk_raw, id=id)

    def public_key_derive(self, id=None):
        max_id = self.__hot_wallet.get_max_id()
        if id is not None:
            if id <= max_id:
                if id not in self.__hot_wallet.get_ids():
                    raise Exception("tudwallet - ID is lower then previous IDs. Choose ID higher than: " + str(max_id))
                else:
                    raw_pk = self.__hot_wallet.public_key_derive(id)
                    return PublicKey(self._get_address(raw_pk), id, raw_pk["X"], raw_pk["Y"])
            next_id = id
        else:
            next_id = max_id + 1

        self.__cold_wallet_synced = False
        raw_pk = self.__hot_wallet.public_key_derive(next_id)
        pk = PublicKey(self._get_address(raw_pk), next_id, raw_pk["X"], raw_pk["Y"])
        return pk

    def sign_transaction(self, transaction_dict, id: int):
        self._id_existing(id)
        if not isinstance(transaction_dict, dict):
            raise TypeError("tudwallet - Transaction given in unsupported format. Provide as dict with keys: nonce, "
                            "chainId, to, data, value, gas, and gasPrice.")

        sk = self.secret_key_derive(id)
        sig = self.__cold_wallet.sign_transaction(transaction_dict, sk)
        return sig

    def sign_message(self, message: str, id: int):
        self._id_existing(id)

        sk = self.secret_key_derive(id)
        sig = self.__cold_wallet.sign_message(message, sk)
        return sig

    def get_all_ids(self):
        ids = self.__hot_wallet.get_ids()
        ids.pop(0)
        return ids

    @staticmethod
    def _get_address(public_key: dict):
        x = public_key["X"][2:]
        y = public_key["Y"][2:]
        preimage = x + y
        keccak256 = keccak(hexstr=preimage)
        return "0x" + keccak256.hex()[24:]

    def _sync_wallets(self):
        if self.__cold_wallet_synced:
            return
        self.__hot_wallet.copy_state_to(self.__cold_wallet.get_state_path())  # Copy state of hot wallet to cold wallet
        self.__cold_wallet_synced = True

    def _id_existing(self, id):
        self._sync_wallets()
        if id == 0:
            raise Exception("tudwallet - Requested ID is the initial one")
        if id not in self.__cold_wallet.get_ids():
            raise Exception("tudwallet - Derive session public/secret key with ID = " + str(id) + " first!")


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
            delete_files_in_folder(self.__base_directory)

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
        self._check_initialization()

        id_state_map = get_dict_from_file(self.__state_file_path)

        key_hash_map = {}
        if os.path.exists(self.__session_secret_file_path):
            key_hash_map = get_dict_from_file(self.__session_secret_file_path)
            if str(id) in key_hash_map:  # if key already derived return it directly from the key file
                return hex(int(str(key_hash_map[str(id)])))

        last_state = id_state_map[str(id - 1)]

        master_sec_key = get_private_key_from_file(self.__master_secret_file_path)  # Type: java.math.BigInteger

        session_secret_key = ColdWalletWrapper().sk_derive(master_sec_key, str(id), last_state).getSecretKey()
        key_hash_map[str(id)] = str(session_secret_key)
        save_dict_to_file(self.__session_secret_file_path, key_hash_map)

        return hex(int(str(key_hash_map[str(id)])))

    def sign_transaction(self, transaction_dict: dict, sk: PrivateKey):
        self._check_initialization()

        signature = account.Account.sign_transaction(transaction_dict, sk.key)
        return signature

    def sign_message(self, message: str, sk: PrivateKey):
        self._check_initialization()

        message_hash = encode_defunct(text=message)
        return account.Account.sign_message(message_hash, sk.key)

    def get_ids(self):
        id_state_map = get_dict_from_file(self.__state_file_path)
        return list(map(int, id_state_map.keys()))

    def get_max_id(self):
        if not os.path.exists(self.__state_file_path):
            raise Exception("No state file exists. Call master_key_gen first!")
        return max(self.get_ids())

    def get_base_path(self):
        return self.__base_directory

    def get_state_path(self):
        return self.__state_file_path

    def copy_state_to(self, path):
        copyfile(self.__state_file_path, path)

    def copy_mpk_to(self, path):
        copyfile(self.__master_public_file_path, path)

    def _check_initialization(self):
        if not os.path.exists(self.__master_secret_file_path):
            raise Exception("Wallet not initialized yet. Call master_key_gen first!")


class _HotWallet:
    def __init__(self, directory):
        if not os.path.exists(directory):
            os.mkdir(directory)

        self.__master_public_file_path = directory + MPK_FILE_NAME
        self.__session_public_file_path = directory + SPK_FILE_NAME
        self.__state_file_path = directory + STATE_FILE_NAME
        self.__base_directory = directory

    def public_key_derive(self, id):
        if not os.path.exists(self.__master_public_file_path):
            raise Exception("Wallet not initialized yet. Call master_key_gen first!")

        id_state_map = get_dict_from_file(self.__state_file_path)
        last_state = id_state_map[str(self.get_max_id())]

        key_hash_map = {}
        if os.path.exists(self.__session_public_file_path):
            key_hash_map = get_dict_from_file(self.__session_public_file_path)
            if str(id) in key_hash_map:  # if key already derived return it directly from the key file
                key = key_hash_map[str(id)].split(",")
                x = hex(int(str(key[0])))
                y = hex(int(str(key[1])))
                return {"X": x, "Y": y}

        master_public_key = get_public_key_from_file(self.__master_public_file_path)
        pk = HotWalletWrapper().pk_derive(master_public_key, str(id), last_state)
        session_public_key = pk.getPublicKey()

        next_state = pk.getState()
        id_state_map[str(id)] = list(next_state)
        save_dict_to_file(self.__state_file_path, id_state_map)

        key_hash_map[str(id)] = str(session_public_key.getPointX()) + "," + str(session_public_key.getPointY())
        save_dict_to_file(self.__session_public_file_path, key_hash_map)

        return {"X": hex(int(str(session_public_key.getPointX()))), "Y": hex(int(str(session_public_key.getPointY())))}

    def get_state_path(self):
        return self.__state_file_path

    def get_mpk_path(self):
        return self.__master_public_file_path

    def get_base_path(self):
        return self.__base_directory

    def copy_state_to(self, path):
        copyfile(self.__state_file_path, path)

    def get_ids(self):
        id_state_map = get_dict_from_file(self.__state_file_path)
        return list(map(int, id_state_map.keys()))

    def get_max_id(self):
        if not os.path.exists(self.__state_file_path):
            raise Exception("No state file exists. Call master_key_gen first!")
        return max(self.get_ids())
