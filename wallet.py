# Author: Leandro Rometsch, 2021
# Email: leandro@rometsch.org
# TU Darmstadt, Chair of Applied Cryptography

from shutil import copyfile

from eth_account import account
from eth_account.messages import encode_defunct
from eth_utils import keccak

from utils.support import *
from utils.wrapper import ColdWalletWrapper, HotWalletWrapper

MPK_FILE_NAME = "MPK.key"  # Master Public Key
MSK_FILE_NAME = "MSK.key"  # Master Secret Key
SSK_FILE_NAME = "SecretKeyID.key"  # Session Secret Keys
SPK_FILE_NAME = "PublicKeyID.key"  # Session Public Keys
STATE_FILE_NAME = "state.txt"


class Wallet:
    """The main (HD) wallet, which joins hot and cold wallet functionality by performing sync/state management"""

    def __init__(self, base_directory_hw="data/", base_directory_cw="data/"):
        """
        Instantiate an hot & cold wallet and prepare directories.

        :param base_directory_hw: specifies the storage location of the hot wallet
        :param base_directory_cw: specifies the storage location of the cold wallet
        """
        if not os.path.exists(base_directory_hw):
            os.makedirs(base_directory_hw)
        if not os.path.exists(base_directory_cw):
            os.makedirs(base_directory_cw)

        self.__cold_wallet = _ColdWallet(base_directory_cw + "ColdWalletData/")
        self.__hot_wallet = _HotWallet(base_directory_hw + "HotWalletData/")
        self.__cold_wallet_synced = False

    def generate_master_key(self, overwrite=False):
        """
        Generate the master key pair of the wallet.

        :param overwrite: replace a possibly existing key pair (or not)
        """
        self.__cold_wallet.master_key_gen(overwrite=overwrite)  # Potential overwrite exception already raised here

        if overwrite:
            delete_files_in_folder(self.__hot_wallet.get_base_path())

        self.__cold_wallet.copy_state_to(self.__hot_wallet.get_state_path())  # Transfer initial state
        self.__cold_wallet.copy_mpk_to(self.__hot_wallet.get_mpk_path())  # Init hot_wallet with MPK
        self.__cold_wallet_synced = True  # The initial state is the same for both wallets

    def secret_key_derive(self, id=None):
        """
        Derives a new session secret key based on the given id.
        If no id is given, create the session secret key for the last derived session public key.
        If the id is already existing, return the key from keystore.

        :param id: specifies the id (as int)
        :return: the session private key as dataclass "PrivateKey"
        """
        self._sync_wallets()  # Cold wallet must come "online" for secret key derive, therefore sync necessary

        if id is None:  # if id is not specified create session secret key for latest (id) derived public key
            max_id = self.__cold_wallet.get_max_id()

            if max_id < 1:  # If no public key has been derived throw exception
                raise Exception("tudwallet - Derive session public key first!")

            sk_raw = self.__cold_wallet.secret_key_derive(max_id)
            return PrivateKey(key=sk_raw, id=max_id)

        if id not in self.__cold_wallet.get_ids():  # if there is no public key derived from given id throw Exception
            raise Exception("tudwallet - Derive session public key with ID = " + str(id) + " first!")

        sk_raw = str(self.__cold_wallet.secret_key_derive(id))

        # Normalize secret key here to prevent loss of a zero byte
        sk_raw_len = len(sk_raw)
        if sk_raw_len < 66:
            sk_raw = sk_raw[2:]  # remove 0x

            i = 66 - sk_raw_len
            for p in range(0, i):
                sk_raw = "0" + sk_raw

            sk_raw = "0x" + sk_raw

        return PrivateKey(key=sk_raw, id=id)

    def public_key_derive(self, id=None):
        """
        Derives a new session public key based on the given id.
        If no id is given, create the session public key for the next possible id (= old_id + 1).
        If the id is already existing, return the key from keystore.

        :param id: specifies the id
        :return: the session public key as dataclass "PublicKey"
        """
        max_id = self.__hot_wallet.get_max_id()
        if id is not None:
            if id <= max_id:  # in this case, check if a key from this id is already derived.
                if id not in self.__hot_wallet.get_ids():  # If not, throw an Exception
                    raise Exception("tudwallet - ID is lower then previous IDs. Choose ID higher than: " + str(max_id))
                else:  # If yes, return the already derived key
                    raw_pk = self.__hot_wallet.public_key_derive(id)
                    return PublicKey(self._get_address(raw_pk), id, raw_pk["X"], raw_pk["Y"])
            next_id = id
        else:  # If no id is given, derive the next key with the next higher id (= old_id +1)
            next_id = max_id + 1

        self.__cold_wallet_synced = False  # Change happened in hot_wallet
        raw_pk = self.__hot_wallet.public_key_derive(next_id)
        return PublicKey(self._get_address(raw_pk), next_id, raw_pk["X"], raw_pk["Y"])

    def sign_transaction(self, transaction_dict, id: int):
        """
        Generates a ECDSA signature for the given transaction based on a already derived key pair given by id.

        :param dict transaction_dict: the transaction with nonce, chainId, to, data, value, gas, gasPrice, ...
        :param id: id of an already derived session key pair
        :return: the signed transaction, containing the rawTransaction, the transactionHash and v, r, s
        """
        self._id_existing(id)
        if not isinstance(transaction_dict, dict):
            raise TypeError("tudwallet - Transaction given in unsupported format. Provide as dict with keys: nonce, "
                            "chainId, to, data, value, gas, and gasPrice.")

        sk = self.secret_key_derive(id)  # Note that in this case no new key is derived. We only fetch the "old" one
        sig = self.__cold_wallet.sign_transaction(transaction_dict, sk)
        return sig

    def sign_message(self, message, id: int):
        """
        Generates a ECDSA signature for the given message based on a already derived key pair given by id.

        :param message: a message given as string or bytes
        :param id: id of an already derived session key pair
        :return: the signed message, containing the messageHash, the signature in Hex and v, r, s
        """
        self._id_existing(id)

        sk = self.secret_key_derive(id)  # Note that in this case no new key is derived. We only fetch the "old" one
        sig = self.__cold_wallet.sign_message(message, sk)
        return sig

    def get_all_ids(self):
        """
        Learn all ids of already derived session public keys.

        :return: all ids used to derive public keys
        """
        ids = self.__hot_wallet.get_ids()
        ids.pop(0)  # 0 is always present because of the master key pair
        return ids

    @staticmethod
    def _get_address(public_key: dict):
        """
        Generates the Ethereum address from a given public key.

        :param public_key: containing x and y coordinates
        :return: the Ethereum address of the given public key
        """
        x = public_key["X"][2:]
        y = public_key["Y"][2:]

        i = 64 - len(x)
        for i in range(0, i):
            x = "0" + x

        i = 64 - len(y)
        for i in range(0, i):
            y = "0" + y

        preimage = x + y
        keccak256 = keccak(hexstr=preimage)
        return "0x" + keccak256.hex()[24:]

    def _sync_wallets(self):
        """
        Sync the hot wallet with the cold wallet by transferring the state.
        """
        if self.__cold_wallet_synced:  # Mitigate unnecessary access to the cold wallet
            return
        self.__hot_wallet.copy_state_to(self.__cold_wallet.get_state_path())  # Copy state of hot wallet to cold wallet
        self.__cold_wallet_synced = True

    def _id_existing(self, id):
        """
        Check if a key pair is already derived from the given id. Both, public and private, keys are needed to be
        derived first otherwise this function will raise an exception.

        :param id: the id to be checked
        """
        self._sync_wallets()
        if id == 0:
            raise Exception("tudwallet - Requested ID is the initial one")
        if id not in self.__cold_wallet.get_ids():
            raise Exception("tudwallet - Derive session public/secret key with ID = " + str(id) + " first!")


class _ColdWallet:
    """The cold wallet. Most notably implementing the wallets signing functionality."""

    def __init__(self, directory):
        """
        Initializes the cold wallet keystore.

        :param directory: the directory the cold wallet will use for keystore
        """
        if not os.path.exists(directory):
            os.mkdir(directory)

        self.__master_secret_file_path = directory + MSK_FILE_NAME
        self.__master_public_file_path = directory + MPK_FILE_NAME
        self.__state_file_path = directory + STATE_FILE_NAME
        self.__session_secret_file_path = directory + SSK_FILE_NAME
        self.__base_directory = directory

    def master_key_gen(self, overwrite=False):
        """
        Generate the master key pair of the wallet.
        If overwrite is False but there is already a key pair existing an exception is raised.

        :param overwrite: replace a possibly existing key pair
        """
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
        """
        Derives a new session secret key based on the given id. A master key pair must be present.
        If a key with the given id has been derived earlier, return it from keystore.

        :param id: specifies the id (as int)
        :return: the session private key in hex
        """
        self._check_initialization()  # Check if master key pair present

        id_state_map = get_dict_from_file(self.__state_file_path)

        key_hash_map = {}
        if os.path.exists(self.__session_secret_file_path):
            key_hash_map = get_dict_from_file(self.__session_secret_file_path)
            if str(id) in key_hash_map:  # if key already derived return it directly from the key file
                return hex(int(str(key_hash_map[str(id)])))

        last_state_id = find_second_highest_key_in_dict(id_state_map)
        last_state = id_state_map[last_state_id]

        master_sec_key = get_private_key_from_file(self.__master_secret_file_path)  # Type: java.math.BigInteger

        session_secret_key = ColdWalletWrapper().sk_derive(master_sec_key, str(id), last_state).getSecretKey()
        key_hash_map[str(id)] = str(session_secret_key)
        save_dict_to_file(self.__session_secret_file_path, key_hash_map)  # Add the new key to keystore

        return hex(int(str(key_hash_map[str(id)])))

    def sign_transaction(self, transaction_dict: dict, sk: PrivateKey):
        """
        Sign a transaction which is given as a dict.
        Currently using eth_account's signing functionality.
        Might switch to the wrapper.py signing functionality in future work.

        :param dict transaction_dict: the ethereum transaction
        :param sk: the session secret key as PrivateKey dataclass
        :return: the signed transaction
        """
        self._check_initialization()

        signature = account.Account.sign_transaction(transaction_dict, sk.key)
        return signature

    def sign_message(self, message, sk: PrivateKey):
        """
        Sign a message given as string or bytes.
        Currently using eth_account's signing functionality.
        Might switch to the wrapper.py signing functionality in future work.

        :param message: the message to be signed
        :param sk: the session secret key as PrivateKey dataclass
        :return: the signed message
        """
        self._check_initialization()

        if type(message) is str:
            message_hash = encode_defunct(text=message)
        elif type(message) is bytes:
            message_hash = encode_defunct(primitive=message)
        else:
            raise Exception("Message type not supported. Please provide as string or bytes.")

        return account.Account.sign_message(message_hash, sk.key)

    def get_ids(self):
        """
        List all ids that were used to derive keys earlier

        :return: already used ids
        """
        id_state_map = get_dict_from_file(self.__state_file_path)
        return list(map(int, id_state_map.keys()))

    def get_max_id(self):
        """
        Extracts the highest/latest id of all ids that were used to derive keys earlier.
        Note that a new key pair is always derived from a higher id than the previous key pair has been.

        :return: latest id
        """
        if not os.path.exists(self.__state_file_path):
            raise Exception("No state file exists. Call master_key_gen first!")
        return max(self.get_ids())

    def get_base_path(self):
        """
        Getter: Get the directory where the data of the cold wallet is stored.

        :return: the cold wallet directory
        """
        return self.__base_directory

    def get_state_path(self):
        """
        Getter: Get the path where the cold wallet state is stored.

        :return: cold wallet's state path
        """
        return self.__state_file_path

    def copy_state_to(self, path):
        """
        Copies the state of the cold wallet to a given location.
        Note that this does not copy any keys! Only the state file.
        This function is intended to to transfer the initial state for the hot wallet initialization.

        :param path: the path where the cold wallet state should be copied to
        """
        copyfile(self.__state_file_path, path)

    def copy_mpk_to(self, path):
        """
        Copies the master public key to a given location.
        Note that this does not copy the master secret key!
        This function is intended to be used for the hot wallet initialization.

        :param path: the path where the master public key should be copied to
        """
        copyfile(self.__master_public_file_path, path)

    def _check_initialization(self):
        """
        Check if the wallet is initialized.
        The wallet is initialized iff the master key is existing inside the cold wallet directory.
        If this function is called and the condition is not met, an exception is raised.
        """
        if not os.path.exists(self.__master_secret_file_path):
            raise Exception("Wallet not initialized yet. Call master_key_gen first!")


class _HotWallet:
    """The hot wallet. Most notably implementing the wallets session public key derivation."""

    def __init__(self, directory):
        """
        Initializes the hot wallet keystore.

        :param directory: the directory the hot wallet will use for keystore
        """
        if not os.path.exists(directory):
            os.mkdir(directory)

        self.__master_public_file_path = directory + MPK_FILE_NAME
        self.__session_public_file_path = directory + SPK_FILE_NAME
        self.__state_file_path = directory + STATE_FILE_NAME
        self.__base_directory = directory

    def public_key_derive(self, id):
        """
        Derives a new session public key based on the given id. A master public key must be present.
        If a key with the given id has been derived earlier, return it from keystore.

        :param id: specifies the id (as int)
        :return: the session public key coordinates in hex as dict
        """
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
        save_dict_to_file(self.__state_file_path, id_state_map)  # save new state in state file

        key_hash_map[str(id)] = str(session_public_key.getPointX()) + "," + str(session_public_key.getPointY())
        save_dict_to_file(self.__session_public_file_path, key_hash_map)  # save new key in keystore

        return {"X": hex(int(str(session_public_key.getPointX()))), "Y": hex(int(str(session_public_key.getPointY())))}

    def get_state_path(self):
        """
        Getter: Get the path where the hot wallet state is stored.

        :return: hot wallet's state path
        """
        return self.__state_file_path

    def get_mpk_path(self):
        """
        Getter: Get the path where the master public key is stored.

        :return: master public key path
        """
        return self.__master_public_file_path

    def get_base_path(self):
        """
        Getter: Get the directory where all the data of the hot wallet is stored.

        :return: the cold wallet directory
        """
        return self.__base_directory

    def copy_state_to(self, path):
        """
        Copies the state of the hot wallet to a given location.
        Note that this does not copy any keys! Only the state file.
        This function is intended to be used for the wallet synchronization.

        :param path: the path where the hot wallet state should be copied to
        """
        copyfile(self.__state_file_path, path)

    def get_ids(self):
        """
        List all ids that were used to derive public session keys earlier

        :return: already used ids
        """
        id_state_map = get_dict_from_file(self.__state_file_path)
        return list(map(int, id_state_map.keys()))

    def get_max_id(self):
        """
        Extracts the highest/latest id of all ids that were used to derive public session keys earlier.
        Note that a new key pair is always derived from a higher id than the previous key pair has been.

        :return: latest public session key id
        """
        if not os.path.exists(self.__state_file_path):
            raise Exception("No state file exists. Call master_key_gen first!")
        return max(self.get_ids())
