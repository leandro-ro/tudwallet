from wrapper import ColdWalletWrapper, HotWalletWrapper
import os
from shutil import copyfile
from utils import *

MPK_FILE_NAME = "MPK.key"  # Master Public Key
MSK_FILE_NAME = "MSK.key"  # Master Secret Key
SSK_FILE_NAME = "SecretKeyID.key"  # Session Secret Keys
STATE_FILE_NAME = "state.txt"
SIG_FILE_NAME = "signature.sig"


class Wallet:
    def __init__(self, base_directory):
        self.cold_wallet = _ColdWallet()
        self.hot_wallet = _HotWallet()
        self.cold_wallet_synced = False

    def generate_master_key(self, overwrite=False):
        self.cold_wallet.master_key_gen(overwrite=overwrite)

        self.cold_wallet.copy_state_to(self.hot_wallet.get_state_path())  # Transfer initial state
        self.cold_wallet.copy_mpk_to(self.hot_wallet.get_mpk_path())  # Init hot_wallet with MPK
        self.cold_wallet_synced = True  # The initial state is the same for both wallets

    def sync_wallets(self):
        self.hot_wallet.copy_state_to(self.cold_wallet.get_state_path)  # Copy state of hot wallet to cold wallet
        self.cold_wallet_synced = True


class _ColdWallet:
    def __init__(self, directory="ColdWalletData/"):
        self.__master_secret_file_path = directory + MSK_FILE_NAME
        self.__master_public_file_path = directory + MPK_FILE_NAME
        self.__state_file_path = directory + STATE_FILE_NAME
        self.__session_secret_file_path = directory + SSK_FILE_NAME
        self.__signature_file_path = directory + SIG_FILE_NAME
        self.__base_directory = directory

    def master_key_gen(self, overwrite=False):
        cww = ColdWalletWrapper()

        if not overwrite and os.path.exists(self.__master_secret_file_path):
            raise Exception("Master Secret Key already created. You must use this function with overwrite=True to "
                            "create a new one")
        elif overwrite:
            for root, dirs, files in os.walk(self.__base_directory):
                for file in files:
                    os.remove(os.path.join(root, file))

        key = cww.master_gen()
        state = key.getState()  # 32 Bytes

        id_state_map = {0: list(state)}  # dict is the state data structure
        update_dict_file(self.__signature_file_path, id_state_map)  # write dict to file

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

    def secret_key_derive(self):
        pass # TODO

    def get_state_path(self):
        return self.__state_file_path

    def copy_state_to(self, path):
        copyfile(self.__state_file_path, path)

    def copy_mpk_to(self, path):
        copyfile(self.__state_file_path, path)


class _HotWallet:
    def __init__(self, directory="HotWalletData/"):
        self.__master_public_file_path = directory + MPK_FILE_NAME
        self.__state_file_path = directory + STATE_FILE_NAME

    def get_state_path(self):
        return self.__state_file_path

    def get_mpk_path(self):
        return self.__master_public_file_path

    def copy_state_to(self, path):
        copyfile(self.__state_file_path, path)
