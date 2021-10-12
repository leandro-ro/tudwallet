import os
from dataclasses import dataclass

import jpype
import json

from wrapper import create_elliptic_curve_point


@dataclass
class PublicKey:
    """This dataclass wraps all information regarding a derived public key.
    It includes its ethereum address, its id and the public key coordinates. """
    address: str
    id: int
    x: str
    y: str


@dataclass
class PrivateKey:
    """This dataclass wraps all information regarding a derived private key.
        It includes the private key and the id used for deriving."""
    key: str
    id: int


def save_dict_to_file(path, data: dict):
    """
    Allows to store any dictionary in a file under the given path.

    :param path: the path where the dictionary should be stored at
    :param dict data: the state to be stored
    """
    with open(path, 'w') as txt_file:
        json.dump(data, txt_file)
        txt_file.close()


def get_dict_from_file(path) -> dict:
    """
    Allows to load any dictionary (that has been stored via save_dict_to_file()) from a file under the given path.

    :param path: the path where the file is located
    :return: the loaded dictionary
    """
    with open(path, 'r') as txt_file:
        data = txt_file.readlines()
        return json.loads(data[0])


def get_private_key_from_file(path):
    """
    Allows to load a private key from a file under the given path.

    :param path: the path where the private key is located
    :return: the private key as java BigInteger
    """
    with open(path, 'r') as key_file:
        data = key_file.readlines()[0]
        key_file.close()

    data = jpype.java.math.BigInteger(data)
    return data


def get_public_key_from_file(path):
    """
    Allows to load a public key from a file under the given path.

    :param path: the path where the public key is located
    :return: the private key as a java EllipticCurvePoint
    """
    with open(path, 'r') as key_file:
        data = key_file.readlines()
        key_file.close()

    data = create_elliptic_curve_point(data[0].replace('\n', ''), data[1])
    return data


def delete_files_in_folder(path):
    """
    Deletes everything inside a certain directory given as a path.
    Intended to be used with the overwrite functionality of the wallet.
    Note that also all sub directories are being deleted.
    The result is an empty directory under path.
    Use with caution!

    :param path: the path to the directory which files/directories are to be deleted
    """
    for root, dirs, files in os.walk(path):
        for file in files:
            os.remove(os.path.join(root, file))