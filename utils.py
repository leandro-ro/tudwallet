import jpype, json
from wrapper import create_elliptic_curve_point


def update_dict_file(path, state_dict: dict):
    with open(path, 'w') as txt_file:
        json.dump(state_dict, txt_file)
        txt_file.close()


def get_dict_from_file(path) -> dict:
    with open(path, 'r') as txt_file:
        data = txt_file.readlines()
        return json.loads(data[0])


def get_private_key_from_file(path):
    with open(path, 'r') as key_file:
        data = key_file.readlines()[0]
        key_file.close()

    data = jpype.java.math.BigInteger(data)
    return data


def get_public_key_from_file(path):
    with open(path, 'r') as key_file:
        data = key_file.readlines()
        key_file.close()

    data = create_elliptic_curve_point(data[0].replace('\n', ''), data[1])
    return data


def write_signature_to_file(path, signature):
    with open(path, "w") as sig_file:
        json.dump(signature, sig_file)
        sig_file.close()
        return True
