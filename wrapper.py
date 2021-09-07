# Allow Java modules to be imported
import jpype.imports

# Start JVM with Java types on return
jpype.startJVM("-ea", classpath=['lib/*'], convertStrings=False)

# import the Java modules
from com.ewallet.field import ColdWallet
from com.ewallet.field import HotWallet
from com.ewallet.field.util import SECP
from com.ewallet.field.util import EllipticCurvePoint
from com.ewallet.field.util import PublicKey
from com.trident.crypto.field.element import FiniteFieldElementFactory


class ColdWalletWrapper:

    def __init__(self, spec=SECP.SECP256K1, hash_algorithm="SHA-256"):
        self.cold_wallet = ColdWallet(spec, hash_algorithm)

    def master_gen(self):
        return self.cold_wallet.MasterGen()

    def sk_derive(self, master_sk, id, state):
        return self.cold_wallet.SKDerive(master_sk, id, state)

    def pk_derive(self, master_pk, id, state):
        return self.cold_wallet.PKDerive(master_pk, id, state)

    def sign(self, msg, secret_key, public_key):
        return self.cold_wallet.sign(msg, secret_key, public_key)


class HotWalletWrapper:

    def __init__(self, spec=SECP.SECP256K1, hash_algorithm="SHA-256"):
        self.hot_wallet = HotWallet(spec, hash_algorithm)

    def pk_derive(self, master_pk, id, state):
        return self.hot_wallet.PKDerive(master_pk, id, state)

    def verify(self, msg, public_key, signature):
        return self.hot_wallet.verify(msg, public_key, signature)


# (Not in utils file because JVM needed)
def create_elliptic_curve_point(x, y):
    factory = FiniteFieldElementFactory()
    converted_x = factory.createFrom(jpype.java.math.BigInteger(x))
    converted_y = factory.createFrom(jpype.java.math.BigInteger(y))

    return EllipticCurvePoint.create(converted_x, converted_y)


def hex_to_java_biginteger(hex_string):
    return jpype.java.math.BigInteger(str(int(hex_string, 0)))


def coords_to_java_public_key(x, y, raw_state: list):
    curve_point = create_elliptic_curve_point(str(int(x, 0)), str(int(y, 0)))
    return PublicKey(curve_point, jpype.java.bytes(raw_state))  # TODO: Check casting to bytes array - likely wrong
