import coincurve
from Crypto.Hash import keccak
from coincurve import keys
from ecdsa import SECP256k1


class Signature:
    CURVE = SECP256k1
    HALF_CURVE_ORDER = SECP256k1.order // 2

    @staticmethod
    def sign_message_hex(private_key_hex, message):
        private_key_bytes = bytes.fromhex(private_key_hex)
        keccak_hash = keccak.new(digest_bits=256)
        keccak_hash.update(message.encode("utf-8"))
        message_hash = keccak_hash.digest()

        private_key = coincurve.PrivateKey(private_key_bytes)

        signature = private_key.sign_recoverable(message_hash, hasher=None)

        signature = signature[:-1] + bytes([signature[-1] + 27])

        return signature

    @staticmethod
    def create_tx_hash_hex(txn_data):
        keccak_hash = keccak.new(digest_bits=256)
        keccak_hash.update(txn_data)
        return keccak_hash.digest()

    @staticmethod
    def sign_message(private_key, message):
        private_key_bytes = private_key.to_bytes(32, 'big')
        # Create a PrivateKey object
        private_key = keys.PrivateKey(private_key_bytes)
        keccak_hash = keccak.new(digest_bits=256)
        keccak_hash.update(message)
        message_hash = keccak_hash.digest()

        signature = private_key.sign_recoverable(message_hash, hasher=None)

        signature = signature[:-1] + bytes([signature[-1] + 27])
        return signature
