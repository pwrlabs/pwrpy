import coincurve
from Crypto.Hash import keccak
import binascii
from io import BytesIO
from pwrapisdk import broadcast_txn

from signer import Signature


class KeyPair:
    public_key = None
    private_key = None

    def __init__(self, private_key, public_key):
        self.public_key = public_key
        self.private_key = private_key


class PWRWallet:
    def __init__(self, private_key_hex=None):
        if private_key_hex:
            self.private_key = coincurve.PrivateKey.from_hex(private_key_hex)
        else:
            self.private_key = coincurve.PrivateKey()
        self.public_key = self.private_key.public_key

    def getPrivateKey(self):
        return self.private_key.to_hex()

    def getPublicKey(self):
        public_hex = self.public_key.format(compressed=False).hex()[2:]
        return public_hex

    def getAddress(self):
        public_hex = self.getPublicKey()
        keccak_hash = keccak.new(digest_bits=256)
        keccak_hash.update(bytes.fromhex(public_hex))
        address_bytes = keccak_hash.digest()[-20:]
        return "0x" + address_bytes.hex()

    def transferPWR(self, to, amount, nonce):
        if len(to.strip()) != 42:
            raise RuntimeError("Invalid address")
        if amount < 0:
            raise RuntimeError("Amount cannot be negative")
        if nonce < 0:
            raise RuntimeError("Nonce cannot be negative")
        # if amount + (98 * self.PWRJ.getFeePerByte()) > self.getBalance():
        #     raise RuntimeError("Insufficient balance")
        # if nonce < self.getNonce():
        #     raise RuntimeError("Nonce is too low")

        buffer = bytearray(33)
        buffer[0] = 0
        buffer[1:5] = nonce.to_bytes(4, byteorder='big')
        buffer[5:13] = amount.to_bytes(8, byteorder='big')
        buffer[13:] = binascii.unhexlify(to[2:])
        txn = bytes(buffer)
        signature = Signature.sign_message(self.private_key, txn)

        final_txn = bytearray(98)
        final_txn[:33] = txn
        final_txn[33:] = signature

        response = broadcast_txn(final_txn)
        if response.success:
            txn_hash = Signature.create_tx_hash_hex(final_txn).hex()
            return "0x" + txn_hash
        else:
            return None
