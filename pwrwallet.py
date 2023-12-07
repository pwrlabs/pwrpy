import coincurve
from Crypto.Hash import keccak
import binascii
from io import BytesIO
from pwrapisdk import PWRPY

from signer import Signature


class WalletResponse:
    def __init__(self, success, txnHash, error=None):
        self.success = success
        self.txnHash = txnHash
        self.error = error


class PWRWallet:
    def __init__(self, private_key_hex=None):
        if private_key_hex:
            self.private_key = coincurve.PrivateKey.from_hex(private_key_hex)
        else:
            self.private_key = coincurve.PrivateKey()
        self.public_key = self.private_key.public_key

    def get_private_key(self):
        return self.private_key.to_hex()

    def get_public_key(self):
        public_hex = self.public_key.format(compressed=False).hex()[2:]
        return public_hex

    def get_address(self):
        public_hex = self.get_public_key()
        keccak_hash = keccak.new(digest_bits=256)
        keccak_hash.update(bytes.fromhex(public_hex))
        address_bytes = keccak_hash.digest()[-20:]
        return "0x" + address_bytes.hex()

    def get_nonce(self):
        nonce = PWRPY.get_nonce_of_address(self.get_address())
        if not nonce.success:
            raise RuntimeError(nonce.message)
        return nonce.data

    def get_balance(self):
        balance_result = PWRPY.get_balance_of_address(self.get_address())
        if not balance_result.success:
            raise RuntimeError(balance_result.message)
        return balance_result.data

    def __create_wallet_response(self, response, final_txn):
        if response.success:
            txn_hash = Signature.create_tx_hash_hex(final_txn).hex()
            return WalletResponse(True, "0x" + txn_hash)
        else:
            return WalletResponse(False, None, response.message)

    def transfer_pwr(self, to, amount, nonce=None):
        if nonce is None:
            nonce_response = PWRPY.get_nonce_of_address(self.get_address())
            if not nonce_response.success:
                return WalletResponse(False, None, nonce_response.message)
            nonce = nonce_response.data

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

        response = PWRPY.broadcast_txn(final_txn)
        return self.__create_wallet_response(response, final_txn)

    def send_vm_data_txn(self, vmId, data, nonce=None):
        if nonce is None:
            nonce_response = PWRPY.get_nonce_of_address(self.get_address())
            if not nonce_response.success:
                return WalletResponse(False, None, nonce_response.message)
            nonce = nonce_response.data

        if nonce < 0:
            raise RuntimeError("Nonce cannot be negative")
        if nonce < self.get_nonce():
            raise RuntimeError("Nonce is too low")

        data_len = len(data)

        buffer = bytearray(13 + data_len)
        buffer[0] = 5
        buffer[1:5] = nonce.to_bytes(4, byteorder='big')
        buffer[5:13] = vmId.to_bytes(8, byteorder='big')
        buffer[13:] = data
        txn = bytes(buffer)
        signature = Signature.sign_message(self.private_key, txn)

        txn_len = len(txn)

        final_txn = bytearray(13 + 65 + data_len)
        final_txn[:txn_len] = txn
        final_txn[txn_len:] = signature

        response = PWRPY.broadcast_txn(final_txn)
        return self.__create_wallet_response(response, final_txn)

    def delegate(self, to, amount, nonce=None):
        if nonce is None:
            nonce_response = PWRPY.get_nonce_of_address(self.get_address())
            if not nonce_response.success:
                return WalletResponse(False, None, nonce_response.message)
            nonce = nonce_response.data

        buffer = bytearray(33)
        buffer[0] = 3
        buffer[1:5] = nonce.to_bytes(4, byteorder='big')
        buffer[5:13] = amount.to_bytes(8, byteorder='big')
        buffer[13:] = binascii.unhexlify(to[2:])
        txn = bytes(buffer)
        signature = Signature.sign_message(self.private_key, txn)

        txn_len = len(txn)

        final_txn = bytearray(txn_len + 65)
        final_txn[:txn_len] = txn
        final_txn[txn_len:] = signature

        response = PWRPY.broadcast_txn(final_txn)
        return self.__create_wallet_response(response, final_txn)

    def withdraw(self, from_wallet, shares_amount, nonce=None):
        if nonce is None:
            nonce_response = PWRPY.get_nonce_of_address(self.get_address())
            if not nonce_response.success:
                return WalletResponse(False, None, nonce_response.message)
            nonce = nonce_response.data

        buffer = bytearray(33)
        buffer[0] = 4
        buffer[1:5] = nonce.to_bytes(4, byteorder='big')
        buffer[5:13] = shares_amount.to_bytes(8, byteorder='big')
        buffer[13:] = binascii.unhexlify(from_wallet[2:])
        txn = bytes(buffer)
        signature = Signature.sign_message(self.private_key, txn)

        txn_len = len(txn)

        final_txn = bytearray(txn_len + 65)
        final_txn[:txn_len] = txn
        final_txn[txn_len:] = signature

        response = PWRPY.broadcast_txn(final_txn)
        return self.__create_wallet_response(response, final_txn)

    def claim_vm_id(self, vm_id, nonce=None):
        if nonce is None:
            nonce_response = PWRPY.get_nonce_of_address(self.get_address())
            if not nonce_response.success:
                return WalletResponse(False, None, nonce_response.message)
            nonce = nonce_response.data

        buffer = bytearray(13)
        buffer[0] = 6
        buffer[1:5] = nonce.to_bytes(4, byteorder='big')
        buffer[5:13] = vm_id.to_bytes(8, byteorder='big')
        txn = bytes(buffer)
        signature = Signature.sign_message(self.private_key, txn)

        txn_len = len(txn)

        final_txn = bytearray(txn_len + 65)
        final_txn[:txn_len] = txn
        final_txn[txn_len:] = signature

        response = PWRPY.broadcast_txn(final_txn)
        return self.__create_wallet_response(response, final_txn)
