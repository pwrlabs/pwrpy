import io
import time

import coincurve
from Crypto.Hash import keccak
import struct
from pwrpy.pwrapisdk import PWRPY
from pwrpy.signer import Signature


class WalletResponse:
    def __init__(self, success, txnHash, error=None):
        self.success = success
        self.txnHash = txnHash
        self.error = error


class PWRWallet:
    pwrsdk: PWRPY = None

    def __init__(self, pwrsdk, private_key_hex=None):
        if private_key_hex:
            self.private_key = coincurve.PrivateKey.from_hex(private_key_hex)
        else:
            self.private_key = coincurve.PrivateKey()
        self.public_key = self.private_key.public_key
        self.pwrsdk = pwrsdk

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
        nonce = self.pwrsdk.get_nonce_of_address(self.get_address())
        return nonce

    def get_balance(self):
        balance_result = self.pwrsdk.get_balance_of_address(self.get_address())
        return balance_result

    @staticmethod
    def __create_wallet_response(response, final_txn):
        if response.success:

            txn_hash = Signature.create_tx_hash_hex(final_txn).hex()
            return WalletResponse(True, "0x" + txn_hash)
        else:
            return WalletResponse(False, None, response.message)

    def transfer_pwr(self, to, amount, nonce=None):
        if nonce is None:
            nonce_response = self.pwrsdk.get_nonce_of_address(
                self.get_address())
            if not nonce_response.success:
                return WalletResponse(False, None, nonce_response.message)
            nonce = nonce_response.data

        if len(to.strip()) != 42:
            raise RuntimeError("Invalid address")
        if amount < 0:
            raise RuntimeError("Amount cannot be negative")
        if nonce < 0:
            raise RuntimeError("Nonce cannot be negative")

        final_txn = self.get_signed_transfer_pwr_Txn(to, amount, nonce)
        response = self.pwrsdk.broadcast_txn(final_txn)
        return self.__create_wallet_response(response, final_txn)

    def send_vm_data_txn(self, vmId, data, nonce=None):
        if nonce is None:
            nonce_response = self.pwrsdk.get_nonce_of_address(
                self.get_address())
            if not nonce_response.success:
                return WalletResponse(False, None, nonce_response.message)
            nonce = nonce_response.data

        if nonce < 0:
            raise RuntimeError("Nonce cannot be negative")
        if nonce < self.get_nonce().data:
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

        response = self.pwrsdk.broadcast_txn(final_txn)
        return self.__create_wallet_response(response, final_txn)

    def delegate(self, to, amount, nonce=None):
        if nonce is None:
            nonce_response = self.pwrsdk.get_nonce_of_address(
                self.get_address())
            if not nonce_response.success:
                return WalletResponse(False, None, nonce_response.message)
            nonce = nonce_response.data

        response = self.pwrsdk.broadcast_txn(self.get_signed_delegate_txn(to, amount, nonce))
        return self.__create_wallet_response(response, final_txn=response.data)

    def withdraw(self, from_wallet, shares_amount, nonce=None):
        if nonce is None:
            nonce_response = self.pwrsdk.get_nonce_of_address(
                self.get_address())
            if not nonce_response.success:
                return WalletResponse(False, None, nonce_response.message)
            nonce = nonce_response.data

        response = self.pwrsdk.broadcast_txn(self.get_signed_withdraw_txn(from_wallet, shares_amount, nonce))
        return self.__create_wallet_response(response, response.data)

    ### Transaction Base

    def get_txn_base(self, identifier, nonce):
        buffer = bytearray(6)
        struct.pack_into('c', buffer, 0, identifier)
        struct.pack_into('>i', buffer, 1, nonce)
        chain_id = self.pwrsdk.get_chainId()
        buffer[1:2] = chain_id
        return bytes(buffer)

    def get_signed_txn(self, txn):
        if txn is None:
            return None
        signature = Signature.sign_message(self.private_key, txn)
        # Create a byte buffer for the final transaction
        final_txn = bytearray(len(txn) + 65)

        # Copy the original transaction and signature to the final transaction buffer
        final_txn[:len(txn)] = txn
        final_txn[len(txn):] = signature

        return bytes(final_txn)

    ### Power Transfer Transactions
    def get_transfer_pwr_txn(self, to, amount, nonce):
        if len(to) != 40 and len(to) != 42:
            raise ValueError("Invalid address")
        if amount < 0:
            raise ValueError("Amount cannot be negative")
        if nonce < 0:
            raise ValueError("Nonce cannot be negative")

        if len(to) == 42:
            to = to[2:]

        txn_base = self.get_txn_base(b'\x00', nonce)
        buffer_size = len(txn_base) + 8 + 20
        buffer = bytearray(buffer_size)

        struct.pack_into(f'{len(txn_base)}s', buffer, 0, txn_base)  # Pack txnBase
        struct.pack_into('>q', buffer, len(txn_base), amount)  # Pack amount as long
        buffer[len(txn_base) + 8:] = bytes.fromhex(to)  # Pack 'to' address

        return bytes(buffer)

    def get_signed_transfer_pwr_Txn(self, to: str, amount: int, nonce: int):
        try:
            txn = self.get_signed_txn(self.get_transfer_pwr_txn(to, amount, nonce))
            return txn
        except IOError as e:
            print(f"An error occurred: {e}")

    ### Join Transactions
    def get_join_txn(self, ip: str, nonce: int):
        txn_base = self.get_txn_base(b'\x01', nonce)
        ip_bytes = ip.encode('utf-8')
        buffer_size = len(txn_base) + len(ip_bytes)
        buffer = bytearray(buffer_size)
        struct.pack_into(f'{len(txn_base)}s{len(ip_bytes)}s', buffer, 0, txn_base, ip_bytes)
        return bytes(buffer)

    def get_signed_join_txn(self, ip: str, nonce: int):
        try:
            txn = self.get_signed_txn(self.get_join_txn(ip, nonce))
            return txn
        except IOError as e:
            print(f"An error occurred:{e}")

    def join(self, ip: str, nonce: int = None):
        try:
            if nonce:
                return self.pwrsdk.broadcast_txn(self.get_signed_join_txn(ip, nonce))
            else:
                return self.pwrsdk.broadcast_txn(self.get_signed_join_txn(ip, self.get_nonce()))
        except IOError as e:
            print(f"An error occurred:{e}")

    ### Claim Transactions
    def get_claim_active_node_spot_txn(self, nonce: int):
        try:
            txnBase = self.get_txn_base(b'x02', nonce)
            return txnBase
        except IOError as e:
            print(f"An error occurred:{e}")

    def get_signed_claim_active_node_spot_txn(self, nonce: int):
        try:
            return self.get_signed_txn(self.get_claim_active_node_spot_txn(nonce))
        except IOError as e:
            print(f"An error occurred:{e}")

    def claim_active_node_spot(self, nonce: int = None):
        try:
            if nonce:
                return self.pwrsdk.broadcast_txn(self.get_signed_claim_active_node_spot_txn(nonce))
            else:
                return self.pwrsdk.broadcast_txn(self.get_signed_claim_active_node_spot_txn(self.get_nonce()))
        except IOError as e:
            print(f"An error occurred:{e}")

    ### Delegation Transactions
    def get_delegate_txn(self, to: str, amount: int, nonce: int):
        try:
            sender_length = len(to)
            if sender_length != 40 and sender_length != 42:
                raise RuntimeError("Invalid address")
            elif amount < 0:
                raise RuntimeError("Amount cannot be negative")
            elif nonce < 0:
                raise RuntimeError("Nonce cannot be negative")

            if sender_length == 42:
                to = to[2:]

            txn_base = self.get_txn_base(b'\x03', nonce)
            buffer_size = len(txn_base) + 8 + len(to) // 2
            buffer = bytearray(buffer_size)

            struct.pack_into(f'{len(txn_base)}s', buffer, 0, txn_base)  # Pack txnBase
            struct.pack_into('>q', buffer, len(txn_base), amount)  # Pack amount as long
            buffer[len(txn_base) + 8:] = bytes.fromhex(to)  # Pack 'to' address

            return bytes(buffer)
        except IOError as e:
            print(f"An error occurred:{e}")

    def get_signed_delegate_txn(self, to: str, amount: int, nonce: int):
        try:
            return self.get_signed_txn(self.get_delegate_txn(to, amount, nonce))
        except IOError as e:
            print(f"An error has occurred:{e}")

    ### Withdraw Transactions
    def get_withdraw_txn(self, from_address: str, shares_amount: int, nonce: int):
        try:
            address_length = len(from_address)
            if address_length != 40 and address_length != 42:
                raise ValueError("Invalid address")
            if shares_amount < 0:
                raise ValueError("Shares amount cannot be negative")
            if nonce < 0:
                raise ValueError("Nonce cannot be negative")

            if address_length == 42:
                from_address = from_address[2:]

            txn_base = self.get_txn_base(b'\x04', nonce)
            buffer_size = len(txn_base) + 8 + len(from_address) // 2
            buffer = bytearray(buffer_size)

            struct.pack_into(f'{len(txn_base)}s', buffer, 0, txn_base)  # Pack txnBase
            struct.pack_into('>q', buffer, len(txn_base), shares_amount)  # Pack sharesAmount as long
            buffer[len(txn_base) + 8:] = bytes.fromhex(from_address)  # Pack 'from' address

            return bytes(buffer)
        except IOError as e:
            print(f"An error has occurred:{e}")

    def get_signed_withdraw_txn(self, from_address: str, shares_amount: int, nonce: int):
        try:
            return self.get_signed_txn(self.get_withdraw_txn(from_address, shares_amount, nonce))
        except IOError as e:
            print(f"An error has occurred:{e}")

    ### Power Withdraw Transactions
    def get_withdraw_pwr_txn(self, from_address: str, pwr_amount: int, nonce: int):
        address_length = len(from_address)
        if address_length != 40 and address_length != 42:
            raise ValueError("Invalid address")
        if pwr_amount < 0:
            raise ValueError("PWR amount cannot be negative")
        if nonce < 0:
            raise ValueError("Nonce cannot be negative")

        if address_length == 42:
            from_address = from_address[2:]

        share_value = self.pwrsdk.get_share_value(from_address)
        shares_amount = int(pwr_amount / share_value)

        if shares_amount <= 0:
            raise ValueError("Shares amount is too low")

        txn_base = self.get_txn_base(b'\x04', nonce)
        buffer_size = len(txn_base) + 8 + address_length // 2
        buffer = bytearray(buffer_size)

        struct.pack_into(f'{len(txn_base)}s', buffer, 0, txn_base)  # Pack txnBase
        struct.pack_into('>q', buffer, len(txn_base), shares_amount)  # Pack sharesAmount as long
        buffer[len(txn_base) + 8:] = bytes.fromhex(from_address)  # Pack 'from' address

        return bytes(buffer)

    def get_signed_withdraw_pwr_txn(self, from_address: str, pwr_mount: int, nonce: int):
        try:
            return self.get_signed_txn(self.get_withdraw_pwr_txn(from_address, pwr_mount, nonce))
        except IOError as e:
            print(f"An error occurred:{e}")

    def withdraw_pwr(self, from_address: str, pwr_amount: int, nonce: int = None):
        if nonce:
            response = self.pwrsdk.broadcast_txn(self.get_signed_withdraw_pwr_txn(from_address, pwr_amount, nonce))
            return self.__create_wallet_response(response, response.data)
        else:
            response = self.pwrsdk.broadcast_txn(
                self.get_signed_withdraw_pwr_txn(from_address, pwr_amount, self.get_nonce()))
            return self.__create_wallet_response(response, response.data)

    ### Send VM Data Transactions
    def get_vm_data_txn(self, vm_id: int, data: bytes, nonce: int):
        try:
            if nonce < 0:
                raise ValueError("Nonce cannot be negative")
            if nonce < self.get_nonce():
                raise ValueError("Nonce is too low")

            txn_base = self.get_txn_base(b'\x05', nonce)
            buffer_size = len(txn_base) + 8 + len(data)
            buffer = bytearray(buffer_size)

            struct.pack_into(f'{len(txn_base)}s', buffer, 0, txn_base)  # Pack txnBase
            struct.pack_into('>q', buffer, len(txn_base), vm_id)  # Pack vmId as long
            buffer[len(txn_base) + 8:] = data

            return bytes(buffer)
        except InterruptedError as e:
            print(f"An error occurred:{e}")
        except IOError as e:
            print(f"An error occurred:{e}")

    def get_signed_vm_data_txn(self, vm_id: int, data: bytearray, nonce: int):
        return self.get_signed_txn(self.get_vm_data_txn(vm_id, data, nonce))

    ### Claiming VM ID Transactions
    def get_claim_vm_id_txn(self, vm_id: int, nonce: int):
        txn_base = self.get_txn_base(b'\x06', nonce)
        buffer_size = len(txn_base) + 8
        buffer = bytearray(buffer_size)

        struct.pack_into(f'{len(txn_base)}s', buffer, 0, txn_base)  # Pack txnBase
        struct.pack_into('>q', buffer, len(txn_base), vm_id)  # Pack vmId as long

        return bytes(buffer)

    def get_signed_claim_vm_id_txn(self, vm_id: int, nonce: int):
        return self.get_signed_txn(self.get_claim_vm_id_txn(vm_id, nonce))

    def claim_vm_id(self, vm_id: int, nonce: int = None):
        if nonce:
            response = self.pwrsdk.broadcast_txn(self.get_signed_claim_vm_id_txn(vm_id, nonce))
            return self.__create_wallet_response(response, response.data)
        else:
            response = self.pwrsdk.broadcast_txn(self.get_signed_claim_vm_id_txn(vm_id, self.get_nonce()))
            return self.__create_wallet_response(response, response.data)

    ### Conduit Transactions

    def get_send_conduit_transaction_txn(self, vm_id: int, txn: bytes, nonce: int):
        if nonce < 0:
            raise ValueError("Nonce cannot be negative")
        if nonce < self.get_nonce():
            raise ValueError("Nonce is too low")

        txn_base = self.get_txn_base(b'\x0B', nonce)
        buffer_size = len(txn_base) + 8 + len(txn)
        buffer = bytearray(buffer_size)

        struct.pack_into(f'{len(txn_base)}s', buffer, 0, txn_base)
        struct.pack_into('>q', buffer, len(txn_base), vm_id)
        buffer[len(txn_base) + 8:] = txn

        return bytes(buffer)

    def get_signed_send_conduit_transaction_txn(self, vm_id: int, txn: bytearray, nonce: int):
        return self.get_signed_txn(self.get_send_conduit_transaction_txn(vm_id, txn, nonce))

    def send_conduit_transaction(self, vm_id: int, txn: bytearray, nonce: int = None):
        if nonce:
            return self.pwrsdk.broadcast_txn(self.get_signed_send_conduit_transaction_txn(vm_id, txn, nonce))
        else:
            return self.pwrsdk.broadcast_txn(self.get_signed_send_conduit_transaction_txn(vm_id, txn, self.get_nonce()))

    ### Guardian Setting Transactions
    def get_set_guardian_txn(self, guardian_address: str, expiry_date: int, nonce: int):
        if len(guardian_address) != 40 and len(guardian_address) != 42:
            raise ValueError("Invalid address")
        if nonce < 0:
            raise ValueError("Nonce cannot be negative")
        if expiry_date < 0:
            raise ValueError("Expiry date cannot be negative")
        if expiry_date < time.time():
            raise ValueError("Expiry date cannot be in the past")

        if len(guardian_address) == 42:
            guardian_address = guardian_address[2:]

        txn_base = self.get_txn_base(b'\x08', nonce)
        buffer_size = len(txn_base) + 20 + 8
        buffer = bytearray(buffer_size)

        struct.pack_into(f'{len(txn_base)}s', buffer, 0, txn_base)  # Pack txnBase
        struct.pack_into('>q', buffer, len(txn_base), expiry_date)  # Pack expiryDate as long
        buffer[len(txn_base) + 8:] = bytes.fromhex(guardian_address)  # Pack guardianAddress

        return bytes(buffer)

    def get_signed_set_guardian_txn(self, guardian_address: str, expiry_date: int, nonce: int):
        return self.get_signed_txn(self.get_set_guardian_txn(guardian_address, expiry_date, nonce))

    def set_guardian(self, guardian_address: str, expiry_date: int, nonce: int = None):
        if nonce:
            response = self.pwrsdk.broadcast_txn(self.get_signed_set_guardian_txn(guardian_address, expiry_date, nonce))
            return self.__create_wallet_response(response, response.data)
        else:
            response = self.pwrsdk.broadcast_txn(
                self.get_signed_set_guardian_txn(guardian_address, expiry_date, self.get_nonce()))
            return self.__create_wallet_response(response, response.data)

    ### Remove Guardian Transactions
    def get_remove_guardian_txn(self, nonce: int):
        txn_base = self.get_txn_base(b'\x09', nonce)
        return txn_base

    def get_signed_remove_guardian_txn(self, nonce: int = None):
        if nonce:
            self.get_signed_txn(self.get_remove_guardian_txn(nonce))
        else:
            self.get_signed_txn(self.get_remove_guardian_txn(self.get_nonce().data))

    def remove_guardian(self, nonce: int = None):
        if nonce:
            response = self.pwrsdk.broadcast_txn(self.get_signed_remove_guardian_txn(nonce))
            return self.__create_wallet_response(response, response.data)
        else:
            response = self.pwrsdk.broadcast_txn(self.get_signed_remove_guardian_txn(self.get_nonce().data))
            return self.__create_wallet_response(response, response.data)

    ### Sending Guardian Wrapped Transactions
    def get_send_guardian_wrapped_transaction_txn(self, txn: bytes, nonce: int):
        txn_base = self.get_txn_base(b'\x0A', nonce)
        buffer_size = len(txn_base) + len(txn)
        buffer = bytearray(buffer_size)

        struct.pack_into(f'{len(txn_base)}s', buffer, 0, txn_base)
        buffer[len(txn_base):] = txn

        return bytes(buffer)

    def get_signed_send_guardian_wrapped_transaction_txn(self, txn: bytearray, nonce: int = None):
        if nonce:
            return self.get_signed_txn(self.get_send_guardian_wrapped_transaction_txn(txn, nonce))
        else:
            return self.get_signed_txn(self.get_send_guardian_wrapped_transaction_txn(txn, self.get_nonce().data))

    def send_guardian_wrapped_transaction(self, txn: bytearray, nonce: int = None):
        if nonce:
            response = self.pwrsdk.broadcast_txn(self.get_signed_send_guardian_wrapped_transaction_txn(txn, nonce))
            return self.__create_wallet_response(response, response.data)
        else:
            response = self.pwrsdk.broadcast_txn(
                self.get_signed_send_guardian_wrapped_transaction_txn(txn, self.get_nonce().data))
            return self.__create_wallet_response(response, response.data)

    ### Payable VM Data Transactions
    def get_payable_vm_data_txn(self, vm_id: int, value: int, data: bytes, nonce: int):
        if nonce < 0:
            raise ValueError("Nonce cannot be negative")
        if nonce < self.get_nonce().data:  #
            raise ValueError("Nonce is too low")

        txn_base = self.get_txn_base(b'\x05', nonce)
        buffer_size = len(txn_base) + 16 + len(data)
        buffer = bytearray(buffer_size)

        struct.pack_into(f'{len(txn_base)}s', buffer, 0, txn_base)  # Pack txnBase
        struct.pack_into('>qq', buffer, len(txn_base), vm_id, value)  # Pack vmId and value as long
        buffer[len(txn_base) + 16:] = data  # Pack data

        return bytes(buffer)

    def get_signed_payable_vm_data_txn(self, vm_id: int, value: int, data: bytes, nonce: int):
        return self.get_signed_txn(self.get_payable_vm_data_txn(vm_id, value, data, nonce))

    def send_payable_vm_data_txn(self, vm_id: int, value: int, data: bytes, nonce: int = None):
        try:
            if not nonce:
                nonce = self.get_nonce().data
            signed_txn = self.get_signed_payable_vm_data_txn(vm_id, value, data, nonce)
            response = self.pwrsdk.broadcast_txn(signed_txn)
            return self.__create_wallet_response(response, response.data)
        except Exception as e:
            return WalletResponse(False, None, str(e))

    def get_send_validator_remove_txn(self, validator: str, nonce: int):
        if len(validator) != 40 and len(validator) != 42:
            raise ValueError("Invalid address")
        if nonce < 0:
            raise ValueError("Nonce cannot be negative")

        if len(validator) == 42:
            validator = validator[2:]

        txn_base = self.get_txn_base(b'\x07', nonce)
        buffer_size = len(txn_base) + 20
        buffer = bytearray(buffer_size)

        struct.pack_into(f'{len(txn_base)}s', buffer, 0, txn_base)  # Pack txnBase
        buffer[len(txn_base):] = bytes.fromhex(validator)  # Pack validator

        return bytes(buffer)

    def get_signed_send_validator_remove_txn(self, validator: str, nonce: int = None):
        return self.get_signed_txn(self.get_send_validator_remove_txn(validator, nonce))

    def send_validator_remove_txn(self, validator: str, nonce: int = None):
        if not nonce:
            nonce = self.get_nonce()
        response = self.pwrsdk.broadcast_txn(self.get_signed_send_validator_remove_txn(validator, nonce))
        return self.__create_wallet_response(response, response.data)

    ### Conduit transactions (approve, set, add, remove)
    def get_conduit_approval_txn(self, vm_id, txns, nonce):
        if nonce < 0:
            raise RuntimeError("Nonce cannot be negative")
        if len(txns) == 0:
            raise RuntimeError("No transactions to approve")

        txn_base = self.get_txn_base(b'\x0C', nonce)
        buffer = io.BytesIO()
        buffer.write(txn_base)
        buffer.write(vm_id.to_bytes(8, 'big'))

        for txn in txns:
            buffer.write(len(txn).to_bytes(4, 'big'))
            buffer.write(txn)

        return buffer.getvalue()

    def get_signed_conduit_approval_txn(self, vm_id, txns, nonce: int):
        try:
            return self.get_signed_txn(self.get_conduit_approval_txn(vm_id, txns, nonce))
        except InterruptedError as e:
            print(f"An error occurred:{e}")
        except IOError as e:
            print(f"An error occurred:{e}")

    def conduit_approve(self, vm_id, txns, nonce: int = None):
        try:
            if not nonce:
                nonce = self.get_nonce()

            response = self.pwrsdk.broadcast_txn(self.get_signed_conduit_approval_txn(vm_id, txns, nonce))
            return self.__create_wallet_response(response,  response.data)
        except IOError as e:
            print(f"An error occurred:{e}")

    def get_set_conduits_txn(self, vm_id, conduits, nonce):
        if nonce < 0:
            raise RuntimeError("Nonce cannot be negative")
        if len(conduits) == 0:
            raise RuntimeError("No transactions to approve")

        txn_base = self.get_txn_base(b'\x0D', nonce)
        buffer = io.BytesIO()
        buffer.write(txn_base)
        buffer.write(vm_id.to_bytes(8, 'big'))

        for conduit in conduits:
            buffer.write(len(conduit).to_bytes(4, 'big'))
            buffer.write(conduit)

        return buffer.getvalue()

    def get_signed_set_conduit_txn(self, vm_id, conduits, nonce: int):
        try:
            return self.get_signed_txn(self.get_set_conduits_txn(vm_id, conduits, nonce))
        except InterruptedError as e:
            print(f"An error occurred:{e}")
        except IOError as e:
            print(f"An error occurred:{e}")

    def set_conduits(self, vm_id, conduits, nonce: int = None):
        try:
            if not nonce:
                nonce = self.get_nonce()

            response = self.pwrsdk.broadcast_txn(self.get_signed_set_conduit_txn(vm_id, conduits, nonce))
            return self.__create_wallet_response(response, response.data)
        except InterruptedError as e:
            print(f"An error has occurred:{e}")
        except IOError as e:
            print(f"An error has occurred:{e}")

    def get_add_conduits_txn(self, vm_id: int, conduits: list, nonce: int):
        try:
            if nonce < 0:
                raise ValueError("Nonce cannot be negative")
            if len(conduits) == 0:
                raise ValueError("No transactions to approve")

            txn_base = self.get_txn_base(b'\x0E', nonce)
            total_conduit_length = sum(len(conduit) for conduit in conduits)
            buffer_size = len(txn_base) + 8 + (len(conduits) * 4) + total_conduit_length
            buffer = bytearray(buffer_size)

            struct.pack_into(f'{len(txn_base)}s', buffer, 0, txn_base)  # Pack txnBase
            struct.pack_into('>q', buffer, len(txn_base), vm_id)  # Pack vmId as long

            offset = len(txn_base) + 8
            for conduit in conduits:
                struct.pack_into('>i', buffer, offset, len(conduit))  # Pack conduit length
                offset += 4
                buffer[offset:offset + len(conduit)] = conduit  # Pack conduit
                offset += len(conduit)

            return bytes(buffer)
        except InterruptedError as e:
            print(f"An error has occurred:{e}")
        except IOError as e:
            print(f"An error has occurred:{e}")

    def get_signed_add_conduits_txn(self, vm_id, conduits, nonce):
        try:
            return self.get_signed_txn(self.get_add_conduits_txn(vm_id, conduits, nonce))
        except InterruptedError as e:
            print(f"An error has occurred:{e}")
        except IOError as e:
            print(f"An error has occurred:{e}")

    def add_conduits(self, vm_id, conduits, nonce):
        try:
            if not nonce:
                nonce = self.get_nonce()
            response = self.pwrsdk.broadcast_txn(self.get_signed_add_conduits_txn(vm_id, conduits, nonce))
            return self.__create_wallet_response(response, response.data)
        except IOError as e:
            print(f"An error has occurred:{e}")

    def get_remove_conduits_txn(self, vm_id: int, conduits: list, nonce: int):
        try:
            if nonce < 0:
                raise RuntimeError("Nonce cannot be negative")
            if len(conduits) == 0:
                raise RuntimeError("No transactions to approve")

            txn_base = self.get_txn_base(b'\x0F', nonce)
            total_conduit_length = sum(len(conduit) for conduit in conduits)
            buffer_size = len(txn_base) + 8 + (len(conduits) * 4) + total_conduit_length
            buffer = bytearray(buffer_size)

            struct.pack_into(f'{len(txn_base)}s', buffer, 0, txn_base)
            struct.pack_into('>q', buffer, len(txn_base), vm_id)

            offset = len(txn_base) + 8
            for conduit in conduits:
                struct.pack_into('>i', buffer, offset, len(conduit))
                offset += 4
                buffer[offset:offset + len(conduit)] = conduit
                offset += len(conduit)

            return bytes(buffer)
        except InterruptedError as e:
            print(f"An error has occurred:{e}")
        except IOError as e:
            print(f"An error has occurred:{e}")

    def get_signed_remove_conduit_txn(self, vm_id, conduits, nonce):
        try:
            return self.get_signed_txn(self.get_remove_conduits_txn(vm_id, conduits, nonce))
        except InterruptedError as e:
            print(f"An error has occurred:{e}")
        except IOError as e:
            print(f"An error has occurred:{e}")

    def remove_conduits(self, vm_id, conduits, nonce):
        try:
            if not nonce:
                nonce = self.get_nonce()
            response = self.pwrsdk.broadcast_txn(self.get_signed_remove_conduit_txn(vm_id, conduits, nonce))
            return self.__create_wallet_response(response, response.data)

        except InterruptedError as e:
            print(f"An error has occurred:{e}")
        except IOError as e:
            print(f"An error has occurred:{e}")
