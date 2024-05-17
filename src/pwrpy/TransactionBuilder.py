import struct
import time
from typing import List
from eth_utils import to_bytes, to_hex


class TransactionBuilder:
    @staticmethod
    def get_transaction_base(identifier: int, nonce: int, chain_id: int) -> bytes:
        return struct.pack(">BBI", identifier, chain_id, nonce)

    @staticmethod
    def asset_address_validity(address: str):
        if address is None or (len(address) != 40 and len(address) != 42):
            raise RuntimeError("Invalid address")

    @staticmethod
    def get_transfer_pwr_transaction(to: str, amount: int, nonce: int, chain_id: int) -> bytes:
        TransactionBuilder.asset_address_validity(to)

        if amount < 0:
            raise RuntimeError("Amount cannot be negative")
        if nonce < 0:
            raise RuntimeError("Nonce cannot be negative")

        transaction_base = TransactionBuilder.get_transaction_base(0, nonce, chain_id)
        buffer = transaction_base + struct.pack(">Q", amount) + to_bytes(hexstr=to)

        return buffer

    @staticmethod
    def get_join_transaction(ip: str, nonce: int, chain_id: int) -> bytes:
        transaction_base = TransactionBuilder.get_transaction_base(1, nonce, chain_id)
        ip_bytes = ip.encode("utf-8")

        buffer = transaction_base + ip_bytes

        return buffer

    @staticmethod
    def get_claim_active_node_spot_transaction(nonce: int, chain_id: int) -> bytes:
        transaction_base = TransactionBuilder.get_transaction_base(2, nonce, chain_id)

        return transaction_base

    @staticmethod
    def get_delegate_transaction(validator: str, amount: int, nonce: int, chain_id: int) -> bytes:
        TransactionBuilder.asset_address_validity(validator)
        if amount < 0:
            raise RuntimeError("Amount cannot be negative")
        if nonce < 0:
            raise RuntimeError("Nonce cannot be negative")

        transaction_base = TransactionBuilder.get_transaction_base(3, nonce, chain_id)
        buffer = transaction_base + struct.pack(">Q", amount) + to_bytes(hexstr=validator)

        return buffer

    @staticmethod
    def get_withdraw_transaction(validator: str, shares_amount: int, nonce: int, chain_id: int) -> bytes:
        TransactionBuilder.asset_address_validity(validator)
        if shares_amount < 0:
            raise RuntimeError("Shares amount cannot be negative")
        if nonce < 0:
            raise RuntimeError("Nonce cannot be negative")

        transaction_base = TransactionBuilder.get_transaction_base(4, nonce, chain_id)
        buffer = transaction_base + struct.pack(">Q", shares_amount) + to_bytes(hexstr=validator)

        return buffer

    @staticmethod
    def get_vm_data_transaction(vm_id: int, data: bytes, nonce: int, chain_id: int) -> bytes:
        if nonce < 0:
            raise RuntimeError("Nonce cannot be negative")

        transaction_base = TransactionBuilder.get_transaction_base(5, nonce, chain_id)
        buffer = transaction_base + struct.pack(">Q", vm_id) + data

        return buffer

    @staticmethod
    def get_claim_vm_id_transaction(vm_id: int, nonce: int, chain_id: int) -> bytes:
        transaction_base = TransactionBuilder.get_transaction_base(6, nonce, chain_id)
        buffer = transaction_base + struct.pack(">Q", vm_id)

        return buffer

    @staticmethod
    def get_set_guardian_transaction(guardian: str, expiry_date: int, nonce: int, chain_id: int) -> bytes:
        TransactionBuilder.asset_address_validity(guardian)

        if nonce < 0:
            raise RuntimeError("Nonce cannot be negative")
        if expiry_date < 0:
            raise RuntimeError("Expiry date cannot be negative")
        if expiry_date < int(time.time()):
            raise RuntimeError("Expiry date cannot be in the past")

        transaction_base = TransactionBuilder.get_transaction_base(8, nonce, chain_id)
        buffer = transaction_base + struct.pack(">Q", expiry_date) + to_bytes(hexstr=guardian)

        return buffer

    @staticmethod
    def get_remove_guardian_transaction(nonce: int, chain_id: int) -> bytes:
        transaction_base = TransactionBuilder.get_transaction_base(9, nonce, chain_id)

        return transaction_base

    @staticmethod
    def get_guardian_approval_transaction(transactions: List[bytes], nonce: int, chain_id: int) -> bytes:
        total_length = sum(len(transaction) for transaction in transactions)

        transaction_base = TransactionBuilder.get_transaction_base(10, nonce, chain_id)
        buffer = transaction_base + struct.pack(">{}I".format(len(transactions)),
                                                *[len(transaction) for transaction in transactions])
        buffer += b"".join(transactions)

        return buffer

    @staticmethod
    def get_payable_vm_data_transaction(vm_id: int, value: int, data: bytes, nonce: int, chain_id: int) -> bytes:
        if nonce < 0:
            raise RuntimeError("Nonce cannot be negative")

        transaction_base = TransactionBuilder.get_transaction_base(11, nonce, chain_id)
        buffer = transaction_base + struct.pack(">QQ", vm_id, value) + data

        return buffer

    @staticmethod
    def get_validator_remove_transaction(validator: str, nonce: int, chain_id: int) -> bytes:
        TransactionBuilder.asset_address_validity(validator)

        if nonce < 0:
            raise RuntimeError("Nonce cannot be negative")

        transaction_base = TransactionBuilder.get_transaction_base(7, nonce, chain_id)
        buffer = transaction_base + to_bytes(hexstr=validator)

        return buffer

    @staticmethod
    def get_conduit_approval_transaction(vm_id: int, transactions: List[bytes], nonce: int, chain_id: int) -> bytes:
        if nonce < 0:
            raise RuntimeError("Nonce cannot be negative")
        if len(transactions) == 0:
            raise RuntimeError("No transactions to approve")

        total_transactions_length = sum(len(transaction) for transaction in transactions)

        transaction_base = TransactionBuilder.get_transaction_base(12, nonce, chain_id)
        buffer = transaction_base + struct.pack(">Q", vm_id)
        buffer += struct.pack(">{}I".format(len(transactions)), *[len(transaction) for transaction in transactions])
        buffer += b"".join(transactions)

        return buffer

    @staticmethod
    def get_set_conduits_transaction(vm_id: int, conduits: List[bytes], nonce: int, chain_id: int) -> bytes:
        if nonce < 0:
            raise RuntimeError("Nonce cannot be negative")
        if len(conduits) == 0:
            raise RuntimeError("No transactions to approve")

        total_conduit_length = sum(len(conduit) for conduit in conduits)

        transaction_base = TransactionBuilder.get_transaction_base(13, nonce, chain_id)
        buffer = transaction_base + struct.pack(">Q", vm_id)
        buffer += struct.pack(">{}I".format(len(conduits)), *[len(conduit) for conduit in conduits])
        buffer += b"".join(conduits)

        return buffer

    @staticmethod
    def get_add_conduits_transaction(vm_id: int, conduits: List[bytes], nonce: int, chain_id: int) -> bytes:
        if nonce < 0:
            raise RuntimeError("Nonce cannot be negative")
        if len(conduits) == 0:
            raise RuntimeError("No conduits provided")

        transaction_base = TransactionBuilder.get_transaction_base(14, nonce, chain_id)
        buffer = transaction_base + struct.pack(">Q", vm_id) + b"".join(conduits)

        return buffer

    @staticmethod
    def get_remove_conduits_transaction(vm_id: int, conduits: List[bytes], nonce: int, chain_id: int) -> bytes:
        if nonce < 0:
            raise RuntimeError("Nonce cannot be negative")
        if len(conduits) == 0:
            raise RuntimeError("No conduits provided")

        transaction_base = TransactionBuilder.get_transaction_base(15, nonce, chain_id)
        buffer = transaction_base + struct.pack(">Q", vm_id) + b"".join(conduits)

        return buffer

    @staticmethod
    def get_move_stake_transaction(shares_amount: int, from_validator: str, to_validator: str, nonce: int,
                                   chain_id: int) -> bytes:
        TransactionBuilder.asset_address_validity(from_validator)
        TransactionBuilder.asset_address_validity(to_validator)

        transaction_base = TransactionBuilder.get_transaction_base(16, nonce, chain_id)
        buffer = transaction_base + struct.pack(">Q", shares_amount) + to_bytes(hexstr=from_validator) + to_bytes(
            hexstr=to_validator)

        return buffer
