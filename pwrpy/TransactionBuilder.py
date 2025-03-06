import struct
import time
from typing import List
from eth_utils import to_bytes


class TransactionBuilder:
    @staticmethod
    def get_transaction_base(identifier, nonce, chain_id):
        buffer = bytearray()
        buffer.extend(identifier.to_bytes(4, 'big'))
        buffer.append(int.from_bytes(chain_id, byteorder='big'))
        buffer.extend(nonce.to_bytes(4, 'big'))
        return bytes(buffer)
    
    @staticmethod
    def get_falcon_transaction_base(identifier, nonce, chain_id, address, fee_per_byte):
        if len(address) == 42:
            address = address[2:]

        buffer = bytearray()
        buffer.extend(identifier.to_bytes(4, 'big'))
        buffer.append(int.from_bytes(chain_id, byteorder='big'))
        buffer.extend(nonce.to_bytes(4, 'big'))
        buffer.extend(fee_per_byte.to_bytes(8, 'big'))
        buffer.extend(bytes.fromhex(address))
        return bytes(buffer)

    @staticmethod
    def asset_address_validity(address: str):
        if address is None or (len(address) != 40 and len(address) != 42):
            raise RuntimeError("Invalid address")

    @staticmethod
    def get_transfer_pwr_transaction(to, amount, nonce, chain_id):
        TransactionBuilder.asset_address_validity(to)
        if amount < 0:
            raise ValueError("Amount cannot be negative")
        if nonce < 0:
            raise ValueError("Nonce cannot be negative")

        if len(to) == 42:
            to = to[2:]

        txn_base = TransactionBuilder.get_transaction_base(0, nonce, chain_id)

        buffer = bytearray()
        buffer.extend(txn_base)
        buffer.extend(amount.to_bytes(8, byteorder='big'))
        buffer.extend(bytes.fromhex(to))

        return bytes(buffer)

    @staticmethod
    def get_join_transaction(ip: str, nonce: int, chain_id: int) -> bytes:
        transaction_base = TransactionBuilder.get_transaction_base('\x01', nonce, chain_id)
        ip_bytes = ip.encode("utf-8")

        buffer = transaction_base + ip_bytes

        return buffer

    @staticmethod
    def get_claim_active_node_spot_transaction(nonce: int, chain_id: int) -> bytes:
        transaction_base = TransactionBuilder.get_transaction_base((2).to_bytes(1, 'big'), nonce, chain_id)

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
        buffer = transaction_base + struct.pack(">Q", vm_id) + struct.pack(">I", len(data)) + data

        return buffer

    @staticmethod
    def get_claim_vm_id_transaction(vm_id: int, nonce: int, chain_id: int) -> bytes:
        transaction_base = TransactionBuilder.get_transaction_base(6, nonce, chain_id)
        buffer = transaction_base + struct.pack(">Q", vm_id)

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

        # Get the base transaction details as a byte array
        transaction_base = TransactionBuilder.get_transaction_base(11, nonce, chain_id)

        buffer = transaction_base + struct.pack(">Q", vm_id) + struct.pack(">I", len(data)) + data + struct.pack(">Q", value)

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

    @staticmethod
    def get_change_early_withdraw_penalty_proposal_txn(withdrawal_penalty_time, withdrawal_penalty, title, description,
                                                       nonce, chain_id):
        transaction_base = TransactionBuilder.get_transaction_base(17, nonce, chain_id)
        title_bytes = title.encode('utf-8')
        description_bytes = description.encode('utf-8')
        buffer = transaction_base
        buffer += struct.pack('>I', len(title_bytes)) + title_bytes
        buffer += struct.pack('>QI', withdrawal_penalty_time, withdrawal_penalty)
        buffer += description_bytes
        return buffer

    @staticmethod
    def get_change_fee_per_byte_proposal_txn(fee_per_byte, title, description, nonce, chain_id):
        transaction_base = TransactionBuilder.get_transaction_base(18, nonce, chain_id)
        title_bytes = title.encode('utf-8')
        description_bytes = description.encode('utf-8')
        buffer = transaction_base
        buffer += struct.pack('>I', len(title_bytes)) + title_bytes
        buffer += struct.pack('>Q', fee_per_byte)
        buffer += description_bytes
        return buffer

    @staticmethod
    def get_change_max_block_size_proposal_txn(max_block_size, title, description, nonce, chain_id):
        transaction_base = TransactionBuilder.get_transaction_base(19, nonce, chain_id)
        title_bytes = title.encode('utf-8')
        description_bytes = description.encode('utf-8')
        buffer = transaction_base
        buffer += struct.pack('>II', len(title_bytes), max_block_size) + title_bytes + description_bytes
        return buffer

    @staticmethod
    def get_change_max_txn_size_proposal_txn(max_txn_size, title, description, nonce, chain_id):
        transaction_base = TransactionBuilder.get_transaction_base(20, nonce, chain_id)
        title_bytes = title.encode('utf-8')
        description_bytes = description.encode('utf-8')
        buffer = transaction_base
        buffer += struct.pack('>II', len(title_bytes), max_txn_size) + title_bytes + description_bytes
        return buffer

    @staticmethod
    def get_change_overall_burn_percentage_proposal_txn(burn_percentage, title, description, nonce, chain_id):
        transaction_base = TransactionBuilder.get_transaction_base(21, nonce, chain_id)
        title_bytes = title.encode('utf-8')
        description_bytes = description.encode('utf-8')
        buffer = transaction_base
        buffer += struct.pack('>II', len(title_bytes), burn_percentage) + title_bytes + description_bytes
        return buffer

    @staticmethod
    def get_change_reward_per_year_proposal_txn(reward_per_year, title, description, nonce, chain_id):
        transaction_base = TransactionBuilder.get_transaction_base(22, nonce, chain_id)
        title_bytes = title.encode('utf-8')
        description_bytes = description.encode('utf-8')
        buffer = transaction_base
        buffer += struct.pack('>I', len(title_bytes)) + title_bytes
        buffer += struct.pack('>Q', reward_per_year)
        buffer += description_bytes
        return buffer

    @staticmethod
    def get_change_validator_count_limit_proposal_txn(validator_count_limit, title, description, nonce, chain_id):
        transaction_base = TransactionBuilder.get_transaction_base(23, nonce, chain_id)
        title_bytes = title.encode('utf-8')
        description_bytes = description.encode('utf-8')
        buffer = transaction_base
        buffer += struct.pack('>II', len(title_bytes), validator_count_limit) + title_bytes + description_bytes
        return buffer

    @staticmethod
    def get_change_validator_joining_fee_proposal_txn(joining_fee, title, description, nonce, chain_id):
        transaction_base = TransactionBuilder.get_transaction_base(24, nonce, chain_id)
        title_bytes = title.encode('utf-8')
        description_bytes = description.encode('utf-8')
        buffer = transaction_base
        buffer += struct.pack('>I', len(title_bytes)) + title_bytes
        buffer += struct.pack('>Q', joining_fee)
        buffer += description_bytes
        return buffer

    @staticmethod
    def get_change_vm_id_claiming_fee_proposal_txn(claiming_fee, title, description, nonce, chain_id):
        transaction_base = TransactionBuilder.get_transaction_base(25, nonce, chain_id)
        title_bytes = title.encode('utf-8')
        description_bytes = description.encode('utf-8')
        buffer = transaction_base
        buffer += struct.pack('>I', len(title_bytes)) + title_bytes
        buffer += struct.pack('>Q', claiming_fee)
        buffer += description_bytes
        return buffer

    @staticmethod
    def get_change_vm_owner_txn_fee_share_proposal_txn(fee_share, title, description, nonce, chain_id):
        transaction_base = TransactionBuilder.get_transaction_base(26, nonce, chain_id)
        title_bytes = title.encode('utf-8')
        description_bytes = description.encode('utf-8')
        buffer = transaction_base
        buffer += struct.pack('>II', len(title_bytes), fee_share) + title_bytes + description_bytes
        return buffer

    @staticmethod
    def get_other_proposal_txn(title, description, nonce, chain_id):
        transaction_base = TransactionBuilder.get_transaction_base(27, nonce, chain_id)
        title_bytes = title.encode('utf-8')
        description_bytes = description.encode('utf-8')
        buffer = transaction_base
        buffer += struct.pack('>I', len(title_bytes)) + title_bytes + description_bytes
        return buffer

    @staticmethod
    def get_vote_on_proposal_txn(proposal_hash, vote, nonce, chain_id):
        transaction_base = TransactionBuilder.get_transaction_base(28, nonce, chain_id)
        proposal_hash_bytes = bytes.fromhex(proposal_hash)
        buffer = transaction_base
        buffer += proposal_hash_bytes
        buffer += struct.pack('>B', vote)
        return buffer
    
    # Falcon transaction bytes
    @staticmethod
    def get_falcon_set_public_key_transaction(public_key, nonce, chain_id, address, fee_per_byte):
        if nonce < 0:
            raise ValueError("Nonce cannot be negative")

        txn_base = TransactionBuilder.get_falcon_transaction_base(1001, nonce, chain_id, address, fee_per_byte)

        buffer = bytearray()
        buffer.extend(txn_base)
        buffer.extend(len(public_key).to_bytes(2, byteorder='big'))
        buffer.extend(public_key)
        return bytes(buffer)
    
    @staticmethod
    def get_falcon_join_as_validator_transaction(ip: str, nonce, chain_id, address, fee_per_byte):
        if nonce < 0:
            raise ValueError("Nonce cannot be negative")

        txn_base = TransactionBuilder.get_falcon_transaction_base(1002, nonce, chain_id, address, fee_per_byte)
        ip_bytes = ip.encode("utf-8")
    
        buffer = bytearray()
        buffer.extend(txn_base)
        buffer.extend(len(ip_bytes).to_bytes(2, byteorder='big'))
        buffer.extend(ip_bytes)
        return bytes(buffer)
    
    @staticmethod
    def get_falcon_delegate_transaction(validator: str, pwr_amount, nonce, chain_id, address, fee_per_byte):
        TransactionBuilder.asset_address_validity(validator)
        if nonce < 0:
            raise ValueError("Nonce cannot be negative")
        
        if len(validator) == 42:
            validator = validator[2:]

        txn_base = TransactionBuilder.get_falcon_transaction_base(1003, nonce, chain_id, address, fee_per_byte)
    
        buffer = bytearray()
        buffer.extend(txn_base)
        buffer.extend(bytes.fromhex(validator))
        buffer.extend(pwr_amount.to_bytes(8, byteorder='big'))
        return bytes(buffer)
    
    @staticmethod
    def get_falcon_change_ip_transaction(new_ip: str, nonce, chain_id, address, fee_per_byte):
        if nonce < 0:
            raise ValueError("Nonce cannot be negative")

        txn_base = TransactionBuilder.get_falcon_transaction_base(1004, nonce, chain_id, address, fee_per_byte)
        new_ip_bytes = new_ip.encode("utf-8")
    
        buffer = bytearray()
        buffer.extend(txn_base)
        buffer.extend(len(new_ip_bytes).to_bytes(2, byteorder='big'))
        buffer.extend(new_ip_bytes)
        return bytes(buffer)
    
    @staticmethod
    def get_falcon_claim_active_node_spot_transaction(nonce, chain_id, address, fee_per_byte):
        if nonce < 0:
            raise ValueError("Nonce cannot be negative")

        txn_base = TransactionBuilder.get_falcon_transaction_base(1005, nonce, chain_id, address, fee_per_byte)
    
        buffer = bytearray()
        buffer.extend(txn_base)
        return bytes(buffer)
    
    @staticmethod
    def get_falcon_transfer_pwr_transaction(to: str, amount, nonce, chain_id, address, fee_per_byte):
        TransactionBuilder.asset_address_validity(to)
        if amount < 0:
            raise ValueError("Amount cannot be negative")
        if nonce < 0:
            raise ValueError("Nonce cannot be negative")

        if len(to) == 42:
            to = to[2:]

        txn_base = TransactionBuilder.get_falcon_transaction_base(1006, nonce, chain_id, address, fee_per_byte)

        buffer = bytearray()
        buffer.extend(txn_base)
        buffer.extend(bytes.fromhex(to))
        buffer.extend(amount.to_bytes(8, byteorder='big'))
        return bytes(buffer)
    
    @staticmethod
    def get_falcon_vm_data_transaction(vm_id: int, data: bytes, nonce, chain_id, address, fee_per_byte):
        if nonce < 0:
            raise ValueError("Nonce cannot be negative")

        txn_base = TransactionBuilder.get_falcon_transaction_base(1007, nonce, chain_id, address, fee_per_byte)
    
        buffer = bytearray()
        buffer.extend(txn_base)
        buffer.extend(vm_id.to_bytes(8, byteorder='big'))
        buffer.extend(len(data).to_bytes(4, byteorder='big'))
        buffer.extend(data)
        return bytes(buffer)
