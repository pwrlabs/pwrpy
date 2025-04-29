import struct
import time
from typing import List
from eth_utils import to_bytes


class TransactionBuilder:
    @staticmethod
    def get_transaction_base(identifier, nonce, chain_id, address, fee_per_byte):
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
    
    # Falcon transaction bytes
    @staticmethod
    def get_set_public_key_transaction(public_key, nonce, chain_id, address, fee_per_byte):
        if nonce < 0:
            raise ValueError("Nonce cannot be negative")

        txn_base = TransactionBuilder.get_transaction_base(1001, nonce, chain_id, address, fee_per_byte)

        buffer = bytearray()
        buffer.extend(txn_base)
        buffer.extend(len(public_key).to_bytes(2, byteorder='big'))
        buffer.extend(public_key)
        return bytes(buffer)
    
    @staticmethod
    def get_join_as_validator_transaction(ip: str, nonce, chain_id, address, fee_per_byte):
        if nonce < 0:
            raise ValueError("Nonce cannot be negative")

        txn_base = TransactionBuilder.get_transaction_base(1002, nonce, chain_id, address, fee_per_byte)
        ip_bytes = ip.encode("utf-8")
    
        buffer = bytearray()
        buffer.extend(txn_base)
        buffer.extend(len(ip_bytes).to_bytes(2, byteorder='big'))
        buffer.extend(ip_bytes)
        return bytes(buffer)
    
    @staticmethod
    def get_delegate_transaction(validator: str, pwr_amount, nonce, chain_id, address, fee_per_byte):
        TransactionBuilder.asset_address_validity(validator)
        if nonce < 0:
            raise ValueError("Nonce cannot be negative")
        
        if len(validator) == 42:
            validator = validator[2:]

        txn_base = TransactionBuilder.get_transaction_base(1003, nonce, chain_id, address, fee_per_byte)
    
        buffer = bytearray()
        buffer.extend(txn_base)
        buffer.extend(bytes.fromhex(validator))
        buffer.extend(pwr_amount.to_bytes(8, byteorder='big'))
        return bytes(buffer)
    
    @staticmethod
    def get_change_ip_transaction(new_ip: str, nonce, chain_id, address, fee_per_byte):
        if nonce < 0:
            raise ValueError("Nonce cannot be negative")

        txn_base = TransactionBuilder.get_transaction_base(1004, nonce, chain_id, address, fee_per_byte)
        new_ip_bytes = new_ip.encode("utf-8")
    
        buffer = bytearray()
        buffer.extend(txn_base)
        buffer.extend(len(new_ip_bytes).to_bytes(2, byteorder='big'))
        buffer.extend(new_ip_bytes)
        return bytes(buffer)
    
    @staticmethod
    def get_claim_active_node_spot_transaction(nonce, chain_id, address, fee_per_byte):
        if nonce < 0:
            raise ValueError("Nonce cannot be negative")

        txn_base = TransactionBuilder.get_transaction_base(1005, nonce, chain_id, address, fee_per_byte)
    
        buffer = bytearray()
        buffer.extend(txn_base)
        return bytes(buffer)
    
    @staticmethod
    def get_transfer_pwr_transaction(to: str, amount, nonce, chain_id, address, fee_per_byte):
        TransactionBuilder.asset_address_validity(to)
        if amount < 0:
            raise ValueError("Amount cannot be negative")
        if nonce < 0:
            raise ValueError("Nonce cannot be negative")

        if len(to) == 42:
            to = to[2:]

        txn_base = TransactionBuilder.get_transaction_base(1006, nonce, chain_id, address, fee_per_byte)

        buffer = bytearray()
        buffer.extend(txn_base)
        buffer.extend(bytes.fromhex(to))
        buffer.extend(amount.to_bytes(8, byteorder='big'))
        return bytes(buffer)
    
    # Governance Proposal Transactions
    @staticmethod
    def get_change_early_withdraw_penalty_proposal_transaction(title: str, description: str, early_withdrawal_time: int, 
                                                                    withdrawal_penalty: int, nonce: int, chain_id: int, 
                                                                    address: str, fee_per_byte: int):
        if nonce < 0:
            raise ValueError("Nonce cannot be negative")

        txn_base = TransactionBuilder.get_transaction_base(1009, nonce, chain_id, address, fee_per_byte)
        title_bytes = title.encode('utf-8')
        description_bytes = description.encode('utf-8')

        buffer = bytearray()
        buffer.extend(txn_base)
        buffer.extend(len(title_bytes).to_bytes(4, byteorder='big'))
        buffer.extend(title_bytes)
        buffer.extend(early_withdrawal_time.to_bytes(8, byteorder='big'))
        buffer.extend(withdrawal_penalty.to_bytes(4, byteorder='big'))
        buffer.extend(description_bytes)
        return bytes(buffer)

    @staticmethod
    def get_change_fee_per_byte_proposal_transaction(title: str, description: str, new_fee_per_byte: int, 
                                                          nonce: int, chain_id: int, address: str, fee_per_byte: int):
        if nonce < 0:
            raise ValueError("Nonce cannot be negative")

        txn_base = TransactionBuilder.get_transaction_base(1010, nonce, chain_id, address, fee_per_byte)
        title_bytes = title.encode('utf-8')
        description_bytes = description.encode('utf-8')

        buffer = bytearray()
        buffer.extend(txn_base)
        buffer.extend(len(title_bytes).to_bytes(4, byteorder='big'))
        buffer.extend(title_bytes)
        buffer.extend(new_fee_per_byte.to_bytes(8, byteorder='big'))
        buffer.extend(description_bytes)
        return bytes(buffer)

    @staticmethod
    def get_change_max_block_size_proposal_transaction(title: str, description: str, max_block_size: int, 
                                                            nonce: int, chain_id: int, address: str, fee_per_byte: int):
        if nonce < 0:
            raise ValueError("Nonce cannot be negative")

        txn_base = TransactionBuilder.get_transaction_base(1011, nonce, chain_id, address, fee_per_byte)
        title_bytes = title.encode('utf-8')
        description_bytes = description.encode('utf-8')

        buffer = bytearray()
        buffer.extend(txn_base)
        buffer.extend(len(title_bytes).to_bytes(4, byteorder='big'))
        buffer.extend(title_bytes)
        buffer.extend(max_block_size.to_bytes(4, byteorder='big'))
        buffer.extend(description_bytes)
        return bytes(buffer)

    @staticmethod
    def get_change_max_txn_size_proposal_transaction(title: str, description: str, max_txn_size: int, 
                                                          nonce: int, chain_id: int, address: str, fee_per_byte: int):
        if nonce < 0:
            raise ValueError("Nonce cannot be negative")

        txn_base = TransactionBuilder.get_transaction_base(1012, nonce, chain_id, address, fee_per_byte)
        title_bytes = title.encode('utf-8')
        description_bytes = description.encode('utf-8')

        buffer = bytearray()
        buffer.extend(txn_base)
        buffer.extend(len(title_bytes).to_bytes(4, byteorder='big'))
        buffer.extend(title_bytes)
        buffer.extend(max_txn_size.to_bytes(4, byteorder='big'))
        buffer.extend(description_bytes)
        return bytes(buffer)

    @staticmethod
    def get_change_overall_burn_percentage_proposal_transaction(title: str, description: str, burn_percentage: int, 
                                                                    nonce: int, chain_id: int, address: str, fee_per_byte: int):
        if nonce < 0:
            raise ValueError("Nonce cannot be negative")

        txn_base = TransactionBuilder.get_transaction_base(1013, nonce, chain_id, address, fee_per_byte)
        title_bytes = title.encode('utf-8')
        description_bytes = description.encode('utf-8')

        buffer = bytearray()
        buffer.extend(txn_base)
        buffer.extend(len(title_bytes).to_bytes(4, byteorder='big'))
        buffer.extend(title_bytes)
        buffer.extend(burn_percentage.to_bytes(4, byteorder='big'))
        buffer.extend(description_bytes)
        return bytes(buffer)

    @staticmethod
    def get_change_reward_per_year_proposal_transaction(title: str, description: str, reward_per_year: int, 
                                                             nonce: int, chain_id: int, address: str, fee_per_byte: int):
        if nonce < 0:
            raise ValueError("Nonce cannot be negative")

        txn_base = TransactionBuilder.get_transaction_base(1014, nonce, chain_id, address, fee_per_byte)
        title_bytes = title.encode('utf-8')
        description_bytes = description.encode('utf-8')

        buffer = bytearray()
        buffer.extend(txn_base)
        buffer.extend(len(title_bytes).to_bytes(4, byteorder='big'))
        buffer.extend(title_bytes)
        buffer.extend(reward_per_year.to_bytes(8, byteorder='big'))
        buffer.extend(description_bytes)
        return bytes(buffer)

    @staticmethod
    def get_change_validator_count_limit_proposal_transaction(title: str, description: str, validator_count_limit: int, 
                                                                   nonce: int, chain_id: int, address: str, fee_per_byte: int):
        if nonce < 0:
            raise ValueError("Nonce cannot be negative")

        txn_base = TransactionBuilder.get_transaction_base(1015, nonce, chain_id, address, fee_per_byte)
        title_bytes = title.encode('utf-8')
        description_bytes = description.encode('utf-8')

        buffer = bytearray()
        buffer.extend(txn_base)
        buffer.extend(len(title_bytes).to_bytes(4, byteorder='big'))
        buffer.extend(title_bytes)
        buffer.extend(validator_count_limit.to_bytes(4, byteorder='big'))
        buffer.extend(description_bytes)
        return bytes(buffer)

    @staticmethod
    def get_change_validator_joining_fee_proposal_transaction(title: str, description: str, joining_fee: int, 
                                                                   nonce: int, chain_id: int, address: str, fee_per_byte: int):
        if nonce < 0:
            raise ValueError("Nonce cannot be negative")

        txn_base = TransactionBuilder.get_transaction_base(1016, nonce, chain_id, address, fee_per_byte)
        title_bytes = title.encode('utf-8')
        description_bytes = description.encode('utf-8')

        buffer = bytearray()
        buffer.extend(txn_base)
        buffer.extend(len(title_bytes).to_bytes(4, byteorder='big'))
        buffer.extend(title_bytes)
        buffer.extend(joining_fee.to_bytes(8, byteorder='big'))
        buffer.extend(description_bytes)
        return bytes(buffer)

    @staticmethod
    def get_change_vida_id_claiming_fee_proposal_transaction(title: str, description: str, vida_id_claiming_fee: int, 
                                                                  nonce: int, chain_id: int, address: str, fee_per_byte: int):
        if nonce < 0:
            raise ValueError("Nonce cannot be negative")

        txn_base = TransactionBuilder.get_transaction_base(1017, nonce, chain_id, address, fee_per_byte)
        title_bytes = title.encode('utf-8')
        description_bytes = description.encode('utf-8')

        buffer = bytearray()
        buffer.extend(txn_base)
        buffer.extend(len(title_bytes).to_bytes(4, byteorder='big'))
        buffer.extend(title_bytes)
        buffer.extend(vida_id_claiming_fee.to_bytes(8, byteorder='big'))
        buffer.extend(description_bytes)
        return bytes(buffer)

    @staticmethod
    def get_change_vida_owner_txn_fee_share_proposal_transaction(title: str, description: str, vida_owner_txn_fee_share: int, 
                                                                    nonce: int, chain_id: int, address: str, fee_per_byte: int):
        if nonce < 0:
            raise ValueError("Nonce cannot be negative")

        txn_base = TransactionBuilder.get_transaction_base(1018, nonce, chain_id, address, fee_per_byte)
        title_bytes = title.encode('utf-8')
        description_bytes = description.encode('utf-8')

        buffer = bytearray()
        buffer.extend(txn_base)
        buffer.extend(len(title_bytes).to_bytes(4, byteorder='big'))
        buffer.extend(title_bytes)
        buffer.extend(vida_owner_txn_fee_share.to_bytes(4, byteorder='big'))
        buffer.extend(description_bytes)
        return bytes(buffer)

    @staticmethod
    def get_other_proposal_transaction(title: str, description: str, nonce: int, chain_id: int, 
                                            address: str, fee_per_byte: int):
        if nonce < 0:
            raise ValueError("Nonce cannot be negative")

        txn_base = TransactionBuilder.get_transaction_base(1019, nonce, chain_id, address, fee_per_byte)
        title_bytes = title.encode('utf-8')
        description_bytes = description.encode('utf-8')

        buffer = bytearray()
        buffer.extend(txn_base)
        buffer.extend(len(title_bytes).to_bytes(4, byteorder='big'))
        buffer.extend(title_bytes)
        buffer.extend(description_bytes)
        return bytes(buffer)

    @staticmethod
    def get_vote_on_proposal_transaction(proposal_hash: str, vote: int, nonce: int, chain_id: int, 
                                              address: str, fee_per_byte: int):
        if nonce < 0:
            raise ValueError("Nonce cannot be negative")

        txn_base = TransactionBuilder.get_transaction_base(1020, nonce, chain_id, address, fee_per_byte)
        proposal_hash_bytes = bytes.fromhex(proposal_hash)

        buffer = bytearray()
        buffer.extend(txn_base)
        buffer.extend(proposal_hash_bytes)
        buffer.extend(vote.to_bytes(1, byteorder='big'))
        return bytes(buffer)

    # Guardian Transactions
    @staticmethod
    def get_guardian_approval_transaction(wrapped_txns: List[bytes], nonce: int, chain_id: int, 
                                               address: str, fee_per_byte: int):
        if nonce < 0:
            raise ValueError("Nonce cannot be negative")

        txn_base = TransactionBuilder.get_transaction_base(1021, nonce, chain_id, address, fee_per_byte)

        buffer = bytearray()
        buffer.extend(txn_base)
        buffer.extend(len(wrapped_txns).to_bytes(4, byteorder='big'))

        for txn in wrapped_txns:
            buffer.extend(len(txn).to_bytes(4, byteorder='big'))
            buffer.extend(txn)

        return bytes(buffer)

    @staticmethod
    def get_remove_guardian_transaction(nonce: int, chain_id: int, address: str, fee_per_byte: int):
        if nonce < 0:
            raise ValueError("Nonce cannot be negative")

        txn_base = TransactionBuilder.get_transaction_base(1022, nonce, chain_id, address, fee_per_byte)
        return txn_base

    @staticmethod
    def get_set_guardian_transaction(expiry_date: int, guardian_address: str, nonce: int, chain_id: int, 
                                          address: str, fee_per_byte: int):
        if nonce < 0:
            raise ValueError("Nonce cannot be negative")

        txn_base = TransactionBuilder.get_transaction_base(1023, nonce, chain_id, address, fee_per_byte)
        if len(guardian_address) == 42:
            guardian_address = guardian_address[2:]

        buffer = bytearray()
        buffer.extend(txn_base)
        buffer.extend(expiry_date.to_bytes(8, byteorder='big'))
        buffer.extend(bytes.fromhex(guardian_address))
        return bytes(buffer)

    # Staking Transactions
    @staticmethod
    def get_move_stake_transaction(shares_amount: int, from_validator: str, to_validator: str, 
                                        nonce: int, chain_id: int, address: str, fee_per_byte: int):
        if nonce < 0:
            raise ValueError("Nonce cannot be negative")

        txn_base = TransactionBuilder.get_transaction_base(1024, nonce, chain_id, address, fee_per_byte)
        if len(from_validator) == 42:
            from_validator = from_validator[2:]
        if len(to_validator) == 42:
            to_validator = to_validator[2:]

        buffer = bytearray()
        buffer.extend(txn_base)
        buffer.extend(shares_amount.to_bytes(8, byteorder='big'))
        buffer.extend(bytes.fromhex(from_validator))
        buffer.extend(bytes.fromhex(to_validator))
        return bytes(buffer)

    @staticmethod
    def get_remove_validator_transaction(validator_address: str, nonce: int, chain_id: int, 
                                              address: str, fee_per_byte: int):
        if nonce < 0:
            raise ValueError("Nonce cannot be negative")

        txn_base = TransactionBuilder.get_transaction_base(1025, nonce, chain_id, address, fee_per_byte)
        if len(validator_address) == 42:
            validator_address = validator_address[2:]

        buffer = bytearray()
        buffer.extend(txn_base)
        buffer.extend(bytes.fromhex(validator_address))
        return bytes(buffer)

    @staticmethod
    def get_withdraw_transaction(shares_amount: int, validator: str, nonce: int, chain_id: int, 
                                      address: str, fee_per_byte: int):
        if nonce < 0:
            raise ValueError("Nonce cannot be negative")

        txn_base = TransactionBuilder.get_transaction_base(1026, nonce, chain_id, address, fee_per_byte)
        if len(validator) == 42:
            validator = validator[2:]

        buffer = bytearray()
        buffer.extend(txn_base)
        buffer.extend(shares_amount.to_bytes(8, byteorder='big'))
        buffer.extend(bytes.fromhex(validator))
        return bytes(buffer)

    # VIDA Transactions
    @staticmethod
    def get_claim_vida_id_transaction(vida_id: int, nonce: int, chain_id: int, address: str, fee_per_byte: int):
        if nonce < 0:
            raise ValueError("Nonce cannot be negative")

        txn_base = TransactionBuilder.get_transaction_base(1028, nonce, chain_id, address, fee_per_byte)

        buffer = bytearray()
        buffer.extend(txn_base)
        buffer.extend(vida_id.to_bytes(8, byteorder='big'))
        return bytes(buffer)

    @staticmethod
    def get_conduit_approval_transaction(vida_id: int, wrapped_txns: List[bytes], nonce: int, chain_id: int, 
                                              address: str, fee_per_byte: int):
        if nonce < 0:
            raise ValueError("Nonce cannot be negative")

        txn_base = TransactionBuilder.get_transaction_base(1029, nonce, chain_id, address, fee_per_byte)

        buffer = bytearray()
        buffer.extend(txn_base)
        buffer.extend(vida_id.to_bytes(8, byteorder='big'))
        buffer.extend(len(wrapped_txns).to_bytes(4, byteorder='big'))

        for txn in wrapped_txns:
            buffer.extend(len(txn).to_bytes(4, byteorder='big'))
            buffer.extend(txn)

        return bytes(buffer)

    @staticmethod
    def get_payable_vida_data_transaction(vida_id: int, data: bytes, value: int, nonce: int, chain_id: int, 
                                               address: str, fee_per_byte: int):
        if nonce < 0:
            raise ValueError("Nonce cannot be negative")

        txn_base = TransactionBuilder.get_transaction_base(1030, nonce, chain_id, address, fee_per_byte)

        buffer = bytearray()
        buffer.extend(txn_base)
        buffer.extend(vida_id.to_bytes(8, byteorder='big'))
        buffer.extend(len(data).to_bytes(4, byteorder='big'))
        buffer.extend(data)
        buffer.extend(value.to_bytes(8, byteorder='big'))
        return bytes(buffer)

    @staticmethod
    def get_remove_conduits_transaction(vida_id: int, conduits: List[str], nonce: int, chain_id: int, 
                                             address: str, fee_per_byte: int):
        if nonce < 0:
            raise ValueError("Nonce cannot be negative")

        txn_base = TransactionBuilder.get_transaction_base(1031, nonce, chain_id, address, fee_per_byte)

        buffer = bytearray()
        buffer.extend(txn_base)
        buffer.extend(vida_id.to_bytes(8, byteorder='big'))

        for conduit in conduits:
            if len(conduit) == 42:
                conduit = conduit[2:]
            buffer.extend(bytes.fromhex(conduit))

        return bytes(buffer)

    @staticmethod
    def get_set_conduit_mode_transaction(vida_id: int, mode: int, conduit_threshold: int, conduits: List[str], 
                                              nonce: int, chain_id: int, address: str, fee_per_byte: int):
        if nonce < 0:
            raise ValueError("Nonce cannot be negative")

        txn_base = TransactionBuilder.get_transaction_base(1033, nonce, chain_id, address, fee_per_byte)

        buffer = bytearray()
        buffer.extend(txn_base)
        buffer.extend(vida_id.to_bytes(8, byteorder='big'))
        buffer.extend(mode.to_bytes(1, byteorder='big'))
        buffer.extend(conduit_threshold.to_bytes(4, byteorder='big'))

        if conduits:
            buffer.extend(len(conduits).to_bytes(4, byteorder='big'))
            for conduit in conduits:
                if len(conduit) == 42:
                    conduit = conduit[2:]
                buffer.extend(bytes.fromhex(conduit))
        else:
            buffer.extend((0).to_bytes(4, byteorder='big'))

        return bytes(buffer)

    @staticmethod
    def get_set_vida_private_state_transaction(vida_id: int, private_state: bool, nonce: int, chain_id: int, 
                                                    address: str, fee_per_byte: int):
        if nonce < 0:
            raise ValueError("Nonce cannot be negative")

        txn_base = TransactionBuilder.get_transaction_base(1034, nonce, chain_id, address, fee_per_byte)

        buffer = bytearray()
        buffer.extend(txn_base)
        buffer.extend(vida_id.to_bytes(8, byteorder='big'))
        buffer.extend((1 if private_state else 0).to_bytes(1, byteorder='big'))
        return bytes(buffer)

    @staticmethod
    def get_set_vida_to_absolute_public_transaction(vida_id: int, nonce: int, chain_id: int, 
                                                         address: str, fee_per_byte: int):
        if nonce < 0:
            raise ValueError("Nonce cannot be negative")

        txn_base = TransactionBuilder.get_transaction_base(1035, nonce, chain_id, address, fee_per_byte)

        buffer = bytearray()
        buffer.extend(txn_base)
        buffer.extend(vida_id.to_bytes(8, byteorder='big'))
        return bytes(buffer)

    @staticmethod
    def get_add_vida_sponsored_addresses_transaction(vida_id: int, sponsored_addresses: List[str], 
                                                          nonce: int, chain_id: int, address: str, fee_per_byte: int):
        if nonce < 0:
            raise ValueError("Nonce cannot be negative")

        txn_base = TransactionBuilder.get_transaction_base(1036, nonce, chain_id, address, fee_per_byte)

        buffer = bytearray()
        buffer.extend(txn_base)
        buffer.extend(vida_id.to_bytes(8, byteorder='big'))

        for address in sponsored_addresses:
            if len(address) == 42:
                address = address[2:]
            buffer.extend(bytes.fromhex(address))

        return bytes(buffer)

    @staticmethod
    def get_add_vida_allowed_senders_transaction(vida_id: int, allowed_senders: List[str], 
                                                      nonce: int, chain_id: int, address: str, fee_per_byte: int):
        if nonce < 0:
            raise ValueError("Nonce cannot be negative")

        txn_base = TransactionBuilder.get_transaction_base(1037, nonce, chain_id, address, fee_per_byte)

        buffer = bytearray()
        buffer.extend(txn_base)
        buffer.extend(vida_id.to_bytes(8, byteorder='big'))

        for sender in allowed_senders:
            if len(sender) == 42:
                sender = sender[2:]
            buffer.extend(bytes.fromhex(sender))

        return bytes(buffer)

    @staticmethod
    def get_remove_vida_allowed_senders_transaction(vida_id: int, allowed_senders: List[str], 
                                                         nonce: int, chain_id: int, address: str, fee_per_byte: int):
        if nonce < 0:
            raise ValueError("Nonce cannot be negative")

        txn_base = TransactionBuilder.get_transaction_base(1038, nonce, chain_id, address, fee_per_byte)

        buffer = bytearray()
        buffer.extend(txn_base)
        buffer.extend(vida_id.to_bytes(8, byteorder='big'))

        for sender in allowed_senders:
            if len(sender) == 42:
                sender = sender[2:]
            buffer.extend(bytes.fromhex(sender))

        return bytes(buffer)

    @staticmethod
    def get_remove_sponsored_addresses_transaction(vida_id: int, sponsored_addresses: List[str], 
                                                        nonce: int, chain_id: int, address: str, fee_per_byte: int):
        if nonce < 0:
            raise ValueError("Nonce cannot be negative")

        txn_base = TransactionBuilder.get_transaction_base(1039, nonce, chain_id, address, fee_per_byte)

        buffer = bytearray()
        buffer.extend(txn_base)
        buffer.extend(vida_id.to_bytes(8, byteorder='big'))

        for address in sponsored_addresses:
            if len(address) == 42:
                address = address[2:]
            buffer.extend(bytes.fromhex(address))

        return bytes(buffer)

    @staticmethod
    def get_set_pwr_transfer_rights_transaction(vida_id: int, owner_can_transfer_pwr: bool, 
                                                     nonce: int, chain_id: int, address: str, fee_per_byte: int):
        if nonce < 0:
            raise ValueError("Nonce cannot be negative")

        txn_base = TransactionBuilder.get_transaction_base(1040, nonce, chain_id, address, fee_per_byte)

        buffer = bytearray()
        buffer.extend(txn_base)
        buffer.extend(vida_id.to_bytes(8, byteorder='big'))
        buffer.extend((1 if owner_can_transfer_pwr else 0).to_bytes(1, byteorder='big'))
        return bytes(buffer)

    @staticmethod
    def get_transfer_pwr_from_vida_transaction(vida_id: int, receiver: str, amount: int, 
                                                    nonce: int, chain_id: int, address: str, fee_per_byte: int):
        if nonce < 0:
            raise ValueError("Nonce cannot be negative")

        txn_base = TransactionBuilder.get_transaction_base(1041, nonce, chain_id, address, fee_per_byte)
        if len(receiver) == 42:
            receiver = receiver[2:]

        buffer = bytearray()
        buffer.extend(txn_base)
        buffer.extend(vida_id.to_bytes(8, byteorder='big'))
        buffer.extend(bytes.fromhex(receiver))
        buffer.extend(amount.to_bytes(8, byteorder='big'))
        return bytes(buffer)
    
