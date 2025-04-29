from eth_utils import to_hex
from eth_account import Account
from eth_account.messages import encode_defunct

from pwrpy.pwrsdk import PWRPY

class TransactionDecoder:
    @staticmethod
    def decode(txn: bytes, sender: bytes = None) -> 'Transaction':
        if sender is None:
            sender = TransactionDecoder.get_sender(txn)
        transaction_type = txn[0]
        nonce = int.from_bytes(txn[2:6], byteorder='big')

        if transaction_type == 0:
            return TransactionDecoder.decode_transfer(txn, sender, nonce)
        elif transaction_type == 1:
            return TransactionDecoder.decode_join(txn, sender, nonce)
        elif transaction_type == 2:
            return TransactionDecoder.decode_claim_spot(txn, sender, nonce)
        elif transaction_type == 3:
            return TransactionDecoder.decode_delegate(txn, sender, nonce)
        elif transaction_type == 4:
            return TransactionDecoder.decode_withdraw(txn, sender, nonce)
        elif transaction_type == 5:
            return TransactionDecoder.decode_vida_data_txn(txn, sender, nonce)
        elif transaction_type == 6:
            return TransactionDecoder.decode_claim_vida_id(txn, sender, nonce)
        elif transaction_type == 8:
            return TransactionDecoder.decode_set_guardian_txn(txn, sender, nonce)
        elif transaction_type == 9:
            return TransactionDecoder.decode_remove_guardian_txn(txn, sender, nonce)
        elif transaction_type == 10:
            return TransactionDecoder.decode_guardian_approval_txn(txn, sender, nonce)
        elif transaction_type == 11:
            return TransactionDecoder.decode_payable_vida_data_txn(txn, sender, nonce)
        elif transaction_type == 12:
            return TransactionDecoder.decode_conduit_approval_txn(txn, sender, nonce)
        elif transaction_type == 13:
            return TransactionDecoder.decode_set_conduits_txn(txn, sender, nonce)
        elif transaction_type == 14:
            return TransactionDecoder.decode_add_conduits_txn(txn, sender, nonce)
        elif transaction_type == 15:
            return TransactionDecoder.decode_remove_conduits_txn(txn, sender, nonce)
        elif transaction_type == 16:
            return TransactionDecoder.decode_move_stake_txn(txn, sender, nonce)
        else:
            raise ValueError(f"Invalid transaction identifier: {transaction_type}")

    @staticmethod
    def decode_transfer(txn: bytes, sender: bytes, nonce: int) -> 'TransferTransaction':
        if len(txn) != 34 and len(txn) != 99:
            raise ValueError("Invalid transaction length for transfer transaction")

        amount = int.from_bytes(txn[6:14], byteorder='big')
        recipient = to_hex(txn[14:34])

        return TransferTransaction(
            sender=to_hex(sender),
            receiver=recipient,
            value=amount,
            nonce=nonce,
            size=len(txn),
            raw_transaction=txn,
            chain_id=txn[1]
        )

    @staticmethod
    def decode_join(txn: bytes, sender: bytes, nonce: int) -> 'JoinTransaction':
        if len(txn) < 79 or len(txn) > 87:
            raise ValueError("Invalid length for join transaction")

        ip = txn[6:-65].decode('utf-8')

        return JoinTransaction(
            sender=to_hex(sender),
            nonce=nonce,
            size=len(txn),
            ip=ip,
            raw_transaction=txn,
            chain_id=txn[1]
        )

    @staticmethod
    def decode_claim_spot(txn: bytes, sender: bytes, nonce: int) -> 'ClaimSpotTransaction':
        if len(txn) != 71:
            raise ValueError("Invalid length for claim spot transaction")

        return ClaimSpotTransaction(
            sender=to_hex(sender),
            nonce=nonce,
            size=len(txn),
            raw_transaction=txn,
            chain_id=txn[1]
        )

    @staticmethod
    def decode_delegate(txn: bytes, sender: bytes, nonce: int) -> 'DelegateTransaction':
        if len(txn) != 34 and len(txn) != 99:
            raise ValueError("Invalid length for delegate transaction")

        amount = int.from_bytes(txn[6:14], byteorder='big')
        validator = to_hex(txn[14:34])

        return DelegateTransaction(
            sender=to_hex(sender),
            validator=validator,
            value=amount,
            nonce=nonce,
            size=len(txn),
            raw_transaction=txn,
            chain_id=txn[1]
        )

    @staticmethod
    def decode_withdraw(txn: bytes, sender: bytes, nonce: int) -> 'WithdrawTransaction':
        if len(txn) != 34 and len(txn) != 99:
            raise ValueError("Invalid length for withdraw transaction")

        shares_amount = int.from_bytes(txn[6:14], byteorder='big')
        validator = to_hex(txn[14:34])

        return WithdrawTransaction(
            sender=to_hex(sender),
            validator=validator,
            value=shares_amount,
            nonce=nonce,
            size=len(txn),
            raw_transaction=txn,
            chain_id=txn[1]
        )

    @staticmethod
    def decode_vida_data_txn(txn: bytes, sender: bytes, nonce: int) -> 'VidaDataTransaction':
        if len(txn) < 14:
            raise ValueError("Invalid length for VIDA Data transaction")

        external_vida_id = int.from_bytes(txn[6:14], byteorder='big')

        data_length = len(txn) - 14 if PWRPY.is_vida_address(to_hex(sender)) else len(txn) - 79

        data = to_hex(txn[14:14+data_length])

        return VidaDataTransaction(
            sender=to_hex(sender),
            nonce=nonce,
            size=len(txn),
            vida_id=external_vida_id,
            data=data,
            raw_transaction=txn,
            chain_id=txn[1]
        )

    @staticmethod
    def decode_claim_vida_id(txn: bytes, sender: bytes, nonce: int) -> 'ClaimVidaIdTransaction':
        if len(txn) != 14 and len(txn) != 79:
            raise ValueError("Invalid length for claim VIDA ID transaction")

        vida_id = int.from_bytes(txn[6:14], byteorder='big')

        return ClaimVidaIdTransaction(
            sender=to_hex(sender),
            nonce=nonce,
            size=len(txn),
            vida_id=vida_id,
            raw_transaction=txn,
            chain_id=txn[1]
        )

    @staticmethod
    def decode_set_guardian_txn(txn: bytes, sender: bytes, nonce: int) -> 'SetGuardianTransaction':
        if len(txn) != 99:
            raise ValueError("Invalid length for set guardian transaction")

        expiry_date = int.from_bytes(txn[6:14], byteorder='big')
        guardian_address = to_hex(txn[14:34])

        return SetGuardianTransaction(
            sender=to_hex(sender),
            nonce=nonce,
            size=len(txn),
            expiry_date=expiry_date,
            guardian=guardian_address,
            raw_transaction=txn,
            chain_id=txn[1]
        )

    @staticmethod
    def decode_remove_guardian_txn(txn: bytes, sender: bytes, nonce: int) -> 'RemoveGuardianTransaction':
        if len(txn) != 71:
            raise ValueError("Invalid length for remove guardian transaction")

        return RemoveGuardianTransaction(
            sender=to_hex(sender),
            nonce=nonce,
            size=len(txn),
            raw_transaction=txn,
            chain_id=txn[1]
        )

    @staticmethod
    def decode_guardian_approval_txn(txn: bytes, sender: bytes, nonce: int) -> 'GuardianApprovalTransaction':
        wrapped_txns = []
        idx = 6

        while idx < len(txn) - 65:
            txn_length = int.from_bytes(txn[idx:idx+4], byteorder='big')
            wrapped_txn = txn[idx+4:idx+4+txn_length]
            wrapped_txns.append(wrapped_txn)
            idx += 4 + txn_length

        transactions = [TransactionDecoder.decode(wrapped_txn) for wrapped_txn in wrapped_txns]

        return GuardianApprovalTransaction(
            sender=to_hex(sender),
            nonce=nonce,
            size=len(txn),
            transactions=transactions,
            raw_transaction=txn,
            chain_id=txn[1]
        )

    @staticmethod
    def decode_payable_vida_data_txn(txn: bytes, sender: bytes, nonce: int) -> 'PayableVidaDataTransaction':
        if len(txn) < 22:
            raise ValueError("Invalid length for payable VIDA Data transaction")

        external_vida_id = int.from_bytes(txn[6:14], byteorder='big')

        data_length = len(txn) - 22 if PWRPY.is_vida_address(to_hex(sender)) else len(txn) - 87

        data = to_hex(txn[14:14+data_length])
        value = int.from_bytes(txn[14+data_length:22+data_length], byteorder='big')

        return PayableVidaDataTransaction(
            sender=to_hex(sender),
            nonce=nonce,
            size=len(txn),
            vida_id=external_vida_id,
            data=data,
            value=value,
            raw_transaction=txn,
            chain_id=txn[1]
        )

    @staticmethod
    def decode_conduit_approval_txn(txn: bytes, sender: bytes, nonce: int) -> 'ConduitApprovalTransaction':
        vida_id = int.from_bytes(txn[6:14], byteorder='big')

        wrapped_txns = []
        idx = 14

        while idx < len(txn) - 65:
            txn_length = int.from_bytes(txn[idx:idx+4], byteorder='big')
            wrapped_txn = txn[idx+4:idx+4+txn_length]
            wrapped_txns.append(wrapped_txn)
            idx += 4 + txn_length

        vida_address = PWRPY.get_vida_id_address(vida_id)
        transactions = [TransactionDecoder.decode(wrapped_txn, vida_address) for wrapped_txn in wrapped_txns]

        return ConduitApprovalTransaction(
            sender=to_hex(sender),
            nonce=nonce,
            size=len(txn),
            transactions=transactions,
            raw_transaction=txn,
            chain_id=txn[1]
        )

    @staticmethod
    def decode_set_conduits_txn(txn: bytes, sender: bytes, nonce: int) -> 'SetConduitsTransaction':
        vida_id = int.from_bytes(txn[6:14], byteorder='big')

        conduits = []
        idx = 14

        while idx < len(txn) - 65:
            txn_length = int.from_bytes(txn[idx:idx+4], byteorder='big')
            conduit = to_hex(txn[idx+4:idx+4+txn_length])
            conduits.append(conduit)
            idx += 4 + txn_length

        if idx != len(txn) - 65:
            raise ValueError(f"Invalid remaining length for set conduits transaction. Remaining: {len(txn) - idx}, Expected: 65")

        return SetConduitsTransaction(
            sender=to_hex(sender),
            nonce=nonce,
            size=len(txn),
            vida_id=vida_id,
            conduits=conduits,
            raw_transaction=txn,
            chain_id=txn[1]
        )

    @staticmethod
    def decode_add_conduits_txn(txn: bytes, sender: bytes, nonce: int) -> 'AddConduitsTransaction':
        vida_id = int.from_bytes(txn[6:14], byteorder='big')

        conduits = []
        idx = 14

        while idx < len(txn):
            conduit = to_hex(txn[idx:idx+20])
            conduits.append(conduit)
            idx += 20

        return AddConduitsTransaction(
            sender=to_hex(sender),
            nonce=nonce,
            size=len(txn),
            vida_id=vida_id,
            conduits=conduits,
            raw_transaction=txn,
            chain_id=txn[1]
        )

    @staticmethod
    def decode_remove_conduits_txn(txn: bytes, sender: bytes, nonce: int) -> 'RemoveConduitsTransaction':
        vida_id = int.from_bytes(txn[6:14], byteorder='big')

        conduits = []
        idx = 14

        while idx < len(txn):
            conduit = to_hex(txn[idx:idx+20])
            conduits.append(conduit)
            idx += 20

        return RemoveConduitsTransaction(
            sender=to_hex(sender),
            nonce=nonce,
            size=len(txn),
            vida_id=vida_id,
            conduits=conduits,
            raw_transaction=txn,
            chain_id=txn[1]
        )

    @staticmethod
    def decode_move_stake_txn(txn: bytes, sender: bytes, nonce: int) -> 'MoveStakeTransaction':
        if len(txn) != 54 and len(txn) != 119:
            raise ValueError("Invalid length for move stake transaction")

        shares_amount = int.from_bytes(txn[6:14], byteorder='big')
        from_validator = to_hex(txn[14:34])
        to_validator = to_hex(txn[34:54])

        return MoveStakeTransaction(
            sender=to_hex(sender),
            nonce=nonce,
            size=len(txn),
            from_validator=from_validator,
            to_validator=to_validator,
            shares_amount=shares_amount,
            raw_transaction=txn,
            chain_id=txn[1]
        )

    @staticmethod
    def get_sender(txn: bytes) -> bytes:
        signature = txn[-65:]
        txn_data = txn[:-65]
        return TransactionDecoder.get_signer(txn_data, signature)

    @staticmethod
    def get_signer(txn: bytes, signature: bytes) -> bytes:
        message = encode_defunct(txn)
        signer_address = Account.recover_message(message, signature=signature)
        return bytes.fromhex(signer_address[2:])

    @staticmethod
    def decode_change_early_withdraw_penalty_proposal_txn(txn: bytes, sender: bytes, nonce: int):
        title_length = int.from_bytes(txn[6:10], 'big')
        title = txn[10:10 + title_length].decode('utf-8')
        offset = 10 + title_length
        withdrawal_penalty_time = int.from_bytes(txn[offset:offset + 8], 'big')
        withdrawal_penalty = int.from_bytes(txn[offset + 8:offset + 12], 'big')
        description = txn[offset + 12:-65].decode('utf-8')  # Assuming signature is 65 bytes long at the end
        return {
            'sender': to_hex(sender),
            'nonce': nonce,
            'title': title,
            'description': description,
            'withdrawal_penalty_time': withdrawal_penalty_time,
            'withdrawal_penalty': withdrawal_penalty,
            'raw_transaction': txn,
            'chain_id': txn[1]
        }

    @staticmethod
    def decode_change_fee_per_byte_proposal_txn(txn: bytes, sender: bytes, nonce: int):
        title_length = int.from_bytes(txn[6:10], 'big')
        title = txn[10:10 + title_length].decode('utf-8')
        offset = 10 + title_length
        fee_per_byte = int.from_bytes(txn[offset:offset + 8], 'big')
        description = txn[offset + 8:-65].decode('utf-8')  # Assuming signature is 65 bytes long at the end
        return {
            'sender': to_hex(sender),
            'nonce': nonce,
            'title': title,
            'description': description,
            'fee_per_byte': fee_per_byte,
            'raw_transaction': txn,
            'chain_id': txn[1]
        }

    @staticmethod
    def decode_change_max_block_size_proposal_txn(txn: bytes, sender: bytes, nonce: int):
        title_length = int.from_bytes(txn[6:10], 'big')
        title = txn[10:10 + title_length].decode('utf-8')
        max_block_size = int.from_bytes(txn[10 + title_length:10 + title_length + 4], 'big')
        description = txn[10 + title_length + 4:-65].decode('utf-8')  # Assuming signature is 65 bytes long at the end
        return {
            'sender': to_hex(sender),
            'nonce': nonce,
            'title': title,
            'description': description,
            'max_block_size': max_block_size,
            'raw_transaction': txn,
            'chain_id': txn[1]
        }

    @staticmethod
    def decode_change_max_txn_size_proposal_txn(txn: bytes, sender: bytes, nonce: int):
        title_length = int.from_bytes(txn[6:10], 'big')
        title = txn[10:10 + title_length].decode('utf-8')
        max_txn_size = int.from_bytes(txn[10 + title_length:10 + title_length + 4], 'big')
        description = txn[10 + title_length + 4:-65].decode('utf-8')  # Assuming signature is 65 bytes long at the end
        return {
            'sender': to_hex(sender),
            'nonce': nonce,
            'title': title,
            'description': description,
            'max_txn_size': max_txn_size,
            'raw_transaction': txn,
            'chain_id': txn[1]
        }

    @staticmethod
    def decode_change_overall_burn_percentage_proposal_txn(txn: bytes, sender: bytes, nonce: int):
        title_length = int.from_bytes(txn[6:10], 'big')
        title = txn[10:10 + title_length].decode('utf-8')
        burn_percentage = int.from_bytes(txn[10 + title_length:10 + title_length + 4], 'big')
        description = txn[10 + title_length + 4:-65].decode('utf-8')  # Assuming signature is 65 bytes long at the end
        return {
            'sender': to_hex(sender),
            'nonce': nonce,
            'title': title,
            'description': description,
            'burn_percentage': burn_percentage,
            'raw_transaction': txn,
            'chain_id': txn[1]
        }

    @staticmethod
    def decode_change_reward_per_year_proposal_txn(txn: bytes, sender: bytes, nonce: int):
        title_length = int.from_bytes(txn[6:10], 'big')
        title = txn[10:10 + title_length].decode('utf-8')
        reward_per_year = int.from_bytes(txn[10 + title_length:10 + title_length + 8], 'big')
        description = txn[10 + title_length + 8:-65].decode('utf-8')  # Assuming signature is 65 bytes long at the end
        return {
            'sender': to_hex(sender),
            'nonce': nonce,
            'title': title,
            'description': description,
            'reward_per_year': reward_per_year,
            'raw_transaction': txn,
            'chain_id': txn[1]
        }

    @staticmethod
    def decode_change_validator_count_limit_proposal_txn(txn: bytes, sender: bytes, nonce: int):
        title_length = int.from_bytes(txn[6:10], 'big')
        title = txn[10:10 + title_length].decode('utf-8')
        validator_count_limit = int.from_bytes(txn[10 + title_length:10 + title_length + 4], 'big')
        description = txn[10 + title_length + 4:-65].decode('utf-8')  # Assuming signature is 65 bytes long at the end
        return {
            'sender': to_hex(sender),
            'nonce': nonce,
            'title': title,
            'description': description,
            'validator_count_limit': validator_count_limit,
            'raw_transaction': txn,
            'chain_id': txn[1]
        }

    @staticmethod
    def decode_change_validator_joining_fee_proposal_txn(txn: bytes, sender: bytes, nonce: int):
        title_length = int.from_bytes(txn[6:10], 'big')
        title = txn[10:10 + title_length].decode('utf-8')
        joining_fee = int.from_bytes(txn[10 + title_length:10 + title_length + 8], 'big')
        description = txn[10 + title_length + 8:-65].decode('utf-8')  # Assuming signature is 65 bytes long at the end
        return {
            'sender': to_hex(sender),
            'nonce': nonce,
            'title': title,
            'description': description,
            'joining_fee': joining_fee,
            'raw_transaction': txn,
            'chain_id': txn[1]
        }

    @staticmethod
    def decode_change_vida_id_claiming_fee_proposal_txn(txn: bytes, sender: bytes, nonce: int):
        title_length = int.from_bytes(txn[6:10], 'big')
        title = txn[10:10 + title_length].decode('utf-8')
        claiming_fee = int.from_bytes(txn[10 + title_length:10 + title_length + 8], 'big')
        description = txn[10 + title_length + 8:-65].decode('utf-8')  # Assuming signature is 65 bytes long at the end
        return {
            'sender': to_hex(sender),
            'nonce': nonce,
            'title': title,
            'description': description,
            'claiming_fee': claiming_fee,
            'raw_transaction': txn,
            'chain_id': txn[1]
        }

    @staticmethod
    def decode_change_vida_owner_txn_fee_share_proposal_txn(txn: bytes, sender: bytes, nonce: int):
        title_length = int.from_bytes(txn[6:10], 'big')
        title = txn[10:10 + title_length].decode('utf-8')
        fee_share = int.from_bytes(txn[10 + title_length:10 + title_length + 4], 'big')
        description = txn[10 + title_length + 4:-65].decode('utf-8')  # Assuming signature is 65 bytes long at the end
        return {
            'sender': to_hex(sender),
            'nonce': nonce,
            'title': title,
            'description': description,
            'fee_share': fee_share,
            'raw_transaction': txn,
            'chain_id': txn[1]
        }

    @staticmethod
    def decode_other_proposal_txn(txn: bytes, sender: bytes, nonce: int):
        title_length = int.from_bytes(txn[6:10], 'big')
        title = txn[10:10 + title_length].decode('utf-8')
        description = txn[10 + title_length:-65].decode('utf-8')  # Assuming signature is 65 bytes long at the end
        return {
            'sender': to_hex(sender),
            'nonce': nonce,
            'title': title,
            'description': description,
            'raw_transaction': txn,
            'chain_id': txn[1]
        }

    @staticmethod
    def decode_vote_on_proposal_txn(txn: bytes, sender: bytes, nonce: int):
        proposal_hash = to_hex(txn[6:38])
        vote = txn[38]
        return {
            'sender': to_hex(sender),
            'nonce': nonce,
            'proposal_hash': proposal_hash,
            'vote': vote,
            'raw_transaction': txn,
            'chain_id': txn[1]
        }