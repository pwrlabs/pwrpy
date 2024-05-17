from eth_utils import to_hex
from eth_account import Account
from eth_account.messages import encode_defunct

from src.pwrpy.pwrapisdk import PWRPY
from src.pwrpy.models.Transaction import *


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
            return TransactionDecoder.decode_vm_data_txn(txn, sender, nonce)
        elif transaction_type == 6:
            return TransactionDecoder.decode_claim_vm_id(txn, sender, nonce)
        elif transaction_type == 8:
            return TransactionDecoder.decode_set_guardian_txn(txn, sender, nonce)
        elif transaction_type == 9:
            return TransactionDecoder.decode_remove_guardian_txn(txn, sender, nonce)
        elif transaction_type == 10:
            return TransactionDecoder.decode_guardian_approval_txn(txn, sender, nonce)
        elif transaction_type == 11:
            return TransactionDecoder.decode_payable_vm_data_txn(txn, sender, nonce)
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
    def decode_vm_data_txn(txn: bytes, sender: bytes, nonce: int) -> 'VmDataTransaction':
        if len(txn) < 14:
            raise ValueError("Invalid length for VM Data transaction")

        external_vm_id = int.from_bytes(txn[6:14], byteorder='big')

        data_length = len(txn) - 14 if PWRPY.is_vm_address(to_hex(sender)) else len(txn) - 79

        data = to_hex(txn[14:14+data_length])

        return VmDataTransaction(
            sender=to_hex(sender),
            nonce=nonce,
            size=len(txn),
            vm_id=external_vm_id,
            data=data,
            raw_transaction=txn,
            chain_id=txn[1]
        )

    @staticmethod
    def decode_claim_vm_id(txn: bytes, sender: bytes, nonce: int) -> 'ClaimVmIdTransaction':
        if len(txn) != 14 and len(txn) != 79:
            raise ValueError("Invalid length for claim VM ID transaction")

        vm_id = int.from_bytes(txn[6:14], byteorder='big')

        return ClaimVmIdTransaction(
            sender=to_hex(sender),
            nonce=nonce,
            size=len(txn),
            vm_id=vm_id,
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
    def decode_payable_vm_data_txn(txn: bytes, sender: bytes, nonce: int) -> 'PayableVmDataTransaction':
        if len(txn) < 22:
            raise ValueError("Invalid length for payable VM Data transaction")

        external_vm_id = int.from_bytes(txn[6:14], byteorder='big')

        data_length = len(txn) - 22 if PWRPY.is_vm_address(to_hex(sender)) else len(txn) - 87

        data = to_hex(txn[14:14+data_length])
        value = int.from_bytes(txn[14+data_length:22+data_length], byteorder='big')

        return PayableVmDataTransaction(
            sender=to_hex(sender),
            nonce=nonce,
            size=len(txn),
            vm_id=external_vm_id,
            data=data,
            value=value,
            raw_transaction=txn,
            chain_id=txn[1]
        )

    @staticmethod
    def decode_conduit_approval_txn(txn: bytes, sender: bytes, nonce: int) -> 'ConduitApprovalTransaction':
        vm_id = int.from_bytes(txn[6:14], byteorder='big')

        wrapped_txns = []
        idx = 14

        while idx < len(txn) - 65:
            txn_length = int.from_bytes(txn[idx:idx+4], byteorder='big')
            wrapped_txn = txn[idx+4:idx+4+txn_length]
            wrapped_txns.append(wrapped_txn)
            idx += 4 + txn_length

        vm_address = PWRPY.get_vm_id_address(vm_id)
        transactions = [TransactionDecoder.decode(wrapped_txn, vm_address) for wrapped_txn in wrapped_txns]

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
        vm_id = int.from_bytes(txn[6:14], byteorder='big')

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
            vm_id=vm_id,
            conduits=conduits,
            raw_transaction=txn,
            chain_id=txn[1]
        )

    @staticmethod
    def decode_add_conduits_txn(txn: bytes, sender: bytes, nonce: int) -> 'AddConduitsTransaction':
        vm_id = int.from_bytes(txn[6:14], byteorder='big')

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
            vm_id=vm_id,
            conduits=conduits,
            raw_transaction=txn,
            chain_id=txn[1]
        )

    @staticmethod
    def decode_remove_conduits_txn(txn: bytes, sender: bytes, nonce: int) -> 'RemoveConduitsTransaction':
        vm_id = int.from_bytes(txn[6:14], byteorder='big')

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
            vm_id=vm_id,
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
