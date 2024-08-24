from json import loads, dumps
from typing import List


class Transaction:
    def __init__(self, size: int, block_number: int, position_in_the_block: int, fee: int, extraFee: int, type: str,
                 sender: str, receiver: str, nonce: int, hash: str, timestamp: int, value: int, raw_transaction: bytes,
                 chainId: bytes, hasError: bool):
        self._size = size
        self._block_number = block_number
        self._position_in_the_block = position_in_the_block
        self._fee = fee
        self._extraFee = extraFee
        self._type = type
        self._sender = sender
        self._receiver = receiver
        self._nonce = nonce
        self._hash = hash
        self._timestamp = timestamp
        self._value = value
        self._raw_transaction = raw_transaction
        self._chainId = chainId
        self._hasError = hasError

    @classmethod
    def from_json(cls, json_data, block_number, timestamp, position_in_the_block):
        size = json_data.get('size', 0)
        block_number = block_number
        position_in_the_block = position_in_the_block
        fee = json_data.get('fee', 0)
        extraFee = json_data.get('extraFee', 0)  # Ensure this field is included
        _type = json_data.get('type', 'unknown')
        sender = json_data.get('sender', '0x')
        receiver = json_data.get('receiver', '0x')
        nonce = json_data.get('nonce', 0)
        _hash = json_data.get('hash', '0x')
        timestamp = timestamp
        value = json_data.get('value', 0)
        raw_transaction = bytes.fromhex(json_data.get('rawTransaction', ''))
        chainId = int.to_bytes(json_data.get('chainId', 0), 1, 'big')
        hasError = not (json_data.get("success", True))  # Fix typo from "sucess" to "success"

        return cls(size=size, block_number=block_number, position_in_the_block=position_in_the_block, fee=fee,
                   extraFee=extraFee, type=_type, sender=sender, receiver=receiver, nonce=nonce, hash=_hash,
                   timestamp=timestamp, value=value, raw_transaction=raw_transaction, chainId=chainId,
                   hasError=hasError)

    @classmethod
    def transaction_from_json(cls, json_data, block_number, timestamp, position_in_the_block):
        txn_type = json_data.get('type', 'Unknown').lower()
        if txn_type == ClaimSpotTransaction.TYPE.lower():
            return ClaimSpotTransaction.from_json(json_data, block_number, timestamp, position_in_the_block)
        elif txn_type == TransferTransaction.TYPE.lower():
            return TransferTransaction.from_json(json_data, block_number, timestamp, position_in_the_block)
        elif txn_type == VmDataTransaction.TYPE.lower():
            return VmDataTransaction.from_json(json_data, block_number, timestamp, position_in_the_block)
        elif txn_type == DelegateTransaction.TYPE.lower():
            return DelegateTransaction.from_json(json_data, block_number, timestamp, position_in_the_block)
        elif txn_type == WithdrawTransaction.TYPE.lower():
            return WithdrawTransaction.from_json(json_data, block_number, timestamp, position_in_the_block)
        elif txn_type == JoinTransaction.TYPE.lower():
            return JoinTransaction.from_json(json_data, block_number, timestamp, position_in_the_block)
        elif txn_type == ClaimVmIdTransaction.TYPE.lower():
            return ClaimVmIdTransaction.from_json(json_data, block_number, timestamp, position_in_the_block)
        elif txn_type == SetGuardianTransaction.TYPE.lower():
            return SetGuardianTransaction.from_json(json_data, block_number, timestamp, position_in_the_block)
        elif txn_type == PayableVmDataTransaction.TYPE.lower():
            return PayableVmDataTransaction.from_json(json_data, block_number, timestamp, position_in_the_block)
        elif txn_type == GuardianApprovalTransaction.TYPE.lower():
            return GuardianApprovalTransaction.from_json(json_data, block_number, timestamp, position_in_the_block)
        elif txn_type == ConduitApprovalTransaction.TYPE.lower():
            return ConduitApprovalTransaction.from_json(json_data, block_number, timestamp, position_in_the_block)
        elif txn_type == RemoveGuardianTransaction.TYPE.lower():
            return RemoveGuardianTransaction.from_json(json_data, block_number, timestamp, position_in_the_block)
        elif txn_type == SetConduitsTransaction.TYPE.lower():
            return SetConduitsTransaction.from_json(json_data, block_number, timestamp, position_in_the_block)
        elif txn_type == AddConduitsTransaction.TYPE.lower():
            return AddConduitsTransaction.from_json(json_data, block_number, timestamp, position_in_the_block)
        elif txn_type == MoveStakeTransaction.TYPE.lower():
            return MoveStakeTransaction.from_json(json_data, block_number, timestamp, position_in_the_block)
        elif txn_type == ChangeEarlyWithdrawPenaltyProposalTransaction.TYPE.lower():
            return ChangeEarlyWithdrawPenaltyProposalTransaction.from_json(json_data, block_number, timestamp,
                                                                           position_in_the_block)
        elif txn_type == ChangeFeePerByteProposalTransaction.TYPE.lower():
            return ChangeFeePerByteProposalTransaction.from_json(json_data, block_number, timestamp,
                                                                 position_in_the_block)
        elif txn_type == ChangeMaxTxnSizeProposalTransaction.TYPE.lower():
            return ChangeMaxTxnSizeProposalTransaction.from_json(json_data, block_number, timestamp,
                                                                 position_in_the_block)
        elif txn_type == ChangeMaxBlockSizeProposalTransaction.TYPE.lower():
            return ChangeMaxBlockSizeProposalTransaction.from_json(json_data, block_number, timestamp,
                                                                   position_in_the_block)
        elif txn_type == ChangeOverallBurnPercentageProposalTransaction.TYPE.lower():
            return ChangeOverallBurnPercentageProposalTransaction.from_json(json_data, block_number, timestamp,
                                                                            position_in_the_block)
        elif txn_type == ChangeRewardPerYearProposalTransaction.TYPE.lower():
            return ChangeRewardPerYearProposalTransaction.from_json(json_data, block_number, timestamp,
                                                                    position_in_the_block)
        elif txn_type == ChangeValidatorCountLimitProposalTransaction.TYPE.lower():
            return ChangeValidatorCountLimitProposalTransaction.from_json(json_data, block_number, timestamp,
                                                                          position_in_the_block)
        elif txn_type == ChangeValidatorJoiningFeeProposalTransaction.TYPE.lower():
            return ChangeValidatorJoiningFeeProposalTransaction.from_json(json_data, block_number, timestamp,
                                                                          position_in_the_block)
        elif txn_type == ChangeVmIdClaimingFeeProposalTransaction.TYPE.lower():
            return ChangeVmIdClaimingFeeProposalTransaction.from_json(json_data, block_number, timestamp,
                                                                      position_in_the_block)
        elif txn_type == ChangeVmOwnerTxnFeeShareProposalTransaction.TYPE.lower():
            return ChangeVmOwnerTxnFeeShareProposalTransaction.from_json(json_data, block_number, timestamp,
                                                                         position_in_the_block)
        elif txn_type == OtherProposalTransaction.TYPE.lower():
            return OtherProposalTransaction.from_json(json_data, block_number, timestamp, position_in_the_block)
        elif txn_type == VoteOnProposalTransaction.TYPE.lower():
            return VoteOnProposalTransaction.from_json(json_data, block_number, timestamp, position_in_the_block)
        else:
            return Transaction.from_json(json_data, block_number, timestamp, position_in_the_block)

    @property
    def size(self):
        return self._size

    @size.setter
    def size(self, value):
        self._size = value

    @property
    def position_in_the_block(self):
        return self._position_in_the_block

    @position_in_the_block.setter
    def position_in_the_block(self, value):
        self._position_in_the_block = value

    @property
    def fee(self):
        return self._fee

    @fee.setter
    def fee(self, value):
        self._fee = value

    @property
    def type(self):
        return self._type

    @type.setter
    def type(self, value):
        self._type = value

    @property
    def sender(self):
        return self._sender

    @sender.setter
    def sender(self, value):
        self._sender = value

    @property
    def receiver(self):
        return self._receiver

    @receiver.setter
    def receiver(self, value):
        self._receiver = value

    @property
    def nonce(self):
        return self._nonce

    @nonce.setter
    def nonce(self, value):
        self._nonce = value

    @property
    def hash(self):
        return self._hash

    @hash.setter
    def hash(self, value):
        self._hash = value

    @property
    def block_number(self):
        return self._block_number

    @block_number.setter
    def block_number(self, value):
        self._block_number = value

    @property
    def timestamp(self):
        return self._timestamp

    @timestamp.setter
    def timestamp(self, value):
        self._timestamp = value

    @property
    def value(self):
        return self._value

    @value.setter
    def value(self, value):
        self._value = value

    @property
    def raw_transaction(self):
        return self._raw_transaction

    @raw_transaction.setter
    def raw_transaction(self, value):
        self._raw_transaction = value

    def to_json(self):
        json_object = {
            "size": self.size,
            "positionInTheBlock": self.position_in_the_block,
            "fee": self.fee,
            "type": self.type,
            "sender": self.sender,
            "receiver": self.receiver,
            "nonce": self.nonce,
            "hash": self.hash,
            "blockNumber": self.block_number,
            "timestamp": self.timestamp,
            "value": self.value,
            "rawTransaction": self.raw_transaction.hex()
        }
        return json_object


class ClaimSpotTransaction(Transaction):
    TYPE = "Validator Claim Spot"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._validator: str = ""

    @classmethod
    def from_json(cls, json_data, block_number, timestamp, position_in_the_block):
        instance = super().from_json(json_data, block_number, timestamp, position_in_the_block)
        instance._validator = instance.sender
        return instance

    @property
    def validator(self) -> str:
        return self._validator

    @validator.setter
    def validator(self, value: str):
        self._validator = value

    def to_json(self):
        json_object = super().to_json()
        json_object['validator'] = self.validator
        return json_object


class ClaimVmIdTransaction(Transaction):
    TYPE = "Claim VM ID"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._vm_id: int = 0

    @classmethod
    def from_json(cls, json_data, block_number, timestamp, position_in_the_block):
        instance = super().from_json(json_data, block_number, timestamp, position_in_the_block)
        instance._vm_id = json_data.get('vmId', 0)
        return instance

    @property
    def vm_id(self) -> int:
        return self._vm_id

    def to_json(self):
        json_object = super().to_json()
        json_object['vmId'] = self.vm_id
        return json_object


class ConduitApprovalTransaction(Transaction):
    TYPE = "Conduit Approval"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._vm_id: int = 0
        self._transactions: List[Transaction] = []

    @classmethod
    def from_json(cls, json_data, block_number, timestamp, position_in_the_block):
        instance = super().from_json(json_data, block_number, timestamp, position_in_the_block)
        instance._vm_id = json_data.get('vmId', 0)
        transactions_data = json_data.get('transactions', [])
        instance._transactions = [
            Transaction.from_json(loads(transaction_data), block_number, timestamp, position_in_the_block)
            for transaction_data in transactions_data
        ]
        return instance

    @property
    def vm_id(self) -> int:
        return self._vm_id

    @property
    def transactions(self) -> List[Transaction]:
        return self._transactions

    def to_json(self):
        json_object = super().to_json()
        json_object['vmId'] = self.vm_id
        json_object['transactions'] = [transaction.to_json() for transaction in self.transactions]
        return json_object


class DelegateTransaction(Transaction):
    TYPE = "Delegate"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._validator: str = ""

    @classmethod
    def from_json(cls, json_data, block_number, timestamp, position_in_the_block):
        instance = super().from_json(json_data, block_number, timestamp, position_in_the_block)
        instance._validator = json_data.get('validator', '0x')
        return instance

    @property
    def validator(self) -> str:
        return self._validator

    def to_json(self):
        json_object = super().to_json()
        json_object['validator'] = self.validator
        return json_object


class GuardianApprovalTransaction(Transaction):
    TYPE = "Guardian Approval"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._transactions: List[Transaction] = []

    @classmethod
    def from_json(cls, json_data, block_number, timestamp, position_in_the_block):
        instance = super().from_json(json_data, block_number, timestamp, position_in_the_block)
        transactions_data = json_data.get('transactions', [])
        instance._transactions = [
            Transaction.from_json(transaction_data, block_number, timestamp, position_in_the_block)
            for transaction_data in transactions_data
        ]
        return instance

    @property
    def transactions(self) -> List[Transaction]:
        return self._transactions

    def to_json(self):
        json_object = super().to_json()
        json_object['transactions'] = [transaction.to_json() for transaction in self.transactions]
        return json_object


class JoinTransaction(Transaction):
    TYPE = "Validator Join"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._validator: str = ""
        self._ip: str = ""

    @classmethod
    def from_json(cls, json_data, block_number, timestamp, position_in_the_block):
        instance = super().from_json(json_data, block_number, timestamp, position_in_the_block)
        instance._validator = json_data.get('sender', '0x')
        instance._ip = json_data.get('ip', '')
        return instance

    @property
    def validator(self) -> str:
        return self._validator

    @property
    def ip(self) -> str:
        return self._ip

    def to_json(self):
        json_object = super().to_json()
        json_object['validator'] = self.validator
        json_object['ip'] = self.ip
        return json_object


class PayableVmDataTransaction(Transaction):
    TYPE = "Payable VM Data"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._vm_id: int = 0
        self._data: str = "0x"

    @classmethod
    def from_json(cls, json_data, block_number, timestamp, position_in_the_block):
        instance = super().from_json(json_data, block_number, timestamp, position_in_the_block)
        instance._vm_id = json_data.get('vmId', 0)
        instance._data = json_data.get('data', '0x')
        return instance

    @property
    def vm_id(self) -> int:
        return self._vm_id

    @property
    def data(self) -> str:
        return self._data

    def to_json(self):
        json_object = super().to_json()
        json_object['vmId'] = self.vm_id
        json_object['data'] = self.data
        return json_object


class RemoveGuardianTransaction(Transaction):
    TYPE = "Remove Guardian"

    @classmethod
    def from_json(cls, json_data, block_number, timestamp, position_in_the_block):
        instance = super().from_json(json_data, block_number, timestamp, position_in_the_block)
        return instance


class SetGuardianTransaction(Transaction):
    TYPE = "Set Guardian"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._guardian: str = "0x"
        self._expiry_date: int = 0

    @classmethod
    def from_json(cls, json_data, block_number, timestamp, position_in_the_block):
        instance = super().from_json(json_data, block_number, timestamp, position_in_the_block)
        instance._guardian = json_data.get('guardian', '0x')
        instance._expiry_date = json_data.get('expiryDate', 0)
        return instance

    @property
    def guardian(self) -> str:
        return self._guardian

    @property
    def expiry_date(self) -> int:
        return self._expiry_date

    def to_json(self):
        json_object = super().to_json()
        json_object['guardian'] = self.guardian
        json_object['expiryDate'] = self.expiry_date
        return json_object


class TransferTransaction(Transaction):
    TYPE = "Transfer"

    def __init__(self, *args, chainId: bytes = b'', **kwargs):
        super().__init__(*args, **kwargs)

    @classmethod
    def from_json(cls, json_data, block_number, timestamp, position_in_the_block):
        return super().from_json(json_data, block_number, timestamp, position_in_the_block)


class VmDataTransaction(Transaction):
    TYPE = "VM Data"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._vm_id: int = 0
        self._data: str = ""

    @classmethod
    def from_json(cls, json_data, block_number, timestamp, position_in_the_block):
        instance = super().from_json(json_data, block_number, timestamp, position_in_the_block)
        instance._vm_id = json_data.get('vmId', 0)
        instance._data = json_data.get('data', "")
        return instance

    @property
    def vm_id(self) -> int:
        return self._vm_id

    @property
    def data(self) -> str:
        return self._data

    def to_json(self):
        json_object = super().to_json()
        json_object['vmId'] = self.vm_id
        json_object['data'] = self.data
        json_object['type'] = "VM Data"
        return json_object


class WithdrawTransaction(Transaction):
    TYPE = "Withdraw"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._validator: str = "0x"
        self._shares: int = 0

    @classmethod
    def from_json(cls, json_data, block_number, timestamp, position_in_the_block):
        instance = super().from_json(json_data, block_number, timestamp, position_in_the_block)
        instance._validator = json_data.get('validator', '0x')
        instance._shares = json_data.get('shares', 0)
        return instance

    @property
    def validator(self) -> str:
        return self._validator

    @property
    def shares(self) -> int:
        return self._shares

    def to_json(self):
        json_object = super().to_json()
        json_object['validator'] = self.validator
        json_object['shares'] = self.shares
        return json_object


class AddConduitsTransaction(Transaction):
    TYPE = "Add Conduits"

    def __init__(self, json_data: dict, block_number: int, timestamp: int, position_in_the_block: int,
                 vm_id: int = 0, conduits: List[str] = None):
        super().__init__(json_data, block_number, timestamp, position_in_the_block)
        self.vm_id = json_data.get("vmId", 0)
        self.conduits = json_data.get("conduits", [])

    def to_json(self) -> dict:
        transaction = super().to_json()
        transaction["vmId"] = self.vm_id
        transaction["conduits"] = self.conduits
        return transaction


class MoveStakeTransaction(Transaction):
    TYPE = "Move Stake"

    def __init__(self, json_data: dict, block_number: int, timestamp: int, position_in_the_block: int,
                 from_validator: str = "0x", to_validator: str = "0x", shares_amount: int = 0):
        super().__init__(json_data, block_number, timestamp, position_in_the_block)
        self.from_validator = json_data.get("fromValidator", "0x")
        self.to_validator = json_data.get("toValidator", "0x")
        self.shares_amount = json_data.get("sharesAmount", 0)

    def to_json(self) -> dict:
        transaction = super().to_json()
        transaction["fromValidator"] = self.from_validator
        transaction["toValidator"] = self.to_validator
        transaction["sharesAmount"] = self.shares_amount
        return transaction


class RemoveConduitsTransaction(Transaction):
    TYPE = "Remove Conduits"

    def __init__(self, json_data: dict, block_number: int, timestamp: int, position_in_the_block: int,
                 vm_id: int = 0, conduits: List[str] = None):
        super().__init__(json_data, block_number, timestamp, position_in_the_block)
        self.vm_id = json_data.get("vmId", 0)
        self.conduits = json_data.get("conduits", [])

    def to_json(self) -> dict:
        transaction = super().to_json()
        transaction["vmId"] = self.vm_id
        transaction["conduits"] = self.conduits
        return transaction


class SetConduitsTransaction(Transaction):
    TYPE = "Set Conduits"

    def __init__(self, json_data: dict, block_number: int, timestamp: int, position_in_the_block: int,
                 vm_id: int = 0, conduits: List[str] = None):
        super().__init__(json_data, block_number, timestamp, position_in_the_block)
        self.vm_id = json_data.get("vmId", 0)
        self.conduits = json_data.get("conduits", [])

    def to_json(self) -> dict:
        transaction = super().to_json()
        transaction["vmId"] = self.vm_id
        transaction["conduits"] = self.conduits
        return transaction


class ChangeEarlyWithdrawPenaltyProposalTransaction(Transaction):
    TYPE = "Change Early Withdraw Penalty Proposal"

    def __init__(self, json_data: dict, block_number: int, timestamp: int, position_in_the_block: int,
                 withdrawal_penalty_time: int = 0, withdrawal_penalty: int = 0, title: str = "", description: str = ""):
        super().__init__(json_data, block_number, timestamp, position_in_the_block)
        self.withdrawal_penalty_time = json_data.get("earlyWithdrawTime", 0)
        self.withdrawal_penalty = json_data.get("earlyWithdrawPenalty", 0)
        self.title = json_data.get("title", "")
        self.description = json_data.get("description", "")

    @classmethod
    def from_json(cls, json_data, block_number, timestamp, position_in_the_block):
        instance = super().from_json(json_data, block_number, timestamp, position_in_the_block)
        instance.withdrawal_penalty_time = json_data.get("earlyWithdrawTime", 0)
        instance.withdrawal_penalty = json_data.get("earlyWithdrawPenalty", 0)
        instance.title = json_data.get("title", "")
        instance.description = json_data.get("description", "")
        return instance

    def to_json(self) -> dict:
        transaction = super().to_json()
        transaction["withdrawalPenaltyTime"] = self.withdrawal_penalty_time
        transaction["withdrawalPenalty"] = self.withdrawal_penalty
        transaction["title"] = self.title
        transaction["description"] = self.description
        return transaction


class ChangeFeePerByteProposalTransaction(Transaction):
    TYPE = "Change Fee Per Byte Proposal"

    def __init__(self, json_data: dict, block_number: int, timestamp: int, position_in_the_block: int,
                 fee_per_byte: int = 8, title: str = "", description: str = ""):
        super().__init__(json_data, block_number, timestamp, position_in_the_block)
        self.fee_per_byte = json_data.get("feePerByte", 8)
        self.title = json_data.get("title", "")
        self.description = json_data.get("description", "")

    @classmethod
    def from_json(cls, json_data, block_number, timestamp, position_in_the_block):
        instance = super().from_json(json_data, block_number, timestamp, position_in_the_block)
        instance.fee_per_byte = json_data.get("feePerByte", 8)
        instance.title = json_data.get("title", "")
        instance.description = json_data.get("description", "")
        return instance

    def to_json(self) -> dict:
        transaction = super().to_json()
        transaction["feePerByte"] = self.fee_per_byte
        transaction["title"] = self.title
        transaction["description"] = self.description
        return transaction


class ChangeMaxBlockSizeProposalTransaction(Transaction):
    TYPE = "Change Max Block Size Proposal"

    def __init__(self, json_data: dict, block_number: int, timestamp: int, position_in_the_block: int,
                 max_block_size: int = 4, title: str = "", description: str = ""):
        super().__init__(json_data, block_number, timestamp, position_in_the_block)
        self.max_block_size = json_data.get("maxBlockSize", 4)
        self.title = json_data.get("title", "")
        self.description = json_data.get("description", "")

    @classmethod
    def from_json(cls, json_data, block_number, timestamp, position_in_the_block):
        instance = super().from_json(json_data, block_number, timestamp, position_in_the_block)
        instance.max_block_size = json_data.get("maxBlockSize", 4)
        instance.title = json_data.get("title", "")
        instance.description = json_data.get("description", "")
        return instance

    def to_json(self) -> dict:
        transaction = super().to_json()
        transaction["maxBlockSize"] = self.max_block_size
        transaction["title"] = self.title
        transaction["description"] = self.description
        return transaction


class ChangeMaxTxnSizeProposalTransaction(Transaction):
    TYPE = "Change Max Txn Size Proposal"

    def __init__(self, json_data: dict, block_number: int, timestamp: int, position_in_the_block: int,
                 max_txn_size: int = 8, title: str = "", description: str = ""):
        super().__init__(json_data, block_number, timestamp, position_in_the_block)
        self.max_txn_size = json_data.get("maxTxnSize", 8)
        self.title = json_data.get("title", "")
        self.description = json_data.get("description", "")

    @classmethod
    def from_json(cls, json_data, block_number, timestamp, position_in_the_block):
        instance = super().from_json(json_data, block_number, timestamp, position_in_the_block)
        instance.max_txn_size = json_data.get("maxTxnSize", 8)
        instance.title = json_data.get("title", "")
        instance.description = json_data.get("description", "")
        return instance

    def to_json(self) -> dict:
        transaction = super().to_json()
        transaction["maxTxnSize"] = self.max_txn_size
        transaction["title"] = self.title
        transaction["description"] = self.description
        return transaction


class ChangeOverallBurnPercentageProposalTransaction(Transaction):
    TYPE = "Change Overall Burn Percentage Proposal"

    def __init__(self, json_data: dict, block_number: int, timestamp: int, position_in_the_block: int,
                 burn_percentage: int = 4, title: str = "", description: str = ""):
        super().__init__(json_data, block_number, timestamp, position_in_the_block)
        self.burn_percentage = json_data.get("overallBurnPercentage", 4)
        self.title = json_data.get("title", "")
        self.description = json_data.get("description", "")

    @classmethod
    def from_json(cls, json_data, block_number, timestamp, position_in_the_block):
        instance = super().from_json(json_data, block_number, timestamp, position_in_the_block)
        instance.burn_percentage = json_data.get("overallBurnPercentage", 4)
        instance.title = json_data.get("title", "")
        instance.description = json_data.get("description", "")
        return instance

    def to_json(self) -> dict:
        transaction = super().to_json()
        transaction["burnPercentage"] = self.burn_percentage
        transaction["title"] = self.title
        transaction["description"] = self.description
        return transaction


class ChangeRewardPerYearProposalTransaction(Transaction):
    TYPE = "Change Reward Per Year Proposal"

    def __init__(self, json_data: dict, block_number: int, timestamp: int, position_in_the_block: int,
                 reward_per_year: int = 8, title: str = "", description: str = ""):
        super().__init__(json_data, block_number, timestamp, position_in_the_block)
        self.reward_per_year = json_data.get("rewardPerYear", 8)
        self.title = json_data.get("title", "")
        self.description = json_data.get("description", "")

    @classmethod
    def from_json(cls, json_data, block_number, timestamp, position_in_the_block):
        instance = super().from_json(json_data, block_number, timestamp, position_in_the_block)
        instance.reward_per_year = json_data.get("rewardPerYear", 8)
        instance.title = json_data.get("title", "")
        instance.description = json_data.get("description", "")
        return instance

    def to_json(self) -> dict:
        transaction = super().to_json()
        transaction["rewardPerYear"] = self.reward_per_year
        transaction["title"] = self.title
        transaction["description"] = self.description
        return transaction


class ChangeValidatorCountLimitProposalTransaction(Transaction):
    TYPE = "Change Validator Count Limit Proposal"

    def __init__(self, json_data: dict, block_number: int, timestamp: int, position_in_the_block: int,
                 validator_count_limit: int = 4, title: str = "", description: str = ""):
        super().__init__(json_data, block_number, timestamp, position_in_the_block)
        self.validator_count_limit = json_data.get("validatorCountLimit", 4)
        self.title = json_data.get("title", "")
        self.description = json_data.get("description", "")

    @classmethod
    def from_json(cls, json_data, block_number, timestamp, position_in_the_block):
        instance = super().from_json(json_data, block_number, timestamp, position_in_the_block)
        instance.validator_count_limit = json_data.get("validatorCountLimit", 4)
        instance.title = json_data.get("title", "")
        instance.description = json_data.get("description", "")
        return instance

    def to_json(self) -> dict:
        transaction = super().to_json()
        transaction["validatorCountLimit"] = self.validator_count_limit
        transaction["title"] = self.title
        transaction["description"] = self.description
        return transaction


class ChangeValidatorJoiningFeeProposalTransaction(Transaction):
    TYPE = "Change Validator Joining Fee Proposal"

    def __init__(self, json_data: dict, block_number: int, timestamp: int, position_in_the_block: int,
                 joining_fee: int = 8, title: str = "", description: str = ""):
        super().__init__(json_data, block_number, timestamp, position_in_the_block)
        self.joining_fee = json_data.get("validatorJoiningFee", 8)
        self.title = json_data.get("title", "")
        self.description = json_data.get("description", "")

    @classmethod
    def from_json(cls, json_data, block_number, timestamp, position_in_the_block):
        instance = super().from_json(json_data, block_number, timestamp, position_in_the_block)
        instance.joining_fee = json_data.get("validatorJoiningFee", 8)
        instance.title = json_data.get("title", "")
        instance.description = json_data.get("description", "")
        return instance

    def to_json(self) -> dict:
        transaction = super().to_json()
        transaction["joiningFee"] = self.joining_fee
        transaction["title"] = self.title
        transaction["description"] = self.description
        return transaction


class ChangeVmIdClaimingFeeProposalTransaction(Transaction):
    TYPE = "Change Vm Id Claiming Fee Proposal"

    def __init__(self, json_data: dict, block_number: int, timestamp: int, position_in_the_block: int,
                 claiming_fee: int = 8, title: str = "", description: str = ""):
        super().__init__(json_data, block_number, timestamp, position_in_the_block)
        self.claiming_fee = json_data.get("vmIdClaimingFee", 8)
        self.title = json_data.get("title", "")
        self.description = json_data.get("description", "")

    @classmethod
    def from_json(cls, json_data, block_number, timestamp, position_in_the_block):
        instance = super().from_json(json_data, block_number, timestamp, position_in_the_block)
        instance.claiming_fee = json_data.get("vmIdClaimingFee", 8)
        instance.title = json_data.get("title", "")
        instance.description = json_data.get("description", "")
        return instance

    def to_json(self) -> dict:
        transaction = super().to_json()
        transaction["claimingFee"] = self.claiming_fee
        transaction["title"] = self.title
        transaction["description"] = self.description
        return transaction


class ChangeVmOwnerTxnFeeShareProposalTransaction(Transaction):
    TYPE = "Change VM Owner Txn Fee Share Proposal"

    def __init__(self, json_data: dict, block_number: int, timestamp: int, position_in_the_block: int,
                 fee_share: int = 8, title: str = "", description: str = ""):
        super().__init__(json_data, block_number, timestamp, position_in_the_block)
        self.fee_share = json_data.get("vmOwnerTxnFeeShare", 8)
        self.title = json_data.get("title", "")
        self.description = json_data.get("description", "")

    @classmethod
    def from_json(cls, json_data, block_number, timestamp, position_in_the_block):
        instance = super().from_json(json_data, block_number, timestamp, position_in_the_block)
        instance.fee_share = json_data.get("vmOwnerTxnFeeShare", 8)
        instance.title = json_data.get("title", "")
        instance.description = json_data.get("description", "")
        return instance

    def to_json(self) -> dict:
        transaction = super().to_json()
        transaction["feeShare"] = self.fee_share
        transaction["title"] = self.title
        transaction["description"] = self.description
        return transaction


class OtherProposalTransaction(Transaction):
    TYPE = "Other Proposal"

    def __init__(self, json_data: dict, block_number: int, timestamp: int, position_in_the_block: int,
                 title: str = "", description: str = ""):
        super().__init__(json_data, block_number, timestamp, position_in_the_block)
        self.title = json_data.get("title", "")
        self.description = json_data.get("description", "")

    @classmethod
    def from_json(cls, json_data, block_number, timestamp, position_in_the_block):
        instance = super().from_json(json_data, block_number, timestamp, position_in_the_block)
        instance.title = json_data.get("title", "")
        instance.description = json_data.get("description", "")
        return instance

    def to_json(self) -> dict:
        transaction = super().to_json()
        transaction["title"] = self.title
        transaction["description"] = self.description
        return transaction


class VoteOnProposalTransaction(Transaction):
    TYPE = "Vote On Proposal"

    def __init__(self, json_data: dict, block_number: int, timestamp: int, position_in_the_block: int,
                 proposal_hash: str = "0x", vote: int = 0, proposal_status: str = "ongoing"):
        super().__init__(json_data, block_number, timestamp, position_in_the_block)
        self.proposal_hash = json_data.get("proposalHash", "0x")
        self.vote = json_data.get("vote", 0)
        self.proposal_status = json_data.get("proposalStatus", "ongoing")

    @classmethod
    def from_json(cls, json_data, block_number, timestamp, position_in_the_block):
        instance = super().from_json(json_data, block_number, timestamp, position_in_the_block)
        instance.proposal_hash = json_data.get("proposalHash", "0x")
        instance.vote = json_data.get("vote", 0)
        instance.proposal_status = json_data.get("proposalStatus", "ongoing")
        return instance

    def to_json(self) -> dict:
        transaction = super().to_json()
        transaction["proposalHash"] = self.proposal_hash
        transaction["vote"] = self.vote
        return transaction
