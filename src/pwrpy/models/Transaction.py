from json import loads,dumps


class Transaction:
    def __init__(self, size: int, block_number: int, position_in_the_block: int, fee: int, type: int, sender: str,
                 receiver: str, nonce: int, hash: str, timestamp: int, value: int):
        self._size = size
        self._block_number = block_number
        self._position_in_the_block = position_in_the_block
        self._fee = fee
        self._type = type
        self._sender = sender
        self._receiver = receiver
        self._nonce = nonce
        self._hash = hash
        self._timestamp = timestamp
        self._value = value

    ### This method will return a Transaction object from a json object
    @classmethod
    def from_json(cls, json_data, block_number, timestamp, position_in_the_block):
        size = json_data.get('size', 0)
        block_number = block_number
        position_in_the_block = position_in_the_block
        fee = json_data.get('fee', 0)
        _type = json_data.get('type', 'unknown')
        sender = json_data.get('sender', '0x')
        receiver = json_data.get('receiver', '0x')
        nonce = json_data.get('nonce', 0)
        _hash = json_data.get('hash', '0x')
        timestamp = timestamp
        value = json_data.get('value', 0)
        return cls(size, block_number, position_in_the_block, fee, _type, sender, receiver, nonce, _hash, timestamp,
                   value)

    ### This method will return a transaction object depending on the transaction type from the json object
    @classmethod
    def transaction_from_json(cls, json_data, block_number, timestamp, position_in_the_block):
        txn_type = str(json_data.get('type', 'Unknown').lower())
        if txn_type == ClaimSpotTxn.TYPE.casefold():
            return ClaimSpotTxn.from_json(json_data, block_number, timestamp, position_in_the_block)
        elif txn_type == TransferTxn.TYPE.casefold():
            return TransferTxn.from_json(json_data, block_number, timestamp, position_in_the_block)
        elif txn_type == VmDataTxn.TYPE.casefold():
            return VmDataTxn.from_json(json_data, block_number, timestamp, position_in_the_block)
        elif txn_type == DelegateTxn.TYPE.casefold():
            return DelegateTxn.from_json(json_data, block_number, timestamp, position_in_the_block)
        elif txn_type == WithdrawTxn.TYPE.casefold():
            return WithdrawTxn.from_json(json_data, block_number, timestamp, position_in_the_block)
        elif txn_type == JoinTxn.TYPE.casefold():
            return JoinTxn.from_json(json_data, block_number, timestamp, position_in_the_block)
        elif txn_type == ClaimVmIdTxn.TYPE.casefold():
            return ClaimVmIdTxn.from_json(json_data, block_number, timestamp, position_in_the_block)
        elif txn_type == SetGuardianTxn.TYPE.casefold():
            return SetGuardianTxn.from_json(json_data, block_number, timestamp, position_in_the_block)
        elif txn_type == PayableVmDataTxn.TYPE.casefold():
            return PayableVmDataTxn.from_json(json_data, block_number, timestamp, position_in_the_block)
        elif txn_type == GuardianApprovedTxn.TYPE.casefold():
            return GuardianApprovedTxn.from_json(json_data, block_number, timestamp, position_in_the_block)
        elif txn_type == ConduitApprovalTxn.TYPE.casefold():
            return ConduitApprovalTxn.from_json(json_data, block_number, timestamp, position_in_the_block)
        elif txn_type == RemoveGuardianTxn.TYPE.casefold():
            return RemoveGuardianTxn.from_json(json_data, block_number, timestamp, position_in_the_block)
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
            "value": self.value
        }
        return json_object


class ClaimSpotTxn(Transaction):
    TYPE = "Validator Claim Spot"

    @classmethod
    def from_json(cls, json_data, block_number, timestamp, position_in_the_block):
        instance = super().from_json(json_data, block_number, timestamp, position_in_the_block)
        validator = json_data.get('sender', '0x')
        instance._validator = validator
        return instance

    @property
    def validator(self):
        return self._validator

    @validator.setter
    def validator(self, value):
        self._validator = value

    def to_json(self):
        json_object = super().to_json()
        json_object['validator'] = self.validator
        return json_object

    class ClaimVmIdTxn(Transaction):
        TYPE = "Claim VM ID"

        @classmethod
        def from_json(cls, json_data, block_number, timestamp, position_in_the_block):
            instance = super().from_json(json_data, block_number, timestamp, position_in_the_block)
            vm_id = json_data.get('vmId', 0)
            instance._vm_id = vm_id
            return instance

        @property
        def vm_id(self):
            return self._vm_id

        def to_json(self):
            json_object = super().to_json()
            json_object['vmId'] = self.vm_id
            return json_object


class ClaimVmIdTxn(Transaction):
    TYPE = "Claim VM ID"
    @classmethod
    def from_json(cls, json_data, block_number, timestamp, position_in_the_block):
        instance = super().from_json(json_data, block_number, timestamp, position_in_the_block)
        vm_id = json_data.get('vmId', 0)
        instance._vm_id = vm_id
        return instance

    @property
    def vm_id(self):
        return self._vm_id

    def to_json(self):
        json_object = super().to_json()
        json_object['vmId'] = self.vm_id
        return json_object


class ConduitApprovalTxn(Transaction):
    TYPE = "Conduit Approval"

    @classmethod
    def from_json(cls, json_data, block_number, timestamp, position_in_the_block):
        instance = super().from_json(json_data, block_number, timestamp, position_in_the_block)
        vm_id = json_data.get('vmId', 0)
        transactions = json_data.get('transactions', [])
        transactions_strs = []
        if len(transactions) != 0:
            for transaction in transactions:
                transactions_strs.append(dumps(transaction))

        instance._transactions = transactions_strs
        instance._vm_id = vm_id
        return instance

    @property
    def vm_id(self):
        return self._vm_id

    @property
    def transactions(self):
        return self._transactions


class DelegateTxn(Transaction):
    TYPE = "Delegate"

    @classmethod
    def from_json(cls, json_data, block_number, timestamp, position_in_the_block):
        instance = super().from_json(json_data, block_number, timestamp, position_in_the_block)
        validator = json_data.get('sender', '0x')
        instance._validator = validator
        return instance

    @property
    def validator(self):
        return self._validator

    def to_json(self):
        json_object = super().to_json()
        json_object['validator'] = self.validator
        return json_object


class GuardianApprovedTxn(Transaction):
    TYPE = "Guardian Approval"

    @classmethod
    def from_json(cls, json_data, block_number, timestamp, position_in_the_block):
        instance = super().from_json(json_data, block_number, timestamp, position_in_the_block)
        transactions = json_data.get('transactions', [])
        transactions_strs = []
        if len(transactions) != 0:
            for transaction in transactions:
                transactions_strs.append(dumps(transaction))

        instance._transactions = transactions_strs
        return instance

    @property
    def transactions(self):
        return self._transactions

    def to_json(self):
        json_object = super().to_json()
        json_object['transactions'] = loads(self._transactions)


class JoinTxn(Transaction):
    TYPE = "Validator Join"

    @classmethod
    def from_json(cls, json_data, block_number, timestamp, position_in_the_block):
        instance = super().from_json(json_data, block_number, timestamp, position_in_the_block)
        validator = json_data.get('sender', '0x')
        instance._validator = validator
        return instance

    @property
    def validator(self):
        return self._validator

    def to_json(self):
        json_object = super().to_json()
        json_object['validator'] = self._validator
        return json_object


class PayableVmDataTxn(Transaction):
    TYPE = "Payable VM Data"

    @classmethod
    def from_json(cls, json_data, block_number, timestamp, position_in_the_block):
        instance = super().from_json(json_data, block_number, timestamp, position_in_the_block)
        vm_id = json_data.get('vmId', 0)
        data = json_data.get('data', '0x')
        instance._vm_id = vm_id
        instance._data = data
        return instance

    @property
    def vm_id(self):
        return self._vm_id

    @property
    def data(self):
        return self._data

    def to_json(self):
        json_object = super().to_json()
        json_object['data'] = self._data
        json_object['vmId'] = self._vm_id
        return json_object


class RemoveGuardianTxn(Transaction):
    TYPE = "Remove Guardian"

    @classmethod
    def from_json(cls, json_data, block_number, timestamp, position_in_the_block):
        instance = super().from_json(json_data, block_number, timestamp, position_in_the_block)
        return instance


class SetGuardianTxn(Transaction):
    TYPE = "Set Guardian"

    @classmethod
    def from_json(cls, json_data, block_number, timestamp, position_in_the_block):
        instance = super().from_json(json_data, block_number, timestamp, position_in_the_block)
        guardian = json_data.get('guardian', '0x')
        expiry_date = json_data.get('expiryDate', 0)
        instance._guardian = guardian
        instance._expiry_date = expiry_date
        return instance

    @property
    def guardian(self):
        return self._guardian

    @property
    def expiry_date(self):
        return self._expiry_date

    def to_json(self):
        json_object = super().to_json()
        json_object['guardian'] = self.guardian
        json_object['expiryDate'] = self.expiry_date
        return json_object


class TransferTxn(Transaction):
    TYPE = "Transfer"

    @classmethod
    def from_json(cls, json_data, block_number, timestamp, position_in_the_block):
        instance = super().from_json(json_data, block_number, timestamp, position_in_the_block)
        return instance

    def to_json(self):
        return super().to_json()


class TxnForGuardianApproval:
    def __init__(self, valid: bool, guardian_address: str, errorMessage: str, transaction: Transaction):
        self._valid = valid
        self._errorMessage = errorMessage
        self._transaction = transaction
        self._guardian_address = guardian_address

    @property
    def valid(self):
        return self._valid

    @property
    def errorMessage(self):
        return self._errorMessage

    @property
    def transaction(self):
        return self._transaction

    @property
    def guardian_address(self):
        return self._guardian_address


class VmDataTxn(Transaction):
    TYPE = "VM Data"

    @classmethod
    def from_json(cls, json_data, block_number, timestamp, position_in_the_block):
        instance = super().from_json(json_data, block_number, timestamp, position_in_the_block)
        vm_id = json_data.get('vmId')
        data = json_data.get('data')
        instance._vm_id = vm_id
        instance._data = data
        return instance

    @property
    def vm_id(self):
        return self._vm_id

    @vm_id.setter
    def vm_id(self, value):
        self._vm_id = value

    @property
    def data(self):
        return self._data

    @data.setter
    def data(self, value):
        self._data = value

    def to_json(self):
        json_object = super().to_json()
        json_object['vmId'] = self.vm_id
        json_object['data'] = self.data
        return json_object


class WithdrawTxn(Transaction):
    TYPE = "Withdraw"

    @classmethod
    def from_json(cls, json_data, block_number, timestamp, position_in_the_block):
        instance = super().from_json(json_data, block_number, timestamp, position_in_the_block)
        validator = json_data.get('sender', '0x')
        shares = json_data.get('shares', 0)
        instance._validator = validator
        instance._shares = shares
        return instance

    @property
    def validator(self):
        return self._validator

    @property
    def shares(self):
        return self._shares

    def to_json(self):
        json_object = super().to_json()
        json_object['validator'] = self.validator
        json_object['shares'] = self.shares
        return json_object
