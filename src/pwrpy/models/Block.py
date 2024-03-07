from pwrpy.models.ClaimSpotTxn import ClaimSpotTxn
from pwrpy.models.ClaimVmIdTxn import ClaimVmIdTxn
from pwrpy.models.ConduitApprovalTxn import ConduitApprovalTxn
from pwrpy.models.DelegateTxn import DelegateTxn
from pwrpy.models.GuardianApprovedTxn import GuardianApprovedTxn
from pwrpy.models.JoinTxn import JoinTxn
from pwrpy.models.PayableVmDataTxn import PayableVmDataTxn
from pwrpy.models.SetGuardianTxn import SetGuardianTxn
from pwrpy.models.Transaction import Transaction
from pwrpy.models.TransferTxn import TransferTxn
from pwrpy.models.VmDataTxn import VmDataTxn
from pwrpy.models.WithdrawTxn import WithdrawTxn


class Block:
    def __init__(self, block_data=None):
        if block_data:
            self.from_json(block_data)
        else:
            self._transaction_count = None
            self._size = None
            self._number = None
            self._reward = None
            self._timestamp = None
            self._hash = None
            self._submitter = None
            self._success = None
            self._transactions = []

    @classmethod
    def from_json(cls, block_data):
        json_data = block_data.get('block')
        instance = cls()  # Use cls() instead of Block() to support subclassing
        instance._transaction_count = json_data.get('transactionCount', 0)
        instance._size = json_data.get('blockSize', 0)
        instance._number = json_data.get('blockNumber', 0)
        instance._reward = json_data.get('blockReward', 0)
        instance._timestamp = json_data.get('timestamp', 0)
        instance._hash = json_data.get('blockHash', None)
        instance._submitter = json_data.get('blockSubmitter', None)
        instance._success = json_data.get('success', False)
        instance._transactions = []

        transactions_list = json_data.get('transactions', [])
        for transaction in transactions_list:
            txn_type = transaction.get('type', 'unknown')
            latest_index = len(instance._transactions)
            if txn_type == 'Validator Claim Spot':
                txn = ClaimSpotTxn.from_json(transaction)
            elif txn_type == 'Conduit Approval':
                txn = ConduitApprovalTxn.from_json(transaction)
            elif txn_type == 'Transfer':
                txn = TransferTxn.from_json(transaction)
            elif txn_type == 'VM Data':
                txn = VmDataTxn.from_json(transaction)
            elif txn_type == 'Delegate':
                txn = DelegateTxn.from_json(transaction)
            elif txn_type == 'Withdraw':
                txn = WithdrawTxn.from_json(transaction)
            elif txn_type == 'Validator Join':
                txn = JoinTxn.from_json(transaction)
            elif txn_type == 'Claim VM ID':
                txn = ClaimVmIdTxn.from_json(transaction)
            elif txn_type == 'Set Guardian':
                txn = SetGuardianTxn.from_json(transaction)
            elif txn_type == 'Payable VM Data':
                txn = PayableVmDataTxn.from_json(transaction)
            elif txn_type == 'Guardian Approval':
                txn = GuardianApprovedTxn.from_json(transaction)
            else:
                txn = Transaction.from_json(transaction)

            txn.block_number = instance._number
            txn.timestamp = instance._timestamp
            txn.position_in_the_block = latest_index
            instance._transactions.append(txn)

        return instance

    def set_transaction_count(self, value):
        self._transaction_count = value

    def set_size(self, value):
        self._size = value

    def set_number(self, value):
        self._number = value

    def set_reward(self, value):
        self._reward = value

    def set_timestamp(self, value):
        self._timestamp = value

    def set_hash(self, value):
        self._hash = value

    def set_submitter(self, value):
        self._submitter = value

    def set_success(self, value):
        self._success = value

    def set_transactions(self, value):
        self._transactions = value

    @property
    def transaction_count(self):
        return self._transaction_count

    @property
    def size(self):
        return self._size

    @property
    def number(self):
        return self._number

    @property
    def reward(self):
        return self._reward

    @property
    def timestamp(self):
        return self._timestamp

    @property
    def hash(self):
        return self._hash

    @property
    def submitter(self):
        return self._submitter

    @property
    def success(self):
        return self._success

    @property
    def transactions(self):
        return self._transactions
