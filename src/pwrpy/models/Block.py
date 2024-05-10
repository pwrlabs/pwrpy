from pwrpy.models.Transaction import Transaction


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
    def from_json(cls, json_data):
        instance = cls()
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
        for i, transaction in enumerate(transactions_list):
            instance._transactions.append(
                Transaction.transaction_from_json(transaction, instance._number, instance._timestamp, i))

        return instance

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
