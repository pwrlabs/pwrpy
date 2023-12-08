class Block:
    def __init__(self, transaction_count, size, number, reward, timestamp, hash, submitter, success, transactions):
        self._transaction_count = transaction_count
        self._size = size
        self._number = number
        self._reward = reward
        self._timestamp = timestamp
        self._hash = hash
        self._submitter = submitter
        self._success = success
        self._transactions = transactions

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
