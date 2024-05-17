from typing import List, Dict, Any
from src.pwrpy.models.Transaction import Transaction


class Block:
    def __init__(self, block_data: Dict[str, Any] = None):
        if block_data:
            self.from_json(block_data)
        else:
            self._transaction_count: int = 0
            self._size: int = 0
            self._number: int = 0
            self._reward: int = 0
            self._timestamp: int = 0
            self._hash: str = ""
            self._submitter: str = ""
            self._success: bool = False
            self._transactions: List[Transaction] = []

    @classmethod
    def from_json(cls, json_data: Dict[str, Any]) -> 'Block':
        instance = cls()
        instance._transaction_count = json_data.get('transactionCount', 0)
        instance._size = json_data.get('blockSize', 0)
        instance._number = json_data.get('blockNumber', 0)
        instance._reward = json_data.get('blockReward', 0)
        instance._timestamp = json_data.get('timestamp', 0)
        instance._hash = json_data.get('blockHash', "")
        instance._submitter = json_data.get('blockSubmitter', "")
        instance._success = json_data.get('success', False)
        instance._transactions = []

        transactions_list = json_data.get('transactions', [])
        for i, transaction in enumerate(transactions_list):
            instance._transactions.append(
                Transaction.transaction_from_json(transaction, instance._number, instance._timestamp, i))

        return instance

    @property
    def transaction_count(self) -> int:
        return self._transaction_count

    @property
    def size(self) -> int:
        return self._size

    @property
    def number(self) -> int:
        return self._number

    @property
    def reward(self) -> int:
        return self._reward

    @property
    def timestamp(self) -> int:
        return self._timestamp

    @property
    def hash(self) -> str:
        return self._hash

    @property
    def submitter(self) -> str:
        return self._submitter

    @property
    def success(self) -> bool:
        return self._success

    @property
    def transactions(self) -> List[Transaction]:
        return self._transactions
