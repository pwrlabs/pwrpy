from typing import List

from pwrpy.models.Transaction import Transaction


class BlockTransaction:
    def __init__(self, identifier: int = 0, transaction_hash: str = "0x"):
        self.identifier = identifier
        self.transaction_hash = transaction_hash

    @classmethod
    def from_json(cls, json_data: dict):
        return cls(
            identifier=json_data.get('identifier', 0),
            transaction_hash=json_data.get('transactionHash', '0x')
        )

    def to_json(self) -> dict:
        return {
            'identifier': self.identifier,
            'transactionHash': self.transaction_hash
        }

    def __str__(self) -> str:
        return f"BlockTransaction(identifier={self.identifier}, hash={self.transaction_hash})"

    def __repr__(self) -> str:
        return self.__str__()


class Block:
    def __init__(self, transaction_count, size, number, reward,
                 timestamp, hash_value, submitter,
                 processed_without_critical_errors,
                 transactions):
        self._transaction_count: int = transaction_count
        self._size: int = size
        self._number: int = number
        self._reward: int = reward
        self._timestamp: int = timestamp
        self._hash: str = hash_value
        self._submitter: str = submitter
        self._processed_without_critical_errors: bool = submitter
        self._transactions = transactions

    @classmethod
    def from_json(cls, block_json):
        transaction_count = block_json.get("transactionCount", 0)
        size = block_json.get("blockSize", 0)
        number = block_json.get("blockNumber", 0)
        reward = block_json.get("blockReward", 0)
        timestamp = block_json.get("timestamp", 0)
        hash_value = block_json.get("blockHash", None)
        submitter = block_json.get("blockSubmitter", None)
        processed_without_critical_errors = block_json.get("processedWithoutCriticalErrors", True)

        txns = block_json.get("transactions", [])
        transactions = [
            BlockTransaction.from_json(txn) for txn in txns
        ]

        return cls(transaction_count, size, number, reward,
                   timestamp, hash_value, submitter,
                   processed_without_critical_errors,
                   transactions)

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
    def processed_without_critical_errors(self) -> bool:
        return self._processed_without_critical_errors

    @property
    def transactions(self) -> List[Transaction]:
        return self._transactions
