from pwrpy.models.Transaction import Transaction
from json import loads, dumps


class GuardianApprovedTxn(Transaction):
    @classmethod
    def from_json(cls, json_data):
        instance = super().from_json(json_data)
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

