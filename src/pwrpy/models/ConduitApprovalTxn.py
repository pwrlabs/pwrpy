from pwrpy.models.Transaction import Transaction
from json import dumps, loads


class ConduitApprovalTxn(Transaction):
    @classmethod
    def from_json(cls, json_data):
        instance = super().from_json(json_data)
        vm_id = json_data.get('vmId')
        transactions = json_data.get('transactions', [])
        transactions_strs = []
        if len(transactions) != 0:
            for transaction in transactions:
                transactions_strs.append(dumps(transaction))

        instance._transactions = transactions_strs
        instance._vm_id = vm_id
        instance._type = 'Conduit Approval'
        return instance

    @property
    def vm_id(self):
        return self._vm_id

    @property
    def transactions(self):
        return self._transactions