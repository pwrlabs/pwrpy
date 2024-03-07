from pwrpy.models.Transaction import Transaction
from json import loads, dumps


class WithdrawTxn(Transaction):
    @classmethod
    def from_json(cls, json_data):
        instance = super().from_json(json_data)
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
