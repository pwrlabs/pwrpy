from pwrpy.models.Transaction import Transaction
from json import loads,dumps


class DelegateTxn(Transaction):
    @classmethod
    def from_json(cls, json_data):
        instance = super().from_json(json_data)
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

