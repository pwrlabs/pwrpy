from pwrpy.models.Transaction import Transaction
from json import dumps, loads


class ClaimVmIdTxn(Transaction):
    @classmethod
    def from_json(cls, json_data):
        instance = super().from_json(json_data)
        vm_id = json_data.get('vmId')
        instance._vm_id = vm_id
        return instance

    @property
    def vm_id(self):
        return self._vm_id

    def to_json(self):
        json_object = super().to_json()
        json_object['vmId'] = self.vm_id
        return json_object
