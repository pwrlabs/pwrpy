from json import loads,dumps
from pwrpy.models.Transaction import Transaction


class PayableVmDataTxn(Transaction):
    @classmethod
    def from_json(cls, json_data):
        instance = super().from_json(json_data)
        vm_id = json_data.get('vmId', 0)
        data = json_data.get('data','0x')
        instance._vm_id = vm_id
        instance._data = data
        return instance

    @property
    def vm_id(self):
        return self._vm_id

    @property
    def data(self):
        return self._data

    def to_json(self):
        json_object = super().to_json()
        json_object['data'] = self._data
        json_object['vmId'] = self._vm_id
        return json_object











