from src.pwrpy.models.Transaction import Transaction
from json import loads, dumps


class VmDataTxn(Transaction):
    @classmethod
    def from_json(cls, json_data):
        instance = super().from_json(json_data)
        vm_id = json_data.get('vmId')
        data = json_data.get('data')
        instance._vm_id = vm_id
        instance._data = data
        return instance

    @property
    def vm_id(self):
        return self._vm_id

    @vm_id.setter
    def vm_id(self, value):
        self._vm_id = value

    @property
    def data(self):
        return self._data

    @data.setter
    def data(self, value):
        self._data = value

    def to_json(self):
        json_object = super().to_json()
        json_object['vmId'] = self.vm_id
        json_object['data'] = self.data
        return json_object
