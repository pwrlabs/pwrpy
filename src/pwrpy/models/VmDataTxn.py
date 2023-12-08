from src.pwrpy.models.Transactions import Transaction


class VmDataTxn(Transaction):
    def __init__(self, vm_id, data, **kwargs):
        super().__init__(**kwargs)
        self._vm_id = vm_id
        self._data = data

    @property
    def vm_id(self):
        return self._vm_id

    @property
    def data(self):
        return self._data
