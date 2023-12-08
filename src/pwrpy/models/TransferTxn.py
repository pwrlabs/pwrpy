from pwrpy.models.Transactions import Transaction


class TransferTxn(Transaction):
    def __init__(self, value, **kwargs):
        super().__init__(**kwargs)
        self._value = value

    @property
    def value(self):
        return self._value
