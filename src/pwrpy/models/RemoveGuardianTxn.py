from pwrpy.models.Transaction import Transaction


class RemoveGuardianTxn(Transaction):

    @classmethod
    def from_json(cls, json_data):
        instance = super().from_json(json_data)
        return instance
