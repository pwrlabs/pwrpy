from pwrpy.models.Transaction import Transaction

class SetGuardianTxn(Transaction):

    @classmethod
    def from_json(cls, json_data):
        instance = super().from_json(json_data)
        guardian = json_data.get('guardian', '0x')
        expiry_date = json_data.get('expiryDate', 0)
        instance._guardian = guardian
        instance._expiry_date = expiry_date
        return instance

    @property
    def guardian(self):
        return self._guardian

    @property
    def expiry_date(self):
        return self._expiry_date

    def to_json(self):
        json_object = super().to_json()
        json_object['guardian'] = self.guardian
        json_object['expiryDate'] = self.expiry_date
        return json_object
