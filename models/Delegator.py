class Delegator:
    def __init__(self, address, validator_address, shares, delegated_pwr):
        self._address = address
        self._validator_address = validator_address
        self._shares = shares
        self._delegated_pwr = delegated_pwr

    @property
    def address(self):
        return self._address

    @property
    def validator_address(self):
        return self._validator_address

    @property
    def shares(self):
        return self._shares

    @property
    def delegated_pwr(self):
        return self._delegated_pwr
