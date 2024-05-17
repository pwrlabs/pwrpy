from src.pwrpy.models.Transaction import Transaction


class TransactionForGuardianApproval:
    def __init__(self, valid: bool, guardian_address: str, error_message: str, transaction: Transaction):
        self._valid = valid
        self._error_message = error_message
        self._transaction = transaction
        self._guardian_address = guardian_address

    @property
    def valid(self) -> bool:
        return self._valid

    @property
    def error_message(self) -> str:
        return self._error_message

    @property
    def transaction(self) -> Transaction:
        return self._transaction

    @property
    def guardian_address(self) -> str:
        return self._guardian_address


class ApiResponse:
    def __init__(self, success, message, data=None):
        self.success = success
        self.message = message
        self.data = data
