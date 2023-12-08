class Transaction:
    def __init__(self, size, position_in_the_block, fee, type, from_address, to, nonce_or_validation_hash, hash):
        self._size = size
        self._position_in_the_block = position_in_the_block
        self._fee = fee
        self._type = type
        self._from = from_address
        self._to = to
        self._nonce_or_validation_hash = nonce_or_validation_hash
        self._hash = hash

    @property
    def size(self):
        return self._size

    @property
    def position_in_the_block(self):
        return self._position_in_the_block

    @property
    def fee(self):
        return self._fee

    @property
    def type(self):
        return self._type

    @property
    def from_address(self):
        return self._from

    @property
    def to(self):
        return self._to

    @property
    def nonce_or_validation_hash(self):
        return self._nonce_or_validation_hash

    @property
    def hash(self):
        return self._hash
