import json

import json

class Transaction:
    def __init__(self, size: int, block_number: int, position_in_the_block: int, fee: int, type: int, sender: str,
                 receiver: str, nonce: int, hash: str, timestamp: int, value: int):
        self._size = size
        self._block_number = block_number
        self._position_in_the_block = position_in_the_block
        self._fee = fee
        self._type = type
        self._sender = sender
        self._receiver = receiver
        self._nonce = nonce
        self._hash = hash
        self._timestamp = timestamp
        self._value = value

    @classmethod
    def from_json(cls, json_data):
        size = json_data.get('size', 0)
        block_number = json_data.get('blockNumber', 0)
        position_in_the_block = json_data.get('positionInTheBlock', 0)
        fee = json_data.get('fee', 0)
        _type = json_data.get('type', 'unknown')
        sender = json_data.get('sender', '0x')
        receiver = json_data.get('receiver', '0x')
        nonce = json_data.get('nonce', 0)
        _hash = json_data.get('hash', '0x')
        timestamp = json_data.get("timestamp", 0)
        value = json_data.get('value', 0)
        return cls(size, block_number, position_in_the_block, fee, _type, sender, receiver, nonce, _hash, timestamp,
                   value)

    @property
    def size(self):
        return self._size

    @size.setter
    def size(self, value):
        self._size = value

    @property
    def position_in_the_block(self):
        return self._position_in_the_block

    @position_in_the_block.setter
    def position_in_the_block(self, value):
        self._position_in_the_block = value

    @property
    def fee(self):
        return self._fee

    @fee.setter
    def fee(self, value):
        self._fee = value

    @property
    def type(self):
        return self._type

    @type.setter
    def type(self, value):
        self._type = value

    @property
    def sender(self):
        return self._sender

    @sender.setter
    def sender(self, value):
        self._sender = value

    @property
    def receiver(self):
        return self._receiver

    @receiver.setter
    def receiver(self, value):
        self._receiver = value

    @property
    def nonce(self):
        return self._nonce

    @nonce.setter
    def nonce(self, value):
        self._nonce = value

    @property
    def hash(self):
        return self._hash

    @hash.setter
    def hash(self, value):
        self._hash = value

    @property
    def block_number(self):
        return self._block_number

    @block_number.setter
    def block_number(self, value):
        self._block_number = value

    @property
    def timestamp(self):
        return self._timestamp

    @timestamp.setter
    def timestamp(self, value):
        self._timestamp = value

    @property
    def value(self):
        return self._value

    @value.setter
    def value(self, value):
        self._value = value

    def to_json(self):
        json_object = {
            "size": self.size,
            "positionInTheBlock": self.position_in_the_block,
            "fee": self.fee,
            "type": self.type,
            "sender": self.sender,
            "receiver": self.receiver,
            "nonce": self.nonce,
            "hash": self.hash,
            "blockNumber": self.block_number,
            "timestamp": self.timestamp,
            "value": self.value
        }
        return json_object
