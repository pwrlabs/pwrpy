import struct
from typing import Union
from pathlib import Path
import sha3
from pwrpy.Utils.Falcon import Falcon
from pwrpy.TransactionBuilder import TransactionBuilder
from pwrpy.pwrsdk import PWRPY

class Falcon512Wallet:
    def __init__(
            self,
            public_key: bytes = None,
            private_key: bytes = None,
            address: bytes = None,
            pwrpy: PWRPY = None
        ):
        self.public_key = public_key
        self.private_key = private_key
        self.address = address

        if pwrpy is None:
            self.pwrpy = PWRPY()
        else:
            self.pwrpy = pwrpy

    @classmethod
    def new(cls) -> 'Falcon512Wallet':
        # Assuming Falcon class exists in Python
        public_key, private_key = Falcon.generate_keypair_512()
        
        # Get the hash of the public key
        hash_bytes = cls.__hash224(public_key)
        address = hash_bytes[:20]

        return cls(
            public_key=public_key,
            private_key=private_key,
            address=address
        )

    @classmethod
    def from_keys(cls, public_key: bytes, private_key: bytes) -> 'Falcon512Wallet':
        # Get the hash of the public key
        hash_bytes = cls.__hash224(public_key)
        address = hash_bytes[:20]

        return cls(
            public_key=public_key,
            private_key=private_key,
            address=address
        )

    def store_wallet(self, file_path: Union[str, Path]) -> None:
        buffer = bytearray()

        # Add public key length and data
        buffer.extend(struct.pack('>I', len(self.public_key)))
        buffer.extend(self.public_key)
        
        # Add private key length and data
        buffer.extend(struct.pack('>I', len(self.private_key)))
        buffer.extend(self.private_key)
    
        with open(file_path, 'wb') as f:
            f.write(buffer)
    
    @classmethod
    def load_wallet(cls, file_path: Union[str, Path]) -> 'Falcon512Wallet':
        with open(file_path, 'rb') as f:
            data = f.read()
        
        if len(data) < 8:  # At minimum we need two 4-byte length fields
            raise ValueError(f"File too small: {len(data)} bytes")
    
        cursor = 0
        
        # Read public key length
        pub_length = struct.unpack('>I', data[cursor:cursor+4])[0]
        cursor += 4
        
        if pub_length == 0 or pub_length > 2048:
            raise ValueError(f"Invalid public key length: {pub_length}")
        
        if cursor + pub_length > len(data):
            raise ValueError(f"File too small for public key of length {pub_length}")
        
        # Read public key
        public_key_bytes = data[cursor:cursor+pub_length]
        cursor += pub_length
        
        if cursor + 4 > len(data):
            raise ValueError("File too small for private key length")
        
        # Read private key length
        sec_length = struct.unpack('>I', data[cursor:cursor+4])[0]
        cursor += 4
        
        if sec_length == 0 or sec_length > 4096:
            raise ValueError(f"Invalid private key length: {sec_length}")
        
        if cursor + sec_length > len(data):
            raise ValueError(f"File too small for private key of length {sec_length}")
        
        # Read private key
        private_key_bytes = data[cursor:cursor+sec_length]
        
        try:
            public_key = public_key_bytes
        except Exception as e:
            raise ValueError(f"Failed to parse public key: {e}")
        
        try:
            private_key = private_key_bytes
        except Exception as e:
            raise ValueError(f"Failed to parse private key: {e}")
        
        return cls.from_keys(public_key, private_key)
    
    def sign(self, message: bytes) -> bytes:
        signature = Falcon.sign_512(message, self.private_key)
        return signature
    
    def verify(self, message: bytes, signature: bytes) -> bool:
        verified = Falcon.verify_512(message, signature, self.public_key)
        return verified

    def get_address(self) -> str:
        return f"0x{self.address.hex()}"

    def get_public_key(self) -> bytes:
        return self.public_key

    def get_private_key(self) -> bytes:
        return self.private_key
    
    def get_balance(self):
        return self.pwrpy.get_balance_of_address(self.get_address())

    def get_nonce(self):
        return self.pwrpy.get_nonce_of_address(self.get_address())
    
    def set_public_key(self, public_key: bytes, fee_per_byte = None, nonce = None):
        if nonce is None:
            nonce = self.get_nonce()
        if fee_per_byte is None:
            fee_per_byte = self.pwrpy.get_fee_per_byte()
        
        tx = TransactionBuilder.get_falcon_set_public_key_transaction(
            public_key, nonce, self.pwrpy.get_chainId(), self.get_address(), fee_per_byte
        )
        signature = self.get_signed_transaction(tx)
        return self.pwrpy.broadcast_transaction(signature)
    
    def join_as_validator(self, ip: str, fee_per_byte = None, nonce = None):
        if nonce is None:
            nonce = self.get_nonce()
        if fee_per_byte is None:
            fee_per_byte = self.pwrpy.get_fee_per_byte()

        response = self.__make_sure_public_key_is_set(fee_per_byte, nonce)
        if response != None and response.success == False: return response
        
        tx = TransactionBuilder.get_falcon_join_as_validator_transaction(
            ip, nonce, self.pwrpy.get_chainId(), self.get_address(), fee_per_byte
        )
        signature = self.get_signed_transaction(tx)
        return self.pwrpy.broadcast_transaction(signature)
    
    def delegate(self, validator: str, pwr_amount, fee_per_byte = None, nonce = None):
        if nonce is None:
            nonce = self.get_nonce()
        if fee_per_byte is None:
            fee_per_byte = self.pwrpy.get_fee_per_byte()

        response = self.__make_sure_public_key_is_set(fee_per_byte, nonce)
        if response != None and response.success == False: return response
        
        tx = TransactionBuilder.get_falcon_delegate_transaction(
            validator, pwr_amount, nonce, self.pwrpy.get_chainId(), self.get_address(), fee_per_byte
        )
        signature = self.get_signed_transaction(tx)
        return self.pwrpy.broadcast_transaction(signature)

    def change_ip(self, new_ip: str, fee_per_byte = None, nonce = None):
        if nonce is None:
            nonce = self.get_nonce()
        if fee_per_byte is None:
            fee_per_byte = self.pwrpy.get_fee_per_byte()

        response = self.__make_sure_public_key_is_set(fee_per_byte, nonce)
        if response != None and response.success == False: return response
        
        tx = TransactionBuilder.get_falcon_change_ip_transaction(
            new_ip, nonce, self.pwrpy.get_chainId(), self.get_address(), fee_per_byte
        )
        signature = self.get_signed_transaction(tx)
        return self.pwrpy.broadcast_transaction(signature)
    
    def claim_active_node_spot(self, fee_per_byte = None, nonce = None):
        if nonce is None:
            nonce = self.get_nonce()
        if fee_per_byte is None:
            fee_per_byte = self.pwrpy.get_fee_per_byte()

        response = self.__make_sure_public_key_is_set(fee_per_byte, nonce)
        if response != None and response.success == False: return response
        
        tx = TransactionBuilder.get_falcon_claim_active_node_spot_transaction(
            nonce, self.pwrpy.get_chainId(), self.get_address(), fee_per_byte
        )
        signature = self.get_signed_transaction(tx)
        return self.pwrpy.broadcast_transaction(signature)

    def transfer_pwr(self, to, amount, fee_per_byte = None, nonce = None): 
        if nonce is None:
            nonce = self.get_nonce()
        if fee_per_byte is None:
            fee_per_byte = self.pwrpy.get_fee_per_byte()

        response = self.__make_sure_public_key_is_set(fee_per_byte, nonce)
        if response != None and response.success == False: return response

        tx = TransactionBuilder.get_falcon_transfer_pwr_transaction(
            to, amount, nonce, self.pwrpy.get_chainId(), self.get_address(), fee_per_byte
        )
        signature = self.get_signed_transaction(tx)
        return self.pwrpy.broadcast_transaction(signature)
    
    def send_vm_data(self, vm_id, data, fee_per_byte = None, nonce = None):
        if nonce is None:
            nonce = self.get_nonce()
        if fee_per_byte is None:
            fee_per_byte = self.pwrpy.get_fee_per_byte()

        response = self.__make_sure_public_key_is_set(fee_per_byte, nonce)
        if response != None and response.success == False: return response

        tx = TransactionBuilder.get_falcon_vm_data_transaction(
            vm_id, data, nonce, self.pwrpy.get_chainId(), self.get_address(), fee_per_byte
        )
        signature = self.get_signed_transaction(tx)
        return self.pwrpy.broadcast_transaction(signature)
    
    def __make_sure_public_key_is_set(self, fee_per_byte, nonce):
        if self.get_nonce() == 0:
            return self.set_public_key(self.get_public_key(), fee_per_byte, nonce)
        else:
            return None

    
    def get_signed_transaction(self, transaction: bytes) -> bytes | None:
        if transaction is None:
            return None
        signature = self.sign(transaction)

        signature_len_bytes = len(signature).to_bytes(2, byteorder='big')

        final_txn = bytearray()
        final_txn.extend(transaction)
        final_txn.extend(signature_len_bytes)
        final_txn.extend(signature)
        return bytes(final_txn)

    @staticmethod
    def __hash224(input_bytes: bytes) -> bytes:
        k = sha3.keccak_224()
        k.update(input_bytes)
        return k.digest()
