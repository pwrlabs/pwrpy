from typing import Union, List
import sha3
from pwrpy.Utils.Falcon import Falcon
from pwrpy.TransactionBuilder import TransactionBuilder
from pwrpy.pwrsdk import PWRPY
from Crypto.Hash import keccak
from pwrpy.Utils.AES256 import AES256
import hashlib
import os
from mnemonic import Mnemonic

falcon_server_url = "http://localhost:3000"

class Wallet:
    def __init__(
            self,
            public_key: bytes = None,
            private_key: bytes = None,
            address: bytes = None,
            seed_phrase: bytes = None,
            pwrpy: PWRPY = None
        ):
        self.public_key = public_key
        self.private_key = private_key
        self.address = address
        self.seed_phrase = seed_phrase

        if pwrpy is None:
            self.pwrpy = PWRPY("https://pwrrpc.pwrlabs.io/")
        else:
            self.pwrpy = pwrpy

    @classmethod
    def new_random(cls, word_count: int, pwrpy: PWRPY = PWRPY("https://pwrrpc.pwrlabs.io/")) -> 'Wallet':
        # Map word count to entropy bytes
        if word_count == 12:
            entropy_bytes = 16  # 128 bits
        elif word_count == 15:
            entropy_bytes = 20  # 160 bits 
        elif word_count == 18:
            entropy_bytes = 24  # 192 bits
        elif word_count == 21:
            entropy_bytes = 28  # 224 bits
        elif word_count == 24:
            entropy_bytes = 32  # 256 bits
        else:
            raise ValueError(f"Invalid word count: {word_count}. Must be 12, 15, 18, 21, or 24")

        # Generate random entropy
        try:
            entropy = os.urandom(entropy_bytes)
        except Exception as e:
            raise RuntimeError(f"Failed to generate entropy: {str(e)}")

        # Generate mnemonic from entropy
        try:
            mnemo = Mnemonic("english")
            mnemonic = mnemo.to_mnemonic(entropy)
        except Exception as e:
            raise RuntimeError(f"Failed to generate mnemonic: {str(e)}")

        # Generate seed from mnemonic
        seed = cls.__generate_seed(mnemonic.encode('utf-8'), "")

        # Generate key pair from seed
        try:
            public_key, private_key = Falcon.generate_keypair_512_from_seed(seed)
        except Exception as e:
            raise RuntimeError(f"Failed to generate key pair: {str(e)}")

        hash_bytes = cls.__hash224(public_key[1:])
        address = hash_bytes[:20]

        return cls(
            public_key=public_key,
            private_key=private_key,
            address=address,
            seed_phrase=mnemonic.encode('utf-8'),
            pwrpy=pwrpy
        )

    @classmethod
    def new(cls, seed_phrase: str, pwrpy: PWRPY = PWRPY("https://pwrrpc.pwrlabs.io/")) -> 'Wallet':
        seed_phrase_bytes = seed_phrase.encode('utf-8')
        seed = cls.__generate_seed(seed_phrase_bytes, "")
        public_key, private_key = Falcon.generate_keypair_512_from_seed(seed)

        # Get the hash of the public key
        hash_bytes = cls.__hash224(public_key[1:])
        address = hash_bytes[:20]

        return cls(
            public_key=public_key,
            private_key=private_key,
            address=address,
            seed_phrase=seed_phrase_bytes,
            pwrpy=pwrpy
        )

    def store_wallet(self, path: str, password: str) -> None:
        try:
            # Convert seed phrase to bytes if it's a string
            seed_phrase_bytes = self.seed_phrase.encode('utf-8') if isinstance(self.seed_phrase, str) else self.seed_phrase
            encrypted_seed_phrase = AES256.encrypt(seed_phrase_bytes, password)

            with open(path, 'wb') as f:
                f.write(encrypted_seed_phrase)
        except Exception as e:
            raise Exception(f"Failed to store wallet: {str(e)}")
        
    @staticmethod
    def load_wallet(path: str, password: str, pwrpy: PWRPY = None) -> 'Wallet':
        try:
            with open(path, 'rb') as f:
                encrypted_seed_phrase = f.read()
            
            seed_phrase_bytes = AES256.decrypt(encrypted_seed_phrase, password)
            seed_phrase = seed_phrase_bytes.decode('utf-8')
            
            return Wallet.new(seed_phrase, pwrpy)
        except Exception as e:
            print(f"Error loading wallet: {e}")
            return None
    
    def sign(self, message: bytes) -> bytes:
        signature = Falcon.sign_512(message, self.private_key)
        return signature
    
    def verify(self, message: bytes, signature: bytes) -> bool:
        verified = Falcon.verify_512(message, signature, self.public_key)
        return verified

    def get_address(self) -> str:
        return f"0x{self.address.hex()}"
    
    def get_seed_phrase(self) -> str:
        return self.seed_phrase.decode('utf-8')

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

        tx = TransactionBuilder.get_set_public_key_transaction(
            public_key, nonce, self.pwrpy.get_chainId(), self.get_address(), fee_per_byte
        )
        signature = self.get_signed_transaction(tx)
        return self.pwrpy.broadcast_transaction(signature)
    
    def join_as_validator(self, ip: str, fee_per_byte = None, nonce = None):
        response = self.__make_sure_public_key_is_set(fee_per_byte)
        if response != None and response.success == False: return response

        if nonce is None:
            nonce = self.get_nonce()
        if fee_per_byte is None:
            fee_per_byte = self.pwrpy.get_fee_per_byte()

        tx = TransactionBuilder.get_join_as_validator_transaction(
            ip, nonce, self.pwrpy.get_chainId(), self.get_address(), fee_per_byte
        )
        signature = self.get_signed_transaction(tx)
        return self.pwrpy.broadcast_transaction(signature)
    
    def delegate(self, validator: str, pwr_amount, fee_per_byte = None, nonce = None):
        response = self.__make_sure_public_key_is_set(fee_per_byte)
        if response != None and response.success == False: return response

        if nonce is None:
            nonce = self.get_nonce()
        if fee_per_byte is None:
            fee_per_byte = self.pwrpy.get_fee_per_byte()

        tx = TransactionBuilder.get_delegate_transaction(
            validator, pwr_amount, nonce, self.pwrpy.get_chainId(), self.get_address(), fee_per_byte
        )
        signature = self.get_signed_transaction(tx)
        return self.pwrpy.broadcast_transaction(signature)

    def propose_change_ip(self, new_ip: str, fee_per_byte = None, nonce = None):
        response = self.__make_sure_public_key_is_set(fee_per_byte)
        if response != None and response.success == False: return response

        if nonce is None:
            nonce = self.get_nonce()
        if fee_per_byte is None:
            fee_per_byte = self.pwrpy.get_fee_per_byte()

        tx = TransactionBuilder.get_change_ip_transaction(
            new_ip, nonce, self.pwrpy.get_chainId(), self.get_address(), fee_per_byte
        )
        signature = self.get_signed_transaction(tx)
        return self.pwrpy.broadcast_transaction(signature)
    
    def claim_active_node_spot(self, fee_per_byte = None, nonce = None):
        response = self.__make_sure_public_key_is_set(fee_per_byte)
        if response != None and response.success == False: return response

        if nonce is None:
            nonce = self.get_nonce()
        if fee_per_byte is None:
            fee_per_byte = self.pwrpy.get_fee_per_byte()

        tx = TransactionBuilder.get_claim_active_node_spot_transaction(
            nonce, self.pwrpy.get_chainId(), self.get_address(), fee_per_byte
        )
        signature = self.get_signed_transaction(tx)
        return self.pwrpy.broadcast_transaction(signature)

    def transfer_pwr(self, to, amount, fee_per_byte = None, nonce = None):
        response = self.__make_sure_public_key_is_set(fee_per_byte)
        if response != None and response.success == False: return response

        if nonce is None:
            nonce = self.get_nonce()
        if fee_per_byte is None:
            fee_per_byte = self.pwrpy.get_fee_per_byte()

        tx = TransactionBuilder.get_transfer_pwr_transaction(
            to, amount, nonce, self.pwrpy.get_chainId(), self.get_address(), fee_per_byte
        )
        signature = self.get_signed_transaction(tx)
        return self.pwrpy.broadcast_transaction(signature)
    
    # Governance Proposal Transactions
    def propose_change_early_withdraw_penalty(self, title: str, description: str, early_withdrawal_time: int, 
                                             withdrawal_penalty: int, fee_per_byte = None, nonce = None):
        response = self.__make_sure_public_key_is_set(fee_per_byte)
        if response != None and response.success == False: return response

        if nonce is None:
            nonce = self.get_nonce()
        if fee_per_byte is None:
            fee_per_byte = self.pwrpy.get_fee_per_byte()

        tx = TransactionBuilder.get_change_early_withdraw_penalty_proposal_transaction(
            title, description, early_withdrawal_time, withdrawal_penalty, nonce, 
            self.pwrpy.get_chainId(), self.get_address(), fee_per_byte
        )
        signature = self.get_signed_transaction(tx)
        return self.pwrpy.broadcast_transaction(signature)

    def propose_change_fee_per_byte(self, title: str, description: str, new_fee_per_byte: int, 
                                   fee_per_byte = None, nonce = None):
        response = self.__make_sure_public_key_is_set(fee_per_byte)
        if response != None and response.success == False: return response

        if nonce is None:
            nonce = self.get_nonce()
        if fee_per_byte is None:
            fee_per_byte = self.pwrpy.get_fee_per_byte()

        tx = TransactionBuilder.get_change_fee_per_byte_proposal_transaction(
            title, description, new_fee_per_byte, nonce, self.pwrpy.get_chainId(), 
            self.get_address(), fee_per_byte
        )
        signature = self.get_signed_transaction(tx)
        return self.pwrpy.broadcast_transaction(signature)

    def propose_change_max_block_size(self, title: str, description: str, max_block_size: int, 
                                     fee_per_byte = None, nonce = None):
        response = self.__make_sure_public_key_is_set(fee_per_byte)
        if response != None and response.success == False: return response

        if nonce is None:
            nonce = self.get_nonce()
        if fee_per_byte is None:
            fee_per_byte = self.pwrpy.get_fee_per_byte()

        tx = TransactionBuilder.get_change_max_block_size_proposal_transaction(
            title, description, max_block_size, nonce, self.pwrpy.get_chainId(), 
            self.get_address(), fee_per_byte
        )
        signature = self.get_signed_transaction(tx)
        return self.pwrpy.broadcast_transaction(signature)

    def propose_change_max_txn_size(self, title: str, description: str, max_txn_size: int, 
                                   fee_per_byte = None, nonce = None):
        response = self.__make_sure_public_key_is_set(fee_per_byte)
        if response != None and response.success == False: return response

        if nonce is None:
            nonce = self.get_nonce()
        if fee_per_byte is None:
            fee_per_byte = self.pwrpy.get_fee_per_byte()

        tx = TransactionBuilder.get_change_max_txn_size_proposal_transaction(
            title, description, max_txn_size, nonce, self.pwrpy.get_chainId(), 
            self.get_address(), fee_per_byte
        )
        signature = self.get_signed_transaction(tx)
        return self.pwrpy.broadcast_transaction(signature)

    def propose_change_overall_burn_percentage(self, title: str, description: str, burn_percentage: int, 
                                              fee_per_byte = None, nonce = None):
        response = self.__make_sure_public_key_is_set(fee_per_byte)
        if response != None and response.success == False: return response

        if nonce is None:
            nonce = self.get_nonce()
        if fee_per_byte is None:
            fee_per_byte = self.pwrpy.get_fee_per_byte()

        tx = TransactionBuilder.get_change_overall_burn_percentage_proposal_transaction(
            title, description, burn_percentage, nonce, self.pwrpy.get_chainId(), 
            self.get_address(), fee_per_byte
        )
        signature = self.get_signed_transaction(tx)
        return self.pwrpy.broadcast_transaction(signature)

    def propose_change_reward_per_year(self, title: str, description: str, reward_per_year: int, 
                                      fee_per_byte = None, nonce = None):
        response = self.__make_sure_public_key_is_set(fee_per_byte)
        if response != None and response.success == False: return response

        if nonce is None:
            nonce = self.get_nonce()
        if fee_per_byte is None:
            fee_per_byte = self.pwrpy.get_fee_per_byte()

        tx = TransactionBuilder.get_change_reward_per_year_proposal_transaction(
            title, description, reward_per_year, nonce, self.pwrpy.get_chainId(), 
            self.get_address(), fee_per_byte
        )
        signature = self.get_signed_transaction(tx)
        return self.pwrpy.broadcast_transaction(signature)

    def propose_change_validator_count_limit(self, title: str, description: str, validator_count_limit: int, 
                                           fee_per_byte = None, nonce = None):
        response = self.__make_sure_public_key_is_set(fee_per_byte)
        if response != None and response.success == False: return response

        if nonce is None:
            nonce = self.get_nonce()
        if fee_per_byte is None:
            fee_per_byte = self.pwrpy.get_fee_per_byte()

        tx = TransactionBuilder.get_change_validator_count_limit_proposal_transaction(
            title, description, validator_count_limit, nonce, self.pwrpy.get_chainId(), 
            self.get_address(), fee_per_byte
        )
        signature = self.get_signed_transaction(tx)
        return self.pwrpy.broadcast_transaction(signature)

    def propose_change_validator_joining_fee(self, title: str, description: str, joining_fee: int, 
                                           fee_per_byte = None, nonce = None):
        response = self.__make_sure_public_key_is_set(fee_per_byte)
        if response != None and response.success == False: return response

        if nonce is None:
            nonce = self.get_nonce()
        if fee_per_byte is None:
            fee_per_byte = self.pwrpy.get_fee_per_byte()

        tx = TransactionBuilder.get_change_validator_joining_fee_proposal_transaction(
            title, description, joining_fee, nonce, self.pwrpy.get_chainId(), 
            self.get_address(), fee_per_byte
        )
        signature = self.get_signed_transaction(tx)
        return self.pwrpy.broadcast_transaction(signature)

    def propose_change_vida_id_claiming_fee(self, title: str, description: str, vida_id_claiming_fee: int, 
                                           fee_per_byte = None, nonce = None):
        response = self.__make_sure_public_key_is_set(fee_per_byte)
        if response != None and response.success == False: return response

        if nonce is None:
            nonce = self.get_nonce()
        if fee_per_byte is None:
            fee_per_byte = self.pwrpy.get_fee_per_byte()

        tx = TransactionBuilder.get_change_vida_id_claiming_fee_proposal_transaction(
            title, description, vida_id_claiming_fee, nonce, self.pwrpy.get_chainId(), 
            self.get_address(), fee_per_byte
        )
        signature = self.get_signed_transaction(tx)
        return self.pwrpy.broadcast_transaction(signature)

    def propose_change_vida_owner_txn_fee_share(self, title: str, description: str, vida_owner_txn_fee_share: int, 
                                             fee_per_byte = None, nonce = None):
        response = self.__make_sure_public_key_is_set(fee_per_byte)
        if response != None and response.success == False: return response

        if nonce is None:
            nonce = self.get_nonce()
        if fee_per_byte is None:
            fee_per_byte = self.pwrpy.get_fee_per_byte()

        tx = TransactionBuilder.get_change_vida_owner_txn_fee_share_proposal_transaction(
            title, description, vida_owner_txn_fee_share, nonce, self.pwrpy.get_chainId(), 
            self.get_address(), fee_per_byte
        )
        signature = self.get_signed_transaction(tx)
        return self.pwrpy.broadcast_transaction(signature)

    def propose_other(self, title: str, description: str, fee_per_byte = None, nonce = None):
        response = self.__make_sure_public_key_is_set(fee_per_byte)
        if response != None and response.success == False: return response

        if nonce is None:
            nonce = self.get_nonce()
        if fee_per_byte is None:
            fee_per_byte = self.pwrpy.get_fee_per_byte()

        tx = TransactionBuilder.get_other_proposal_transaction(
            title, description, nonce, self.pwrpy.get_chainId(), 
            self.get_address(), fee_per_byte
        )
        signature = self.get_signed_transaction(tx)
        return self.pwrpy.broadcast_transaction(signature)

    def vote_on_proposal(self, proposal_hash: str, vote: int, fee_per_byte = None, nonce = None):
        response = self.__make_sure_public_key_is_set(fee_per_byte)
        if response != None and response.success == False: return response

        if nonce is None:
            nonce = self.get_nonce()
        if fee_per_byte is None:
            fee_per_byte = self.pwrpy.get_fee_per_byte()

        tx = TransactionBuilder.get_vote_on_proposal_transaction(
            proposal_hash, vote, nonce, self.pwrpy.get_chainId(), 
            self.get_address(), fee_per_byte
        )
        signature = self.get_signed_transaction(tx)
        return self.pwrpy.broadcast_transaction(signature)

    # Guardian Transactions
    def guardian_approval(self, wrapped_txns: List[bytes], fee_per_byte = None, nonce = None):
        response = self.__make_sure_public_key_is_set(fee_per_byte)
        if response != None and response.success == False: return response

        if nonce is None:
            nonce = self.get_nonce()
        if fee_per_byte is None:
            fee_per_byte = self.pwrpy.get_fee_per_byte()

        tx = TransactionBuilder.get_guardian_approval_transaction(
            wrapped_txns, nonce, self.pwrpy.get_chainId(), 
            self.get_address(), fee_per_byte
        )
        signature = self.get_signed_transaction(tx)
        return self.pwrpy.broadcast_transaction(signature)

    def remove_guardian(self, fee_per_byte = None, nonce = None):
        response = self.__make_sure_public_key_is_set(fee_per_byte)
        if response != None and response.success == False: return response

        if nonce is None:
            nonce = self.get_nonce()
        if fee_per_byte is None:
            fee_per_byte = self.pwrpy.get_fee_per_byte()

        tx = TransactionBuilder.get_remove_guardian_transaction(
            nonce, self.pwrpy.get_chainId(), self.get_address(), fee_per_byte
        )
        signature = self.get_signed_transaction(tx)
        return self.pwrpy.broadcast_transaction(signature)

    def set_guardian(self, expiry_date: int, guardian_address: str, fee_per_byte = None, nonce = None):
        response = self.__make_sure_public_key_is_set(fee_per_byte)
        if response != None and response.success == False: return response

        if nonce is None:
            nonce = self.get_nonce()
        if fee_per_byte is None:
            fee_per_byte = self.pwrpy.get_fee_per_byte()

        tx = TransactionBuilder.get_set_guardian_transaction(
            expiry_date, guardian_address, nonce, self.pwrpy.get_chainId(), 
            self.get_address(), fee_per_byte
        )
        signature = self.get_signed_transaction(tx)
        return self.pwrpy.broadcast_transaction(signature)

    # Staking Transactions
    def move_stake(self, shares_amount: int, from_validator: str, to_validator: str, 
                  fee_per_byte = None, nonce = None):
        response = self.__make_sure_public_key_is_set(fee_per_byte)
        if response != None and response.success == False: return response

        if nonce is None:
            nonce = self.get_nonce()
        if fee_per_byte is None:
            fee_per_byte = self.pwrpy.get_fee_per_byte()

        tx = TransactionBuilder.get_move_stake_transaction(
            shares_amount, from_validator, to_validator, nonce, self.pwrpy.get_chainId(), 
            self.get_address(), fee_per_byte
        )
        signature = self.get_signed_transaction(tx)
        return self.pwrpy.broadcast_transaction(signature)

    def remove_validator(self, validator_address: str, fee_per_byte = None, nonce = None):
        response = self.__make_sure_public_key_is_set(fee_per_byte)
        if response != None and response.success == False: return response

        if nonce is None:
            nonce = self.get_nonce()
        if fee_per_byte is None:
            fee_per_byte = self.pwrpy.get_fee_per_byte()

        tx = TransactionBuilder.get_remove_validator_transaction(
            validator_address, nonce, self.pwrpy.get_chainId(), 
            self.get_address(), fee_per_byte
        )
        signature = self.get_signed_transaction(tx)
        return self.pwrpy.broadcast_transaction(signature)

    def withdraw(self, shares_amount: int, validator: str, fee_per_byte = None, nonce = None):
        response = self.__make_sure_public_key_is_set(fee_per_byte)
        if response != None and response.success == False: return response

        if nonce is None:
            nonce = self.get_nonce()
        if fee_per_byte is None:
            fee_per_byte = self.pwrpy.get_fee_per_byte()

        tx = TransactionBuilder.get_withdraw_transaction(
            shares_amount, validator, nonce, self.pwrpy.get_chainId(), 
            self.get_address(), fee_per_byte
        )
        signature = self.get_signed_transaction(tx)
        return self.pwrpy.broadcast_transaction(signature)

    # VIDA Transactions
    def claim_vida_id(self, vida_id: int, fee_per_byte = None, nonce = None):
        response = self.__make_sure_public_key_is_set(fee_per_byte)
        if response != None and response.success == False: return response

        if nonce is None:
            nonce = self.get_nonce()
        if fee_per_byte is None:
            fee_per_byte = self.pwrpy.get_fee_per_byte()

        tx = TransactionBuilder.get_claim_vida_id_transaction(
            vida_id, nonce, self.pwrpy.get_chainId(), 
            self.get_address(), fee_per_byte
        )
        signature = self.get_signed_transaction(tx)
        return self.pwrpy.broadcast_transaction(signature)

    def conduit_approval(self, vida_id: int, wrapped_txns: List[bytes], fee_per_byte = None, nonce = None):
        response = self.__make_sure_public_key_is_set(fee_per_byte)
        if response != None and response.success == False: return response

        if nonce is None:
            nonce = self.get_nonce()
        if fee_per_byte is None:
            fee_per_byte = self.pwrpy.get_fee_per_byte()

        tx = TransactionBuilder.get_conduit_approval_transaction(
            vida_id, wrapped_txns, nonce, self.pwrpy.get_chainId(), 
            self.get_address(), fee_per_byte
        )
        signature = self.get_signed_transaction(tx)
        return self.pwrpy.broadcast_transaction(signature)

    def send_payable_vida_data(self, vida_id: int, data: bytes, value: int, fee_per_byte = None, nonce = None):
        response = self.__make_sure_public_key_is_set(fee_per_byte)
        if response != None and response.success == False: return response

        if nonce is None:
            nonce = self.get_nonce()
        if fee_per_byte is None:
            fee_per_byte = self.pwrpy.get_fee_per_byte()

        tx = TransactionBuilder.get_payable_vida_data_transaction(
            vida_id, data, value, nonce, self.pwrpy.get_chainId(), 
            self.get_address(), fee_per_byte
        )
        signature = self.get_signed_transaction(tx)
        return self.pwrpy.broadcast_transaction(signature)
    
    def send_vida_data(self, vida_id: int, data: bytes, fee_per_byte = None, nonce = None):
        return self.send_payable_vida_data(vida_id, data, 0, fee_per_byte, nonce)

    def remove_conduits(self, vida_id: int, conduits: List[str], fee_per_byte = None, nonce = None):
        response = self.__make_sure_public_key_is_set(fee_per_byte)
        if response != None and response.success == False: return response

        if nonce is None:
            nonce = self.get_nonce()
        if fee_per_byte is None:
            fee_per_byte = self.pwrpy.get_fee_per_byte()

        tx = TransactionBuilder.get_remove_conduits_transaction(
            vida_id, conduits, nonce, self.pwrpy.get_chainId(), 
            self.get_address(), fee_per_byte
        )
        signature = self.get_signed_transaction(tx)
        return self.pwrpy.broadcast_transaction(signature)

    def set_conduit_mode(self, vida_id: int, mode: int, conduit_threshold: int, conduits: List[str], 
                        fee_per_byte = None, nonce = None):
        response = self.__make_sure_public_key_is_set(fee_per_byte)
        if response != None and response.success == False: return response

        if nonce is None:
            nonce = self.get_nonce()
        if fee_per_byte is None:
            fee_per_byte = self.pwrpy.get_fee_per_byte()

        tx = TransactionBuilder.get_set_conduit_mode_transaction(
            vida_id, mode, conduit_threshold, conduits, nonce, self.pwrpy.get_chainId(), 
            self.get_address(), fee_per_byte
        )
        signature = self.get_signed_transaction(tx)
        return self.pwrpy.broadcast_transaction(signature)

    def set_vida_private_state(self, vida_id: int, private_state: bool, fee_per_byte = None, nonce = None):
        response = self.__make_sure_public_key_is_set(fee_per_byte)
        if response != None and response.success == False: return response

        if nonce is None:
            nonce = self.get_nonce()
        if fee_per_byte is None:
            fee_per_byte = self.pwrpy.get_fee_per_byte()

        tx = TransactionBuilder.get_set_vida_private_state_transaction(
            vida_id, private_state, nonce, self.pwrpy.get_chainId(), 
            self.get_address(), fee_per_byte
        )
        signature = self.get_signed_transaction(tx)
        return self.pwrpy.broadcast_transaction(signature)

    def set_vida_to_absolute_public(self, vida_id: int, fee_per_byte = None, nonce = None):
        response = self.__make_sure_public_key_is_set(fee_per_byte)
        if response != None and response.success == False: return response

        if nonce is None:
            nonce = self.get_nonce()
        if fee_per_byte is None:
            fee_per_byte = self.pwrpy.get_fee_per_byte()

        tx = TransactionBuilder.get_set_vida_to_absolute_public_transaction(
            vida_id, nonce, self.pwrpy.get_chainId(), 
            self.get_address(), fee_per_byte
        )
        signature = self.get_signed_transaction(tx)
        return self.pwrpy.broadcast_transaction(signature)

    def add_vida_sponsored_addresses(self, vida_id: int, sponsored_addresses: List[str], 
                                   fee_per_byte = None, nonce = None):
        response = self.__make_sure_public_key_is_set(fee_per_byte)
        if response != None and response.success == False: return response

        if nonce is None:
            nonce = self.get_nonce()
        if fee_per_byte is None:
            fee_per_byte = self.pwrpy.get_fee_per_byte()

        tx = TransactionBuilder.get_add_vida_sponsored_addresses_transaction(
            vida_id, sponsored_addresses, nonce, self.pwrpy.get_chainId(), 
            self.get_address(), fee_per_byte
        )
        signature = self.get_signed_transaction(tx)
        return self.pwrpy.broadcast_transaction(signature)

    def add_vida_allowed_senders(self, vida_id: int, allowed_senders: List[str], 
                               fee_per_byte = None, nonce = None):
        response = self.__make_sure_public_key_is_set(fee_per_byte)
        if response != None and response.success == False: return response

        if nonce is None:
            nonce = self.get_nonce()
        if fee_per_byte is None:
            fee_per_byte = self.pwrpy.get_fee_per_byte()

        tx = TransactionBuilder.get_add_vida_allowed_senders_transaction(
            vida_id, allowed_senders, nonce, self.pwrpy.get_chainId(), 
            self.get_address(), fee_per_byte
        )
        signature = self.get_signed_transaction(tx)
        return self.pwrpy.broadcast_transaction(signature)

    def remove_vida_allowed_senders(self, vida_id: int, allowed_senders: List[str], 
                                  fee_per_byte = None, nonce = None):
        response = self.__make_sure_public_key_is_set(fee_per_byte)
        if response != None and response.success == False: return response

        if nonce is None:
            nonce = self.get_nonce()
        if fee_per_byte is None:
            fee_per_byte = self.pwrpy.get_fee_per_byte()

        tx = TransactionBuilder.get_remove_vida_allowed_senders_transaction(
            vida_id, allowed_senders, nonce, self.pwrpy.get_chainId(), 
            self.get_address(), fee_per_byte
        )
        signature = self.get_signed_transaction(tx)
        return self.pwrpy.broadcast_transaction(signature)

    def remove_sponsored_addresses(self, vida_id: int, sponsored_addresses: List[str], 
                                 fee_per_byte = None, nonce = None):
        response = self.__make_sure_public_key_is_set(fee_per_byte)
        if response != None and response.success == False: return response

        if nonce is None:
            nonce = self.get_nonce()
        if fee_per_byte is None:
            fee_per_byte = self.pwrpy.get_fee_per_byte()

        tx = TransactionBuilder.get_remove_sponsored_addresses_transaction(
            vida_id, sponsored_addresses, nonce, self.pwrpy.get_chainId(), 
            self.get_address(), fee_per_byte
        )
        signature = self.get_signed_transaction(tx)
        return self.pwrpy.broadcast_transaction(signature)

    def set_pwr_transfer_rights(self, vida_id: int, owner_can_transfer_pwr: bool, 
                              fee_per_byte = None, nonce = None):
        response = self.__make_sure_public_key_is_set(fee_per_byte)
        if response != None and response.success == False: return response

        if nonce is None:
            nonce = self.get_nonce()
        if fee_per_byte is None:
            fee_per_byte = self.pwrpy.get_fee_per_byte()

        tx = TransactionBuilder.get_set_pwr_transfer_rights_transaction(
            vida_id, owner_can_transfer_pwr, nonce, self.pwrpy.get_chainId(), 
            self.get_address(), fee_per_byte
        )
        signature = self.get_signed_transaction(tx)
        return self.pwrpy.broadcast_transaction(signature)

    def transfer_pwr_from_vida(self, vida_id: int, receiver: str, amount: int, 
                             fee_per_byte = None, nonce = None):
        response = self.__make_sure_public_key_is_set(fee_per_byte)
        if response != None and response.success == False: return response

        if nonce is None:
            nonce = self.get_nonce()
        if fee_per_byte is None:
            fee_per_byte = self.pwrpy.get_fee_per_byte()

        tx = TransactionBuilder.get_transfer_pwr_from_vida_transaction(
            vida_id, receiver, amount, nonce, self.pwrpy.get_chainId(), 
            self.get_address(), fee_per_byte
        )
        signature = self.get_signed_transaction(tx)
        return self.pwrpy.broadcast_transaction(signature)
    
    def get_rpc(self):
        return self.pwrpy

    def __make_sure_public_key_is_set(self, fee_per_byte):
        nonce = self.get_nonce()
        if nonce == 0:
            return self.set_public_key(self.get_public_key(), fee_per_byte, nonce)
        else:
            return None


    def get_signed_transaction(self, transaction: bytes) -> bytes | None:
        if transaction is None:
            return None
        hasher = keccak.new(digest_bits=256)
        hasher.update(transaction)
        tx_hash = hasher.digest()

        signature = self.sign(tx_hash)
        signature_len_bytes = len(signature).to_bytes(2, byteorder='big')

        final_txn = bytearray()
        final_txn.extend(transaction)
        final_txn.extend(signature)
        final_txn.extend(signature_len_bytes)
        return bytes(final_txn)

    @staticmethod
    def __hash224(input_bytes: bytes) -> bytes:
        k = sha3.keccak_224()
        k.update(input_bytes)
        return k.digest()
    
    @staticmethod
    def __generate_seed(mnemonic: Union[bytes, bytearray], passphrase: str) -> bytes:
        """
        Generate a seed from a mnemonic phrase using PBKDF2.
        
        Args:
            mnemonic: The mnemonic phrase as bytes
            passphrase: The passphrase to use for seed generation
            
        Returns:
            bytes: The generated 64-byte seed
        """
        mnemonic_bytes = bytes(mnemonic)    
        salt = b"mnemonic" + passphrase.encode('utf-8')
        
        # Use PBKDF2 with SHA512
        # Parameters:
        # - mnemonic as the password
        # - "mnemonic" + passphrase as the salt
        # - 2048 iterations
        # - 64 bytes output (512 bits)
        return hashlib.pbkdf2_hmac(
            'sha512',
            mnemonic_bytes,
            salt,
            2048,
            64
        )
