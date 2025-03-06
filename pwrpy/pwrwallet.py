import eth_account
from pwrpy.signer import Signature
from pwrpy.TransactionBuilder import TransactionBuilder
from pwrpy.pwrsdk import PWRPY
from pwrpy.models.Response import ApiResponse
from pwrpy.Utils.AES256 import AES256

class PWRWallet:
    def __init__(self, private_key=None, pwrpy: PWRPY = None):
        if private_key is None:
            self.private_key = int.from_bytes(eth_account.Account.create().key, 'big')
        elif isinstance(private_key, str):
            if private_key.startswith("0x"):
                private_key = private_key[2:]
            self.private_key = int(private_key, 16)
        elif isinstance(private_key, bytes):
            self.private_key = int.from_bytes(private_key, 'big')
        elif isinstance(private_key, int):
            self.private_key = private_key
        else:
            raise ValueError("Invalid private key format")

        if pwrpy is None:
            self.pwrpy = PWRPY()
        else:
            self.pwrpy = pwrpy

    def get_address(self):
        return eth_account.Account.from_key(self.private_key).address

    def get_balance(self):
        return self.pwrpy.get_balance_of_address(self.get_address())

    def get_nonce(self):
        return self.pwrpy.get_nonce_of_address(self.get_address())

    def get_private_key(self):
        return self.private_key

    def get_signed_transaction(self, transaction):
        if transaction is None:
            return None
        signature = Signature.sign_message(private_key=self.get_private_key(),
                                           message=transaction)
        final_txn = bytearray(transaction)
        final_txn.extend(signature)

        return bytes(final_txn)

    def store_wallet(self, path: str, password: str) -> None:
        try:
            private_key_bytes = self.private_key.to_bytes(
                (self.private_key.bit_length() + 7) // 8, 
                byteorder='big'
            )
            encrypted_private_key = AES256.encrypt(private_key_bytes, password)
            
            with open(path, 'wb') as f:
                f.write(encrypted_private_key)
        except Exception as e:
            raise Exception(f"Failed to store wallet: {str(e)}")

    @staticmethod
    def load_wallet(path: str, password: str, pwrpy: PWRPY = None) -> 'PWRWallet':
        try:
            with open(path, 'rb') as f:
                encrypted_private_key = f.read()
            
            private_key_bytes = AES256.decrypt(encrypted_private_key, password)
            
            return PWRWallet(private_key_bytes, pwrpy)
        except Exception as e:
            print(f"Error loading wallet: {e}")
            return None

    def transfer_pwr(self, to, amount, nonce = None):
        if nonce is None:
            nonce = self.get_nonce()
        tx = TransactionBuilder.get_transfer_pwr_transaction(to, amount, nonce, self.pwrpy.get_chainId())
        signature = self.get_signed_transaction(tx)
        return self.pwrpy.broadcast_transaction(signature)

    def join(self, ip, nonce = None):
        if nonce is None:
            nonce = self.get_nonce()
        tx = TransactionBuilder.get_join_transaction(ip, nonce, self.pwrpy.get_chainId())
        signature = self.get_signed_transaction(tx)
        return self.pwrpy.broadcast_transaction(signature)

    def claim_active_node_spot(self, nonce = None):
        if nonce is None:
            nonce = self.get_nonce()
        tx = TransactionBuilder.get_claim_active_node_spot_transaction(nonce, self.pwrpy.get_chainId())
        signature = self.get_signed_transaction(tx)
        return self.pwrpy.broadcast_transaction(signature)

    def delegate(self, validator, amount, nonce = None):
        if nonce is None:
            nonce = self.get_nonce()
        tx = TransactionBuilder.get_delegate_transaction(validator, amount, nonce, self.pwrpy.get_chainId())
        signature = self.get_signed_transaction(tx)
        return self.pwrpy.broadcast_transaction(signature)

    def withdraw(self, validator, shares_amount, nonce = None):
        if nonce is None:
            nonce = self.get_nonce()
        tx = TransactionBuilder.get_withdraw_transaction(validator, shares_amount, nonce, self.pwrpy.get_chainId())
        signature = self.get_signed_transaction(tx)
        return self.pwrpy.broadcast_transaction(signature)

    def send_vm_data_transaction(self, vm_id, data, nonce = None):
        if nonce is None:
            nonce = self.get_nonce()
        tx = TransactionBuilder.get_vm_data_transaction(vm_id, data, nonce, self.pwrpy.get_chainId())
        signature = self.get_signed_transaction(tx)
        return self.pwrpy.broadcast_transaction(signature)

    def claim_vm_id(self, vm_id, nonce = None):
        if nonce is None:
            nonce = self.get_nonce()
        tx = TransactionBuilder.get_claim_vm_id_transaction(vm_id, nonce, self.pwrpy.get_chainId())
        signature = self.get_signed_transaction(tx)
        return self.pwrpy.broadcast_transaction(signature)

    def set_guardian(self, guardian, expiry_date, nonce = None):
        if nonce is None:
            nonce = self.get_nonce()
        tx = TransactionBuilder.get_set_guardian_transaction(guardian, expiry_date, nonce, self.pwrpy.get_chainId())
        signature = self.get_signed_transaction(tx)
        return self.pwrpy.broadcast_transaction(signature)

    def remove_guardian(self, nonce = None):
        if nonce is None:
            nonce = self.get_nonce()
        tx = TransactionBuilder.get_remove_guardian_transaction(nonce, self.pwrpy.get_chainId())
        signature = self.get_signed_transaction(tx)
        return self.pwrpy.broadcast_transaction(signature)

    def send_guardian_approval_transaction(self, transactions, nonce = None):
        if nonce is None:
            nonce = self.get_nonce()
        tx = TransactionBuilder.get_guardian_approval_transaction(transactions, nonce, self.pwrpy.get_chainId())
        signature = self.get_signed_transaction(tx)
        return self.pwrpy.broadcast_transaction(signature)

    def send_payable_vm_data_transaction(self, vm_id, value, data, nonce = None):
        if nonce is None:
            nonce = self.get_nonce()
        tx = TransactionBuilder.get_payable_vm_data_transaction(vm_id, value, data, nonce, self.pwrpy.get_chainId())
        signature = self.get_signed_transaction(tx)
        try:
            return self.pwrpy.broadcast_transaction(signature)
        except Exception as e:
            return ApiResponse(success=False, data=None, message=str(e))

    def get_signed_validator_remove_transaction(self, validator, nonce):
        return self.get_signed_transaction(
            TransactionBuilder.get_validator_remove_transaction(validator, nonce, self.pwrpy.get_chainId()))

    def send_validator_remove_transaction(self, validator, nonce = None):
        if nonce is None:
            nonce = self.get_nonce()
        return self.pwrpy.broadcast_transaction(self.get_signed_validator_remove_transaction(validator, nonce))

    def get_signed_conduit_approval_transaction(self, vm_id, transactions, nonce):
        return self.get_signed_transaction(
            TransactionBuilder.get_conduit_approval_transaction(vm_id, transactions, nonce,
                                                                self.pwrpy.get_chainId()))

    def conduit_approve(self, vm_id, transactions, nonce = None):
        if nonce is None:
            nonce = self.get_nonce()
        return self.pwrpy.broadcast_transaction(
            self.get_signed_conduit_approval_transaction(vm_id, transactions, nonce))

    def get_signed_set_conduit_transaction(self, vm_id, conduits, nonce):
        return self.get_signed_transaction(
            TransactionBuilder.get_set_conduits_transaction(vm_id, conduits, nonce, self.pwrpy.get_chainId()))

    def set_conduits(self, vm_id, conduits, nonce = None):
        if nonce is None:
            nonce = self.get_nonce()
        return self.pwrpy.broadcast_transaction(self.get_signed_set_conduit_transaction(vm_id, conduits, nonce))

    def get_signed_move_stake_transaction(self, shares_amount, from_validator, to_validator, nonce):
        return self.get_signed_transaction(
            TransactionBuilder.get_move_stake_transaction(shares_amount, from_validator, to_validator, nonce,
                                                          self.pwrpy.get_chainId()))

    def move_stake(self, shares_amount, from_validator, to_validator, nonce = None):
        if nonce is None:
            nonce = self.get_nonce()
        return self.pwrpy.broadcast_transaction(
            self.get_signed_move_stake_transaction(shares_amount, from_validator, to_validator, nonce))

    ### Governance Update
    def get_signed_change_early_withdraw_penalty_proposal_txn(self, withdrawal_penalty_time, withdrawal_penalty, title,
                                                              description, nonce):
        return self.get_signed_transaction(
            TransactionBuilder.get_change_early_withdraw_penalty_proposal_txn(withdrawal_penalty_time,
                                                                              withdrawal_penalty, title, description,
                                                                              nonce, self.pwrpy.get_chainId()))

    def create_proposal_change_early_withdrawal_penalty(self, withdrawal_penalty_time, withdrawal_penalty, title,
                                                        description, nonce = None):
        if nonce is None:
            nonce = self.get_nonce()
        return self.pwrpy.broadcast_transaction(
            self.get_signed_change_early_withdraw_penalty_proposal_txn(withdrawal_penalty_time, withdrawal_penalty,
                                                                       title, description, nonce))

    def get_signed_change_fee_per_byte_proposal_txn(self, fee_per_byte, title, description, nonce):
        return self.get_signed_transaction(
            TransactionBuilder.get_change_fee_per_byte_proposal_txn(fee_per_byte, title, description, nonce,
                                                                    self.pwrpy.get_chainId()))

    def create_proposal_change_fee_per_byte(self, fee_per_byte, title, description, nonce = None):
        if nonce is None:
            nonce = self.get_nonce()
        return self.pwrpy.broadcast_transaction(
            self.get_signed_change_fee_per_byte_proposal_txn(fee_per_byte, title, description, nonce))

    def get_signed_change_max_block_size_proposal_txn(self, max_block_size, title, description, nonce):
        return self.get_signed_transaction(
            TransactionBuilder.get_change_max_block_size_proposal_txn(max_block_size, title, description, nonce,
                                                                      self.pwrpy.get_chainId()))

    def create_proposal_change_max_block_size(self, max_block_size, title, description, nonce = None):
        if nonce is None:
            nonce = self.get_nonce()
        return self.pwrpy.broadcast_transaction(
            self.get_signed_change_max_block_size_proposal_txn(max_block_size, title, description, nonce))

    def get_signed_change_max_txn_size_proposal_txn(self, max_txn_size, title, description, nonce):
        return self.get_signed_transaction(
            TransactionBuilder.get_change_max_txn_size_proposal_txn(max_txn_size, title, description, nonce,
                                                                    self.pwrpy.get_chainId()))

    def create_proposal_change_max_txn_size(self, max_txn_size, title, description, nonce = None):
        if nonce is None:
            nonce = self.get_nonce()
        return self.pwrpy.broadcast_transaction(
            self.get_signed_change_max_txn_size_proposal_txn(max_txn_size, title, description, nonce))

    def get_signed_change_overall_burn_percentage_proposal_txn(self, burn_percentage, title, description, nonce):
        return self.get_signed_transaction(
            TransactionBuilder.get_change_overall_burn_percentage_proposal_txn(burn_percentage, title, description,
                                                                               nonce, self.pwrpy.get_chainId()))

    def create_proposal_change_overall_burn_percentage(self, burn_percentage, title, description, nonce = None):
        if nonce is None:
            nonce = self.get_nonce()
        return self.pwrpy.broadcast_transaction(
            self.get_signed_change_overall_burn_percentage_proposal_txn(burn_percentage, title, description, nonce))

    def get_signed_change_reward_per_year_proposal_txn(self, reward_per_year, title, description, nonce):
        return self.get_signed_transaction(
            TransactionBuilder.get_change_reward_per_year_proposal_txn(reward_per_year, title, description, nonce,
                                                                       self.pwrpy.get_chainId()))

    def create_proposal_change_reward_per_year(self, reward_per_year, title, description, nonce = None):
        if nonce is None:
            nonce = self.get_nonce()
        return self.pwrpy.broadcast_transaction(
            self.get_signed_change_reward_per_year_proposal_txn(reward_per_year, title, description, nonce))

    def get_signed_change_validator_count_limit_proposal_txn(self, validator_count_limit, title, description, nonce):
        return self.get_signed_transaction(
            TransactionBuilder.get_change_validator_count_limit_proposal_txn(validator_count_limit, title, description,
                                                                             nonce, self.pwrpy.get_chainId()))

    def create_proposal_change_validator_count_limit(self, validator_count_limit, title, description, nonce = None):
        if nonce is None:
            nonce = self.get_nonce()
        return self.pwrpy.broadcast_transaction(
            self.get_signed_change_validator_count_limit_proposal_txn(validator_count_limit, title, description, nonce))

    def get_signed_change_validator_joining_fee_proposal_txn(self, joining_fee, title, description, nonce):
        return self.get_signed_transaction(
            TransactionBuilder.get_change_validator_joining_fee_proposal_txn(joining_fee, title, description, nonce,
                                                                             self.pwrpy.get_chainId()))

    def create_proposal_change_validator_joining_fee(self, joining_fee, title, description, nonce = None):
        if nonce is None:
            nonce = self.get_nonce()
        return self.pwrpy.broadcast_transaction(
            self.get_signed_change_validator_joining_fee_proposal_txn(joining_fee, title, description, nonce))

    def get_signed_change_vm_id_claiming_fee_proposal_txn(self, claiming_fee, title, description, nonce):
        return self.get_signed_transaction(
            TransactionBuilder.get_change_vm_id_claiming_fee_proposal_txn(claiming_fee, title, description, nonce,
                                                                          self.pwrpy.get_chainId()))

    def create_proposal_change_vm_id_claiming_fee(self, claiming_fee, title, description, nonce = None):
        if nonce is None:
            nonce = self.get_nonce()
        return self.pwrpy.broadcast_transaction(
            self.get_signed_change_vm_id_claiming_fee_proposal_txn(claiming_fee, title, description, nonce))

    def get_signed_change_vm_owner_txn_fee_share_proposal_txn(self, fee_share, title, description, nonce):
        return self.get_signed_transaction(
            TransactionBuilder.get_change_vm_owner_txn_fee_share_proposal_txn(fee_share, title, description, nonce,
                                                                              self.pwrpy.get_chainId()))

    def create_proposal_change_vm_owner_txn_fee_share(self, fee_share, title, description, nonce = None):
        if nonce is None:
            nonce = self.get_nonce()
        return self.pwrpy.broadcast_transaction(
            self.get_signed_change_vm_owner_txn_fee_share_proposal_txn(fee_share, title, description, nonce))

    def get_signed_other_proposal_txn(self, title, description, nonce):
        return self.get_signed_transaction(
            TransactionBuilder.get_other_proposal_txn(title, description, nonce, self.pwrpy.get_chainId()))

    def create_proposal_other_proposal(self, title, description, nonce = None):
        if nonce is None:
            nonce = self.get_nonce()
        return self.pwrpy.broadcast_transaction(self.get_signed_other_proposal_txn(title, description, nonce))

    def get_signed_vote_on_proposal_txn(self, proposal_hash, vote, nonce):
        return self.get_signed_transaction(
            TransactionBuilder.get_vote_on_proposal_txn(proposal_hash, vote, nonce, self.pwrpy.get_chainId()))

    def vote_on_proposal(self, proposal_hash, vote, nonce = None):
        if nonce is None:
            nonce = self.get_nonce()
        return self.pwrpy.broadcast_transaction(self.get_signed_vote_on_proposal_txn(proposal_hash, vote, nonce))
