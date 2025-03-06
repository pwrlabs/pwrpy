import json
import requests
from eth_hash.auto import keccak
from requests.exceptions import Timeout, RequestException
from binascii import hexlify
from typing import Callable

from pwrpy.models.Transaction import Transaction, GuardianApprovalTransaction
from pwrpy.models.Transaction import VmDataTransaction
from pwrpy.models.Block import Block
from pwrpy.models.Validator import Validator
from pwrpy.models.Response import ApiResponse, TransactionForGuardianApproval, EarlyWithdrawPenaltyResponse
from pwrpy.models.TxSubscription import VidaTransactionSubscription

def get_response(url: str, timeout):
    """
    Fetch a Response object from the given URL.

    Args:
        url (str): The URL to fetch the JSON object from.
        timeout (int): Timeout for the HTTP request in seconds. Default is 5 seconds.

    Returns:
        Response: The response object containing the HTTP response from the server.
    """
    try:
        headers = {
            "Accept": "application/json",
            "Content-type": "application/json"
        }
        response = requests.get(url, timeout=timeout, headers=headers)
        response.raise_for_status()
        return response
    except Timeout:
        print("Request timed out.")

    except RequestException as e:
        print("Request error:", e)

    except Exception as e:
        print("An unexpected error occurred:", e)


class PWRPY:
    so_timeout = 20
    connection_timeout = 20
    timeout = (connection_timeout, so_timeout)

    def __init__(self):
        self.__rpc_node_url = "https://pwrrpc.pwrlabs.io/"
        self.__chainId = b'-1'  # The chain ID is set to -1 until fetched from the rpc_node_url

    def get_chainId(self):
        if self.__chainId == b'-1':
            url = self.__rpc_node_url + "/chainId/"
            response = get_response(url, self.timeout)
            chainID = response.json()["chainId"].to_bytes(1, byteorder='big')
            return chainID

    def get_rpc_node_url(self):
        return self.__rpc_node_url

    def set_rpc_node_url(self, url):
        self.__rpc_node_url = url

    def get_fee_per_byte(self):
        url = self.get_rpc_node_url() + "/feePerByte/"
        response = get_response(url, self.timeout)
        data = response.json()
        fee = data.get('feePerByte')
        return fee

    def get_blockchain_version(self):
        url = f"{self.__rpc_node_url}/blockchainVersion/"
        response = get_response(url, self.timeout)
        data = response.json()
        version = data.get('blockchainVersion')
        return version

    def broadcast_transaction(self, txn):
        try:
            url = self.__rpc_node_url + "/broadcast/"
            data = {
                "txn": txn.hex()
            }

            headers = {
                "Accept": "application/json",
                "Content-Type": "application/json"
            }

            response = requests.post(url, json=data, headers=headers, timeout=(self.connection_timeout, self.so_timeout))

            if response.status_code == 200:
                txnHash = "0x" + keccak(txn).hex()
                return ApiResponse(True, None, bytes.fromhex(txnHash[2:]))
            elif response.status_code == 400:
                error_message = json.loads(response.text)["message"]
                return ApiResponse(False, error_message, None)
            else:
                raise RuntimeError("Failed with HTTP error code: " + str(response.status_code))

        except Exception as e:
            return ApiResponse(False, None, str(e))

    def get_nonce_of_address(self, address: str):
        try:
            url = self.get_rpc_node_url() + "/nonceOfUser/?userAddress=" + address
            responseRaw = get_response(url, self.timeout)
            response = responseRaw.json()

            if responseRaw.status_code != 200:
                return ApiResponse(False, response.get("message"))
            else:
                return ApiResponse(True, response.get("message"), response.get("nonce")).data

        except Exception as e:
            return ApiResponse(False, str(e))

    def get_balance_of_address(self, address: str):
        url = self.get_rpc_node_url() + "/balanceOf/?userAddress=" + address
        response = get_response(url, self.timeout)
        data = response.json()
        balance = data.get('balance') / (10 ** 9)
        return balance

    def get_guardian_of_address(self, address: str):
        url = f"{self.__rpc_node_url}/guardianOf/?userAddress={address}"
        response = get_response(url, self.timeout)
        data = response.json()
        if data.get('isGuarded'):
            return data.get('guardian')
        else:
            return None

    def get_blocks_count(self):
        url = self.get_rpc_node_url() + "/blocksCount/"
        response = get_response(url, self.timeout)
        data = response.json()
        return data.get('blocksCount')

    def get_block_by_number(self, block_number):
        url = f"{self.__rpc_node_url}/block/?blockNumber={block_number}"
        response = get_response(url, self.timeout)
        data = response.json()
        block = Block.from_json(data.get('block'))
        return block

    def get_total_validators_count(self):
        try:
            url = self.get_rpc_node_url() + "/totalValidatorsCount/"
            responseRaw = get_response(url, self.timeout)
            response = responseRaw.json()

            if responseRaw.status_code != 200:
                return response.get("message")
            else:
                return response.get("validatorsCount")

        except Exception as e:
            return str(e)

    def get_total_delegators_count(self):
        try:
            url = self.get_rpc_node_url() + "/totalDelegatorsCount/"
            responseRaw = get_response(url, self.timeout)
            response = responseRaw.json()

            if responseRaw.status_code != 200:
                return response.get("message")
            else:
                return response.get("validatorsCount")

        except Exception as e:
            return str(e)

    def get_standby_validators_count(self):
        try:
            url = self.get_rpc_node_url() + "/standbyValidatorsCount/"
            responseRaw = get_response(url, self.timeout)
            response = responseRaw.json()

            if responseRaw.status_code != 200:
                return response.get("message")
            else:
                return response.get("validatorsCount")

        except Exception as e:
            return str(e)

    def get_active_validators_count(self):
        try:
            url = self.get_rpc_node_url() + "/activeValidatorsCount/"
            responseRaw = requests.get(url)
            response = responseRaw.json()

            if responseRaw.status_code != 200:
                return response.get("message")
            else:
                return response.get("validatorsCount")

        except Exception as e:
            return str(e)

    def get_all_validators(self):
        try:
            url = self.get_rpc_node_url() + "/allValidators/"
            response = get_response(url, self.timeout)
            if response.status_code == 200:
                data = response.json()
                validators = data['validators']
                validators_list = []

                for validator_data in validators:
                    validator = Validator(
                        validator_data.get("address"),
                        validator_data.get("ip"),
                        validator_data.get("badActor", False),
                        validator_data.get("votingPower", 0),
                        validator_data.get("totalShares", 0),
                        validator_data.get("delegatorsCount", 0),
                        validator_data.get("status", 'unknown')
                    )
                    validators_list.append(validator)

                return validators_list
            else:
                return response.get("message")

        except Exception as e:
            return str(e)

    def get_standby_validators(self):
        try:
            url = self.get_rpc_node_url() + "/standbyValidators/"
            response = get_response(url, self.timeout)
            if response.status_code == 200:
                data = response.json()
                validators = data['validators']
                validators_list = []
                for validator_data in validators:
                    # Assuming Validator is a class you have defined elsewhere
                    validator = Validator(
                        validator_data.get("address"),
                        validator_data.get("ip"),
                        validator_data.get("badActor", False),
                        validator_data.get("votingPower", 0),
                        validator_data.get("totalShares", 0),
                        validator_data.get("delegatorsCount", 0),
                        validator_data.get("status", 'unknown')
                    )
                    validators_list.append(validator)
                return validators_list
            else:
                return response.get('message')

        except Exception as e:
            return str(e)

    def get_active_validators(self):
        try:
            url = self.get_rpc_node_url() + "/activeValidators/"
            response = get_response(url, self.timeout)

            if response.status_code == 200:
                data = response.json()
                validators = data['validators']
                validators_list = []

                for validator_data in validators:
                    # Assuming Validator is a class you have defined elsewhere
                    validator = Validator(
                        validator_data.get("address"),
                        validator_data.get("ip"),
                        validator_data.get("badActor", False),
                        validator_data.get("votingPower", 0),
                        validator_data.get("totalShares", 0),
                        validator_data.get("delegatorsCount", 0),
                        validator_data.get("status", 'unknown')
                    )
                    validators_list.append(validator)

                return validators_list
            else:
                return response.get("message")

        except Exception as e:
            return str(e)

    def get_owner_of_vm(self, vm_id):
        try:
            url = f"{self.__rpc_node_url}/ownerOfVmId/?vmId={vm_id}"
            response = get_response(url, self.timeout)

            if response.status_code == 200:
                data = response.json()
                if data.get("claimed", False):
                    return data["owner"]
                else:
                    return None
            else:
                return response.get("message")

        except Exception as e:
            return str(e)

    def get_latest_block_number(self):
        latest_block_number = self.get_blocks_count() - 1
        return latest_block_number

    def get_vm_data_txns(self, starting_block: int, ending_block: int, vm_id: int):
        url = f"{self.__rpc_node_url}/getVmTransactions/?startingBlock={starting_block}&endingBlock={ending_block}&vmId={vm_id}"
        response = get_response(url, self.timeout)
        if response.status_code == 200:
            data = response.json()
            vmDataTxn = data.get('transactions')
            txn_array = []
            for txn_object in vmDataTxn:
                txn = VmDataTransaction.from_json(
                    txn_object,
                    txn_object.get('blockNumber'),
                    txn_object.get('timestamp'),
                    txn_object.get('positionInBlock')
                )
                txn_array.append(txn)
            return txn_array

    def get_vm_data_txns_filter_by_byte_prefix(self, starting_block: int, ending_block: int, vm_id: int,
                                               prefix: bytearray):
        url = f"{self.get_rpc_node_url()}/getVmTransactionsSortByBytePrefix/?startingBlock={starting_block}&endingBlock={ending_block}&vmId={vm_id}&bytePrefix={hexlify(prefix).decode()}"
        response = get_response(url, self.timeout)

        if response.status_code == 200:
            data = response.json()
            vmDataTxn = data.get('transactions')
            txn_array = []
            for txn_object in vmDataTxn:
                txn = VmDataTransaction.from_json(
                    txn_object,
                    txn_object.get('blockNumber'),
                    txn_object.get('timestamp'),
                    txn_object.get('positionInBlock')
                )
                txn_array.append(txn)

            return txn_array
        else:
            return response.message

    def get_active_voting_power(self):
        url = f"{self.__rpc_node_url}/activeVotingPower/"
        response = get_response(url, self.timeout)
        data = response.json()
        return data.get('activeVotingPower')

    def get_delegatees(self, address: str):
        url = f"{self.__rpc_node_url}/delegateesOfUser/?userAddress={address}"
        response = get_response(url, self.timeout)
        data = response.json()
        print(data)
        validator_objects = data.get('validators')
        delegatees = []
        if validator_objects is None:
            return delegatees

        for validator_object in validator_objects:
            validator = Validator(
                address=validator_object.get('address'),
                ip=validator_object.get('ip'),
                bad_actor=validator_object.get('badActor'),
                voting_power=validator_object.get('votingPower'),
                shares=validator_object.get('totalShares'),
                delegators_count=validator_object.get('delegatorsCount'),
                status=validator_object.get('status')
            )
            delegatees.append(validator)
        return delegatees

    def get_validator(self, address: str):
        url = f"{self.__rpc_node_url}/validator/?validatorAddress={address}"
        response = get_response(url, self.timeout)
        data = response.json()
        validator_object = data.get('validator')
        validator = Validator(
            address=validator_object.get('address'),
            ip=validator_object.get('ip'),
            bad_actor=validator_object.get('badActor'),
            voting_power=validator_object.get('votingPower'),
            shares=validator_object.get('totalShares'),
            delegators_count=validator_object.get('delegatorsCount'),
            status=validator_object.get('status')
        )
        return validator

    def get_delegated_pwr(self, delegator_address: str, validator_address: str):
        url = f"{self.__rpc_node_url}/validator/delegator/delegatedPWROfAddress/?userAddress={delegator_address}&validatorAddress={validator_address}"
        response = get_response(url, self.timeout)
        data = response.json()
        return data.get('delegatedPWR')

    def get_share_value(self, validator_address: str):
        url = f"{self.__rpc_node_url}/validator/shareValue/?validatorAddress={validator_address}"
        response = get_response(url, self.timeout)
        data = response.json()
        return data.get('shareValue')

    @staticmethod
    def get_vm_id_address(vm_id):
        hex_address = "1" if vm_id >= 0 else "0"
        if vm_id < 0:
            vm_id = -vm_id
        vm_id_string = str(vm_id)
        hex_address += "0" * (39 - len(vm_id_string)) + vm_id_string
        return "0x" + hex_address

    @staticmethod
    def is_vm_address(address):
        if address is None or (len(address) != 40 and len(address) != 42):
            return False
        if address.startswith("0x"):
            address = address[2:]
        if not address.startswith("0") and not address.startswith("1"):
            return False
        negative = address.startswith("0")
        if not negative:
            address = address[1:]
        try:
            vm_id = int(address)
            if negative:
                vm_id = -vm_id
            if vm_id > 2 ** 63 - 1 or vm_id < -(2 ** 63):
                return False
        except ValueError:
            return False
        return True

    def is_transaction_valid_for_guardian_approval(self, transaction):
        if isinstance(transaction, (bytes, bytearray)):
            transaction = transaction.hex()
        url = f"{self.__rpc_node_url}/isTransactionValidForGuardianApproval/"
        data = {"transaction": transaction}
        response = requests.post(url, json=data)
        response_data = response.json()
        if response_data["valid"]:
            return TransactionForGuardianApproval(
                valid=True,
                guardian_address=response_data.get("guardian", "0x"),
                transaction=Transaction.from_json(response_data["transaction"], 0, 0, 0),
                error_message=None
            )
        else:
            return TransactionForGuardianApproval(
                valid=False,
                guardian_address=response_data.get("guardian", "0x"),
                transaction=None,
                error_message=response_data["error"]
            )

    def get_shares_of_delegator(self, delegator_address, validator_address):
        url = f"{self.__rpc_node_url}/validator/delegator/sharesOfAddress/?userAddress={delegator_address}&validatorAddress={validator_address}"
        response = requests.get(url)
        response_data = response.json()
        return response_data["shares"]

    def get_conduits_of_vm(self, vm_id):
        try:
            url = f"{self.__rpc_node_url}/conduitsOfVm/?vmId={vm_id}"
            response = requests.get(url)
            response_data = response.json()
            conduits = response_data["conduits"]
            return [Validator.from_json(conduit) for conduit in conduits]
        except Exception as e:
            print(e)
            return []

    def get_fee(self, txn):
        fee_per_byte = self.get_fee_per_byte()
        from pwrpy.TransactionDecoder import TransactionDecoder
        transaction = TransactionDecoder.decode(txn)

        if isinstance(transaction, GuardianApprovalTransaction):
            ecdsa_verification_fee = self.get_ecdsa_verification_fee()
            fee = (len(txn) * fee_per_byte) + ecdsa_verification_fee
            fee += len(transaction.get_transactions()) * ecdsa_verification_fee
            return fee
        else:
            ecdsa_verification_fee = self.get_ecdsa_verification_fee()
            return (len(txn) * fee_per_byte) + ecdsa_verification_fee

    def get_ecdsa_verification_fee(self):
        try:
            url = self.get_rpc_node_url() + "/ecdsaVerificationFee/"
            response = requests.get(url, timeout=(self.connection_timeout, self.so_timeout))

            if response.status_code == 200:
                return response.json()["ecdsaVerificationFee"]
            else:
                raise RuntimeError(
                    "Failed to get ECDSA verification fee with HTTP error code: " + str(response.status_code))
        except Exception as e:
            raise IOError(str(e))

    def get_max_block_size(self):
        try:
            url = self.get_rpc_node_url() + "/maxBlockSize/"
            response = requests.get(url, timeout=(self.connection_timeout, self.so_timeout))

            if response.status_code == 200:
                return response.json()["maxBlockSize"]
            else:
                raise RuntimeError("Failed to get max block size with HTTP error code: " + str(response.status_code))
        except Exception as e:
            raise IOError(str(e))

    def get_max_transaction_size(self):
        try:
            url = self.get_rpc_node_url() + "/maxTransactionSize/"
            response = requests.get(url, timeout=(self.connection_timeout, self.so_timeout))

            if response.status_code == 200:
                return response.json()["maxTransactionSize"]
            else:
                raise RuntimeError(
                    "Failed to get max transaction size with HTTP error code: " + str(response.status_code))
        except Exception as e:
            raise IOError(str(e))

    def get_validator_count_limit(self):
        try:
            url = self.get_rpc_node_url() + "/validatorCountLimit/"
            response = requests.get(url, timeout=(self.connection_timeout, self.so_timeout))

            if response.status_code == 200:
                return response.json()["validatorCountLimit"]
            else:
                raise RuntimeError(
                    "Failed to get validator count limit with HTTP error code: " + str(response.status_code))
        except Exception as e:
            raise IOError(str(e))

    def get_validator_slashing_fee(self):
        try:
            url = self.get_rpc_node_url() + "/validatorSlashingFee/"
            response = requests.get(url, timeout=(self.connection_timeout, self.so_timeout))

            if response.status_code == 200:
                return response.json()["validatorSlashingFee"]
            else:
                raise RuntimeError(
                    "Failed to get validator slashing fee with HTTP error code: " + str(response.status_code))
        except Exception as e:
            raise IOError(str(e))

    def get_vm_owner_transaction_fee_share(self):
        try:
            url = self.get_rpc_node_url() + "/vmOwnerTransactionFeeShare/"
            response = requests.get(url, timeout=(self.connection_timeout, self.so_timeout))

            if response.status_code == 200:
                return response.json()["vmOwnerTransactionFeeShare"]
            else:
                raise RuntimeError("Failed to get VM owner transaction fee share with HTTP error code: " + str(
                    response.status_code))
        except Exception as e:
            raise IOError(str(e))

    def get_burn_percentage(self):
        try:
            url = self.get_rpc_node_url() + "/burnPercentage/"
            response = requests.get(url, timeout=(self.connection_timeout, self.so_timeout))

            if response.status_code == 200:
                return response.json()["burnPercentage"]
            else:
                raise RuntimeError(
                    "Failed to get burn percentage with HTTP error code: " + str(response.status_code))
        except Exception as e:
            raise IOError(str(e))

    def get_validator_operational_fee(self):
        try:
            url = self.get_rpc_node_url() + "/validatorOperationalFee/"
            response = requests.get(url, timeout=(self.connection_timeout, self.so_timeout))

            if response.status_code == 200:
                return response.json()["validatorOperationalFee"]
            else:
                raise RuntimeError(
                    "Failed to get validator operational fee with HTTP error code: " + str(response.status_code))
        except Exception as e:
            raise IOError(str(e))

    def get_block_number(self):
        try:
            url = self.get_rpc_node_url() + "/blockNumber/"
            response = requests.get(url, timeout=(self.connection_timeout, self.so_timeout))

            if response.status_code == 200:
                return response.json()["blockNumber"]
            else:
                raise RuntimeError("Failed to get block number with HTTP error code: " + str(response.status_code))
        except Exception as e:
            raise IOError(str(e))

    def get_block_timestamp(self):
        try:
            url = self.get_rpc_node_url() + "/blockTimestamp/"
            response = requests.get(url, timeout=(self.connection_timeout, self.so_timeout))

            if response.status_code == 200:
                return response.json()["blockTimestamp"]
            else:
                raise RuntimeError(
                    "Failed to get block timestamp with HTTP error code: " + str(response.status_code))
        except Exception as e:
            raise IOError(str(e))

    def get_total_voting_power(self):
        try:
            url = self.get_rpc_node_url() + "/totalVotingPower/"
            response = requests.get(url, timeout=(self.connection_timeout, self.so_timeout))

            if response.status_code == 200:
                return response.json()["totalVotingPower"]
            else:
                raise RuntimeError(
                    "Failed to get total voting power with HTTP error code: " + str(response.status_code))
        except Exception as e:
            raise IOError(str(e))

    def get_pwr_rewards_per_year(self):
        try:
            url = self.get_rpc_node_url() + "/pwrRewardsPerYear/"
            response = requests.get(url, timeout=(self.connection_timeout, self.so_timeout))

            if response.status_code == 200:
                return response.json()["pwrRewardsPerYear"]
            else:
                raise RuntimeError(
                    "Failed to get PWR rewards per year with HTTP error code: " + str(response.status_code))
        except Exception as e:
            raise IOError(str(e))

    def get_withdrawal_lock_time(self):
        try:
            url = self.get_rpc_node_url() + "/withdrawalLockTime/"
            response = requests.get(url, timeout=(self.connection_timeout, self.so_timeout))

            if response.status_code == 200:
                return response.json()["withdrawalLockTime"]
            else:
                raise RuntimeError(
                    "Failed to get withdrawal lock time with HTTP error code: " + str(response.status_code))
        except Exception as e:
            raise IOError(str(e))

    def get_validator_joining_fee(self):
        try:
            url = self.get_rpc_node_url() + "/validatorJoiningFee/"
            response = requests.get(url, timeout=(self.connection_timeout, self.so_timeout))

            if response.status_code == 200:
                return response.json()["validatorJoiningFee"]
            else:
                raise RuntimeError(
                    "Failed to get validator joining fee with HTTP error code: " + str(response.status_code))
        except Exception as e:
            raise IOError(str(e))

    def get_max_guardian_time(self):
        try:
            url = self.get_rpc_node_url() + "/maxGuardianTime/"
            response = requests.get(url, timeout=(self.connection_timeout, self.so_timeout))

            if response.status_code == 200:
                return response.json()["maxGuardianTime"]
            else:
                raise RuntimeError(
                    "Failed to get max guardian time with HTTP error code: " + str(response.status_code))
        except Exception as e:
            raise IOError(str(e))

    def get_vm_id_claiming_fee(self):
        try:
            url = self.get_rpc_node_url() + "/vmIdClaimingFee/"
            response = requests.get(url, timeout=(self.connection_timeout, self.so_timeout))

            if response.status_code == 200:
                return response.json()["vmIdClaimingFee"]
            else:
                raise RuntimeError(
                    "Failed to get VM ID claiming fee with HTTP error code: " + str(response.status_code))
        except Exception as e:
            raise IOError(str(e))

    def get_proposal_fee(self):
        try:
            url = self.get_rpc_node_url() + "/proposalFee/"
            response = requests.get(url, timeout=(self.connection_timeout, self.so_timeout))

            if response.status_code == 200:
                return response.json()["proposalFee"]
            else:
                raise RuntimeError("Failed to get proposal fee with HTTP error code: " + str(response.status_code))
        except Exception as e:
            raise IOError(str(e))

    def get_proposal_validity_time(self):
        try:
            url = self.get_rpc_node_url() + "/proposalValidityTime/"
            response = requests.get(url, timeout=(self.connection_timeout, self.so_timeout))

            if response.status_code == 200:
                return response.json()["proposalValidityTime"]
            else:
                raise RuntimeError(
                    "Failed to get proposal validity time with HTTP error code: " + str(response.status_code))
        except Exception as e:
            raise IOError(str(e))

    def get_minimum_delegating_amount(self):
        try:
            url = self.get_rpc_node_url() + "/minimumDelegatingAmount/"
            response = requests.get(url, timeout=(self.connection_timeout, self.so_timeout))

            if response.status_code == 200:
                return response.json()["minimumDelegatingAmount"]
            else:
                raise RuntimeError(
                    "Failed to get minimum delegating amount with HTTP error code: " + str(response.status_code))
        except Exception as e:
            raise IOError(str(e))

    def get_early_withdraw_penalty(self, withdraw_time):
        url = f"{self.get_rpc_node_url()}/earlyWithdrawPenalty/?withdrawTime={withdraw_time}"
        response = requests.get(url).json()

        early_withdraw_available = response.get("earlyWithdrawAvailable", False)
        penalty = response.get("penalty", 0) if early_withdraw_available else 0

        return EarlyWithdrawPenaltyResponse(early_withdraw_available, penalty)

    def get_all_early_withdraw_penalties(self):
        url = f"{self.get_rpc_node_url()}/allEarlyWithdrawPenalties/"
        response = requests.get(url).json()

        penalties_obj = response.get("earlyWithdrawPenalties", {})
        penalties = {int(k): v for k, v in penalties_obj.items()}

        return penalties
    
    def subscribe_to_vida_transactions(
        self,
        vida_id: int,
        starting_block: int,
        handler: Callable[[VmDataTransaction], None],
        poll_interval: int = 100
    ) -> VidaTransactionSubscription:
        subscription = VidaTransactionSubscription(
            rpc=self,
            vida_id=vida_id,
            starting_block=starting_block,
            handler=handler,
            poll_interval=poll_interval
        )
        subscription.start()
        return subscription
    
