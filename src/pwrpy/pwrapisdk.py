import os
import requests
import json
from binascii import hexlify

from pwrpy.models.Block import Block
from pwrpy.models.Transactions import Transaction
from pwrpy.models.Validator import Validator

if os.environ.get("PRC_NODE_URL") is None:
    raise RuntimeError("Please set the PRC_NODE_URL environment variable")


class ApiResponse:
    def __init__(self, success, message, data=None):
        self.success = success
        self.message = message
        self.data = data


class PWRPY:
    # Replace with the actual RPC node URL
    __rpc_node_url = None
    __fee_per_byte = 100

    def __init__(self, rpc_node_url) -> None:
        self.__rpc_node_url = rpc_node_url

    def get_rpc_node_url(self):
        return self.__rpc_node_url

    def get_fee_per_byte(self):
        return self.__fee_per_byte

    def broadcast_txn(self, txn):
        try:
            url = self.get_rpc_node_url() + "/broadcast/"
            headers = {
                "Accept": "application/json",
                "Content-type": "application/json"
            }
            payload = json.dumps({"txn": hexlify(txn).decode()})

            responseRaw = requests.post(url, data=payload, headers=headers)

            response = responseRaw.json()
            is_ok = responseRaw.status_code == 200

            return ApiResponse(is_ok, response.get("message"))

        except Exception as e:
            return ApiResponse(False, str(e))

    def get_nonce_of_address(self, address):
        try:
            url = self.get_rpc_node_url() + "/nonceOfUser/?userAddress=" + address
            headers = {
                "Accept": "application/json",
                "Content-type": "application/json"
            }

            responseRaw = requests.get(url, headers=headers)

            response = responseRaw.json()

            if responseRaw.status_code != 200:
                return ApiResponse(False, response.get("message"))
            else:
                return ApiResponse(True, response.get("message"), response.get("nonce"))

        except Exception as e:
            return ApiResponse(False, str(e))

    def get_balance_of_address(self, address):
        try:
            url = self.get_rpc_node_url() + "/balanceOf/?userAddress=" + address
            headers = {
                "Accept": "application/json",
                "Content-type": "application/json"
            }

            responseRaw = requests.get(url, headers=headers)

            response = responseRaw.json()

            if responseRaw.status_code != 200:
                return ApiResponse(False, response.get("message"))
            else:
                return ApiResponse(True, response.get("message"), response.get("balance"))

        except Exception as e:
            return ApiResponse(False, str(e))

    def get_blocks_count(self):
        try:
            url = self.get_rpc_node_url() + "/blocksCount/"
            headers = {
                "Accept": "application/json",
                "Content-type": "application/json"
            }

            responseRaw = requests.get(url, headers=headers)

            response = responseRaw.json()

            if responseRaw.status_code != 200:
                return ApiResponse(False, response.get("message"))
            else:
                return ApiResponse(True, response.get("message"), response.get("blocksCount"))

        except Exception as e:
            return ApiResponse(False, str(e))

    def get_block_by_number(self, block_number):
        try:
            url = self.get_rpc_node_url()
            response = requests.get(
                f"{url}/block/?blockNumber={block_number}")

            if response.status_code == 200:
                json_data = response.json().get('block')
                # Assuming the Block constructor takes the JSON data directly

                block_instance = Block(
                    transaction_count=json_data['transactionCount'],
                    size=json_data['blockSize'],
                    number=json_data['blockNumber'],
                    reward=json_data['blockReward'],
                    timestamp=json_data['timestamp'],
                    hash=json_data['blockHash'],
                    submitter=json_data['blockSubmitter'],
                    success=json_data['success'],
                    transactions=[Transaction(size=txn['size'], hash=txn['hash'], fee=txn['fee'], from_address=txn['from'], to=txn['to'],
                                              nonce_or_validation_hash=txn['nonceOrValidationHash'], position_in_the_block=txn['positionInTheBlock'], type=txn['type']) for txn in json_data['transactions']]
                )

                return block_instance
            elif response.status_code == 400:
                error_data = response.json()
                raise RuntimeError(f"Failed with HTTP error 400 and message: {
                                   error_data.get('message')}")
            else:
                raise RuntimeError(f"Failed with HTTP error code : {
                                   response.status_code}")

        except requests.HTTPError as http_err:
            raise RuntimeError(f"HTTP error occurred: {http_err}")
        except Exception as err:
            raise RuntimeError(f"An error occurred: {err}")

    def get_total_validators_count(self):
        try:
            url = self.get_rpc_node_url() + "/totalValidatorsCount/"
            headers = {
                "Accept": "application/json",
                "Content-type": "application/json"
            }

            responseRaw = requests.get(url, headers=headers)

            response = responseRaw.json()

            if responseRaw.status_code != 200:
                return ApiResponse(False, response.get("message"))
            else:
                return ApiResponse(True, response.get("message"), response.get("validatorsCount"))

        except Exception as e:
            return ApiResponse(False, str(e))

    def get_standby_validators_count(self):
        try:
            url = self.get_rpc_node_url() + "/standbyValidatorsCount/"
            headers = {
                "Accept": "application/json",
                "Content-type": "application/json"
            }

            responseRaw = requests.get(url, headers=headers)

            response = responseRaw.json()

            if responseRaw.status_code != 200:
                return ApiResponse(False, response.get("message"))
            else:
                return ApiResponse(True, response.get("message"), response.get("validatorsCount"))

        except Exception as e:
            return ApiResponse(False, str(e))

    def get_active_validators_count(self):
        try:
            url = self.get_rpc_node_url() + "/activeValidatorsCount/"
            headers = {
                "Accept": "application/json",
                "Content-type": "application/json"
            }

            responseRaw = requests.get(url, headers=headers)

            response = responseRaw.json()

            if responseRaw.status_code != 200:
                return ApiResponse(False, response.get("message"))
            else:
                return ApiResponse(True, response.get("message"), response.get("validatorsCount"))

        except Exception as e:
            return ApiResponse(False, str(e))

    def get_all_validators(self):
        try:
            response = requests.get(
                self.get_rpc_node_url() + "/allValidators/")

            if response.status_code == 200:
                data = response.json()
                validators = data['validators']
                validators_list = []

                for validator_data in validators:
                    # Assuming Validator is a class you have defined elsewhere
                    validator = Validator(
                        "0x" + validator_data.get("address"),
                        validator_data.get("ip"),
                        validator_data.get("badActor"),
                        validator_data.get("votingPower"),
                        validator_data.get("totalShares"),
                        validator_data.get("delegatorsCount"),
                        validator_data.get("status")
                    )
                    validators_list.append(validator)

                return validators_list
            else:
                return ApiResponse(False, response.get("message"))

        except Exception as e:
            return ApiResponse(False, str(e))

    def get_standby_validators(self):
        try:
            url = self.get_rpc_node_url()
            response = requests.get(url + "/standbyValidators/")

            if response.status_code == 200:
                data = response.json()
                validators = data['validators']
                validators_list = []

                for validator_data in validators:
                    # Assuming Validator is a class you have defined elsewhere
                    validator = Validator(
                        "0x" + validator_data.get("address"),
                        validator_data.get("ip"),
                        validator_data.get("badActor"),
                        validator_data.get("votingPower"),
                        validator_data.get("totalShares"),
                        validator_data.get("delegatorsCount"),
                        validator_data.get("status")
                    )
                    validators_list.append(validator)

                return validators_list
            else:
                return ApiResponse(False, response.get("message"))

        except Exception as e:
            return ApiResponse(False, str(e))

    def get_active_validators(self):
        try:
            url = self.get_rpc_node_url()
            response = requests.get(
                url + "/activeValidators/")

            if response.status_code == 200:
                data = response.json()
                validators = data['validators']
                validators_list = []

                for validator_data in validators:
                    # Assuming Validator is a class you have defined elsewhere
                    validator = Validator(
                        "0x" + validator_data.get("address"),
                        validator_data.get("ip"),
                        validator_data.get("badActor"),
                        validator_data.get("votingPower"),
                        validator_data.get("totalShares"),
                        validator_data.get("delegatorsCount"),
                        validator_data.get("status")
                    )
                    validators_list.append(validator)

                return validators_list
            else:
                return ApiResponse(False, response.get("message"))

        except Exception as e:
            return ApiResponse(False, str(e))

    def get_owner_of_vm(self, vm_id):
        try:
            url = self.get_rpc_node_url()
            response = requests.get(
                f"{url}/ownerOfVmId/?vmId={vm_id}")

            if response.status_code == 200:
                data = response.json()
                return data["owner"]
            else:
                return ApiResponse(False, response.get("message"))

        except Exception as e:
            return ApiResponse(False, str(e))

    def update_fee_per_byte(self):
        try:
            url = self.get_rpc_node_url()
            response = requests.get(f"{url}/feePerByte/")

            if response.status_code == 200:
                data = response.json()
                self.__fee_per_byte = data["feePerByte"]
                return self.__fee_per_byte
            else:
                return ApiResponse(False, response.get("message"))

        except Exception as e:
            return ApiResponse(False, str(e))

    def get_latest_block_number(self):
        response = self.get_blocks_count()
        if not response.success:
            return ApiResponse(False, response.get("message"))

        return ApiResponse(True, None, response.data - 1)
