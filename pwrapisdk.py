import os
import requests
import json
from binascii import hexlify

from models.Block import Block
from models.Transactions import Transaction

__PRC_NODE_URL = os.environ.get("PRC_NODE_URL")


class ApiResponse:
    def __init__(self, success, message, data=None):
        self.success = success
        self.message = message
        self.data = data


def getRpcNodeUrl():
    return __PRC_NODE_URL


def getFeePerByte():
    return 100


def broadcast_txn(txn):
    try:
        url = __PRC_NODE_URL + "/broadcast/"
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


def get_nonce_of_address(address):
    try:
        url = __PRC_NODE_URL + "/nonceOfUser/?userAddress=" + address
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


def getBalanceOfAddress(address):
    try:
        url = __PRC_NODE_URL + "/balanceOf/?userAddress=" + address
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


def getBlocksCount():
    try:
        url = __PRC_NODE_URL + "/blocksCount/"
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


def getBlockByNumber(block_number):
    try:
        response = requests.get(
            f"{__PRC_NODE_URL}/block/?blockNumber={block_number}")

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


def getLatestBlockNumber():
    response = getBlocksCount()
    if not response.success:
        return ApiResponse(False, response.get("message"))

    return ApiResponse(True, None, response.data - 1)
