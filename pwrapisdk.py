import os
import requests
import json
from binascii import hexlify

PRC_NODE_URL = os.environ.get("PRC_NODE_URL")


class Response:
    def __init__(self, success, message, data=None):
        self.success = success
        self.message = message
        self.data = data


def broadcast_txn(txn):
    try:
        url = PRC_NODE_URL + "/broadcast/"
        headers = {
            "Accept": "application/json",
            "Content-type": "application/json"
        }
        payload = json.dumps({"txn": hexlify(txn).decode()})

        responseRaw = requests.post(url, data=payload, headers=headers)

        response = responseRaw.json()

        if responseRaw.status_code != 200:
            return Response(False, response.get("message"))
        else:
            return Response(True, response.get("message"))

    except Exception as e:
        return Response(False, str(e))


def get_nonce(address):
    try:
        url = PRC_NODE_URL + "/nonceOfUser/?userAddress=" + address
        headers = {
            "Accept": "application/json",
            "Content-type": "application/json"
        }

        responseRaw = requests.get(url, headers=headers)

        response = responseRaw.json()

        if responseRaw.status_code != 200:
            return Response(False, response.get("message"))
        else:
            return Response(True, response.get("message"), response.get("nonce"))

    except Exception as e:
        return Response(False, str(e))
