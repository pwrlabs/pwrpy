import os
import requests
import json
from binascii import hexlify

PRC_NODE_URL = os.environ.get("PRC_NODE_URL")


class Response:
    def __init__(self, success, txn_hash, message):
        self.success = success
        self.txn_hash = txn_hash
        self.message = message


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
            return Response(False, None, response.get("message"))

    except Exception as e:
        return Response(False, None, str(e))
