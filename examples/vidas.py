from pwrpy.pwrsdk import PWRPY
from pwrpy.models.Transaction import VidaDataTransaction
import json

rpc = PWRPY("http://46.101.151.203:8085/")

vida_id = 1
starting_block = rpc.get_latest_block_number()

def handle_transaction(txn: VidaDataTransaction):
    try:
        sender = txn.sender
        data_hex = txn.data
        data_bytes = bytes.fromhex(data_hex)
        obj = json.loads(data_bytes.decode('utf-8'))

        if obj["action"] == "send-message-v1":
            print(f"Message from {sender}: {obj['message']}")

    except Exception as e:
        print(f"Error processing transaction: {e}")

subscription = rpc.subscribe_to_vida_transactions(vida_id, starting_block, handler=handle_transaction)
subscription.pause()
subscription.resume()
# subscription.stop()
print(f"Latest checked block: {subscription.get_latest_checked_block()}")
