from pwrpy.pwrsdk import PWRPY
from pwrpy.models.Transaction import VmDataTransaction
import json
import time

rpc = PWRPY()

vida_id = 1234
starting_block = rpc.get_latest_block_number()

def handle_transaction(txn: VmDataTransaction):
    try:
        sender = txn.sender
        data_hex = txn.data
        data_bytes = bytes.fromhex(data_hex[2:])
        obj = json.loads(data_bytes.decode('utf-8'))

        if obj["action"] == "send-message-v1":
            print(f"Message from {sender}: {obj['message']}")

    except Exception as e:
        print(f"Error processing transaction: {e}")

vidaTxs = rpc.subscribe_to_vida_transactions(vida_id, starting_block, handler=handle_transaction)
print(vidaTxs.get_vida_id())

try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    print("\nStopping subscription...")
    vidaTxs.stop()