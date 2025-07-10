from pwrpy.pwrsdk import PWRPY
from pwrpy.models.Transaction import VidaDataTransaction
import json

rpc = PWRPY("https://pwrrpc.pwrlabs.io/")
vida_id = 1 # Replace with your VIDA's ID

# Since our VIDA is global chat room and we don't care about historical messages,
# we will start reading transactions startng from the latest PWR Chain block
starting_block = rpc.get_latest_block_number()

def handler(txn: VidaDataTransaction):
    try:
        # Get the address of the transaction sender
        sender = txn.sender
        # Get the data sent in the transaction (In Hex Format)
        data_hex = txn.data
        # Convert data string to bytes 
        data_bytes = bytes.fromhex(data_hex)
        obj = json.loads(data_bytes.decode('utf-8'))

        # Check the action and execute the necessary code
        if obj["action"] == "send-message-v1":
            print(f"Message from {sender}: {obj['message']}")

    except Exception as e:
        print(f"Error processing transaction: {e}")

# To pause, resume, and stop the subscription
subscription = rpc.subscribe_to_vida_transactions(vida_id, starting_block, handler)
subscription.pause()
subscription.resume()
# subscription.stop()

# To get the latest checked block
print(subscription.get_latest_checked_block())