from pwrpy.pwrsdk import PWRPY
from pwrpy.pwrwallet import Wallet
import json

pwr = PWRPY("https://pwrrpc.pwrlabs.io/")
wallet = Wallet.new("demand april length soap cash concert shuffle result force mention fringe slim")

json_object = {
    "action": "send-message-v1",
    "message": "Hello World!"
}
data = json.dumps(json_object).encode("utf-8")
fee_per_byte = wallet.get_rpc().get_fee_per_byte()

# Send transaction
response = wallet.send_vida_data(1, data, fee_per_byte)
if response.success:
    print("Transaction sent successfully!")
    print(f"Transaction hash: 0x{response.hash.hex()}")
else:
    print(f"Transaction failed: {response.error}")

