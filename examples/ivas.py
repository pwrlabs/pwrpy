from pwrpy.pwrsdk import PWRPY
from pwrpy.models.Transaction import VmDataTransaction

rpc = PWRPY()

vm_id = 1234
starting_block = rpc.get_latest_block_number()

def handle_transaction(tx: VmDataTransaction):
    try:
        data_bytes = bytes.fromhex(tx.data[2:])
        data = data_bytes.decode('utf-8')
        print(f"DATA: {data}")
    except Exception as e:
        print(f"Error processing transaction: {e}")

shit = rpc.subscribe_to_iva_transactions(vm_id, starting_block, handler=handle_transaction)
print(f"SHIT: {shit}")
