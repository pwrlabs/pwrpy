from pwrpy.pwrsdk import PWRPY
from pwrpy.pwrwallet import PWRWallet

private_key = "0x04828e90065864c111871769c601d7de2246570b39dd37c19ccac16c14b18f72"
pwr = PWRPY("https://pwrrpc.pwrlabs.io/")

PWRWallet(private_key, pwr).store_wallet("my_wallet.dat", "1234")
wallet = PWRWallet.load_wallet("my_wallet.dat", "1234")

GREEN = "\033[92m"
RESET = "\033[0m"
ORANGE = "\033[93m"

print(ORANGE + "Tests for Governance Update" + RESET)

address = wallet.get_address()
print(GREEN + "Address:" + RESET, address)

nonce = wallet.get_nonce()
print(GREEN + "Nonce:" + RESET, nonce)

nonce = pwr.get_nonce_of_address(address)
print(GREEN + "NonceAddress:" + RESET, nonce)

balance = wallet.get_balance()
print(GREEN + "Balance:" + RESET, balance)

blocks_count = pwr.get_blocks_count()
print(GREEN + "BlocksCount:" + RESET, blocks_count)

latest_block_count = pwr.get_latest_block_number()
print(GREEN + "LatestBlockCount:" + RESET, latest_block_count)

block = pwr.get_block_by_number(1337)
print(GREEN + "Block:" + RESET, block.__dict__)

active_voting_power = pwr.get_active_voting_power()
print(GREEN + "ActiveVotingPower:" + RESET, active_voting_power)

total_validators_count = pwr.get_all_validators()
print(GREEN + "TotalValidatorsCount:" + RESET, total_validators_count)

standby_validators_count = pwr.get_standby_validators_count()
print(GREEN + "StandbyValidatorsCount:" + RESET, standby_validators_count)

active_validators_count = pwr.get_active_validators_count()
print(GREEN + "ActiveValidatorsCount:" + RESET, active_validators_count)

all_validators = pwr.get_all_validators()
print(GREEN + "AllValidators:" + RESET, all_validators)

standby_validators = pwr.get_standby_validators()
print(GREEN + "StandbyValidators:" + RESET, standby_validators)

active_validators = pwr.get_active_validators()
print(GREEN + "ActiveValidators:" + RESET, active_validators)

transfer = wallet.transfer_pwr(wallet.get_address(), 100)
if transfer.success:
    print(GREEN + "Transfer:" + RESET, f"0x{transfer.data.hex()}")
else:
    print(ORANGE + "FAILED!" + RESET)

data = "Hello World!"
sendVmData = wallet.send_vm_data_transaction(123, data.encode())
if sendVmData.success:
    print(GREEN + "SendVmData:" + RESET, f"0x{sendVmData.data.hex()}")
else:
    print(ORANGE + "FAILED!" + RESET)

sendPayableVmData = wallet.send_payable_vm_data_transaction(123, 100, data.encode())
if sendPayableVmData.success:
    print(GREEN + "SendPayableVmData:" + RESET, f"0x{sendPayableVmData.data.hex()}")
else:
    print(ORANGE + "FAILED!" + RESET)
