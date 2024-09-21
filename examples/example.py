from pwrpy.pwrapisdk import PWRPY
from pwrpy.pwrwallet import PWRWallet

private_key = "0x9D4428C6E0638331B4866B70C831F8BA51C11B031F4B55EED4087BBB8EF0151F"
pwr = PWRPY()
wallet = PWRWallet(private_key)

GREEN = "\033[92m"
RESET = "\033[0m"
ORANGE = "\033[93m"

print(ORANGE + "Tests for Governance Update" + RESET)

address = wallet.get_address()
print(GREEN + "Address:" + RESET, address)

nonce = wallet.get_nonce().data
print(GREEN + "Nonce:" + RESET, nonce)

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

transfer = wallet.transfer_pwr("0x61bd8fc1e30526aaf1c4706ada595d6d236d9883", 100000, nonce)
if transfer.success:
    print(GREEN + "Transfer:" + RESET, transfer.__dict__)
else:
    print(ORANGE + "FAILED!" + RESET)

data = "Hello World!"
sendVmData = wallet.send_vm_data_transaction(123, data.encode(), nonce+1)
if sendVmData.success:
    print(GREEN + "SendVmData:" + RESET, sendVmData.__dict__)
else:
    print(ORANGE + "FAILED!" + RESET)