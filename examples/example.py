from pwrpy.pwrsdk import PWRPY
from pwrpy.pwrwallet import Wallet

pwr = PWRPY("https://pwrrpc.pwrlabs.io/")
wallet = Wallet.new("demand april length soap cash concert shuffle result force mention fringe slim")
wallet.store_wallet("example_wallet.dat", "your_password_here")

wallet = Wallet.load_wallet("example_wallet.dat", "your_password_here", pwr)

GREEN = "\033[92m"
RESET = "\033[0m"
ORANGE = "\033[93m"

print(ORANGE + "Tests for Governance Update" + RESET)

address = wallet.get_address()
print(GREEN + "Address:" + RESET, address)

block = pwr.get_block_by_number(123741)        
# prints the sender address from every transaction in the block
for index, txs in enumerate(block.transactions):
    transaction = pwr.get_transaction_by_hash(txs.transaction_hash)
    print(f"Sender {index}: {transaction.sender}")

seed_phrase = wallet.get_seed_phrase()
print(GREEN + "Seed Phrase:" + RESET, seed_phrase)

nonce = wallet.get_nonce()
print(GREEN + "Nonce:" + RESET, nonce)

balance = wallet.get_balance()
print(GREEN + "Balance:" + RESET, balance)

blocks_count = pwr.get_blocks_count()
print(GREEN + "BlocksCount:" + RESET, blocks_count)

latest_block_count = pwr.get_latest_block_number()
print(GREEN + "LatestBlockCount:" + RESET, latest_block_count)

block = pwr.get_block_by_number(9040)
print(GREEN + "Block:" + RESET, block.__dict__)

active_voting_power = pwr.get_active_voting_power()
print(GREEN + "ActiveVotingPower:" + RESET, active_voting_power)

start_block = 85411
end_block = 85420
vida_id = 123
transactions = pwr.get_vida_data_transactions(start_block, end_block, vida_id)
print(GREEN + "Transactions:" + RESET, transactions)

transactions = pwr.get_vida_data_transactions(start_block, end_block, vida_id)
# prints the trasnactions data
for txs in transactions:
    print("Data:", txs.data)

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

fee_per_byte = wallet.get_rpc().get_fee_per_byte()
print(GREEN + "FeePerByte:" + RESET, fee_per_byte)

tx = wallet.transfer_pwr(wallet.get_address(), 100, fee_per_byte)
if tx.success:
    print(GREEN + "Transfer:" + RESET, f"0x{tx.hash.hex()}")
else:
    print(ORANGE + "FAILED:" + RESET, tx.message)

data = "Hello World!"
tx = wallet.send_vida_data(123, data.encode(), fee_per_byte)
if tx.success:
    print(GREEN + "SendVidaData:" + RESET, f"0x{tx.hash.hex()}")
else:
    print(ORANGE + "FAILED:" + RESET, tx.message)

tx = wallet.send_payable_vida_data(123, data.encode(), 100, fee_per_byte)
if tx.success:
    print(GREEN + "SendPayableVidaData:" + RESET, f"0x{tx.hash.hex()}")
else:
    print(ORANGE + "FAILED:" + RESET, tx.message)
