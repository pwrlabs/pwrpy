### Tests for the PWRPY API SDK functions
from pwrpy.pwrapisdk import PWRPY

sdk = PWRPY()
address = "0xf6fe6a14b3aac06c2c102cf5f028df35157f9770"

GREEN = "\033[92m"
RESET = "\033[0m"

# Print statements with formatted strings
print(GREEN + "Chain ID:" + RESET, sdk.get_chainId())
print(GREEN + "RPC Node URL:" + RESET, sdk.get_rpc_node_url())
print(GREEN + "Fee per byte:" + RESET, sdk.get_fee_per_byte())
print(GREEN + "Blockchain version:" + RESET, sdk.get_blockchain_version())
print(GREEN + "Blocks count:" + RESET, sdk.get_blocks_count())
print(GREEN + "Latest block number:", sdk.get_latest_block_number())
block_number = 999  # change block number for different blocks
block = sdk.get_block_by_number(block_number=block_number)
print(GREEN + f"Block no. {block_number}:" + RESET, "\nSuccess", block.success, "\nTransaction count:", block.transaction_count,
      "\nHash:", block.hash, "\nTimestamp:", block.timestamp, "\nBlock number:", block.number, "\nReward", block.reward,
      "\nSize:", block.size,"\nSubmitter:", block.submitter, "\nTransactions:")
for i, transaction in enumerate(block.transactions):
    print(f"Transaction {i+1}:")
    print("\tSize:", transaction.size)
    print("\tHash:", transaction.hash)
    print("\tTimestamp:", transaction.timestamp)
    print("\tPosition in the block:", transaction.position_in_the_block)
    print("\tBlock number:", transaction.block_number)
    print("\tType:", transaction.type)
    print("\tValue:", transaction.value)
    print("\tFee:", transaction.fee)
    print("\tNonce:", transaction.nonce)
    print("\tReceiver:", transaction.receiver)
    print("\tSender:", transaction.sender)

print(GREEN + "Active voting power:" + RESET, sdk.get_active_voting_power())
print(GREEN + "Total validators count:" + RESET, sdk.get_total_validators_count())
print(GREEN + "Standby validators count:" + RESET, sdk.get_standby_validators_count())
print(GREEN + "Active validators count:" + RESET, sdk.get_active_validators_count())
print(GREEN + "Total delegators count:" + RESET, sdk.get_total_delegators_count())
print(GREEN + "All validators:" + RESET)
for i, validator in enumerate(sdk.get_all_validators()):
    print(f"Validator {i + 1}:")
    print("\tAddress:", validator.address)
    print("\tIP address:", validator.ip)
    print("\tIs bad actor", validator.bad_actor)
    print("\tVoting Power:", validator.voting_power)
    print("\tDelegators count:", validator.delegators_count)
    print("\tShares:", validator.shares)
    print("\tStatus:", validator.status)

print(GREEN + "Standby validators:" + RESET, sdk.get_standby_validators())
print(GREEN + "Active Validators:" + RESET, sdk.get_active_validators())
print(GREEN + "Transactions from block 1 to 4:" + RESET, sdk.get_vm_data_txns(1, 4, 10023))
print(GREEN + "Owner of vm 100:" + RESET, sdk.get_owner_of_vm(100))
print(GREEN + "Nonce:" + RESET, sdk.get_nonce_of_address(address).data)
print(GREEN + "Balance:" + RESET, sdk.get_balance_of_address(address))
print(GREEN + "Guardian:" + RESET, sdk.get_guardian_of_address(address))
print(GREEN + "Delegatees:" + RESET, sdk.get_delegatees(address))
print(GREEN + "Validator:" + RESET, sdk.get_validator(address))
print(GREEN + "Delegated PWR:" + RESET, sdk.get_delegated_pwr(address, "0xf6fe6a14b3aac06c2c102cf5f028df35157f9770"))
print(GREEN + "Share value:" + RESET, sdk.get_share_value(address))
