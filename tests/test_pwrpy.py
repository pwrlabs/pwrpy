### Tests for the PWRPY API SDK functions
from pwrpy.pwrsdk import PWRPY

sdk = PWRPY("https://pwrrpc.pwrlabs.io/")
address = "0xf6fe6a14b3aac06c2c102cf5f028df35157f9770"

GREEN = "\033[92m"
RESET = "\033[0m"
ORANGE = "\033[93m"

#
# # Print statements with formatted strings
# print(GREEN + "Chain ID:" + RESET, sdk.get_chainId())
# print(GREEN + "RPC Node URL:" + RESET, sdk.get_rpc_node_url())
# print(GREEN + "Fee per byte:" + RESET, sdk.get_fee_per_byte())
# print(GREEN + "Blockchain version:" + RESET, sdk.get_blockchain_version())
# print(GREEN + "Blocks count:" + RESET, sdk.get_blocks_count())
# print(GREEN + "Latest block number:" + RESET, sdk.get_latest_block_number())
# block_number = 1  # change block number for different blocks
# block = sdk.get_block_by_number(block_number=block_number)
# print(GREEN + f"Block no. {block_number}:" + RESET, "\nProcessed without critical errors:", block.processed_without_critical_errors, "\nTransaction count:", block.transaction_count,
#       "\nHash:", block.hash, "\nTimestamp:", block.timestamp, "\nBlock number:", block.number, "\nReward", block.reward,
#       "\nSize:", block.size, "\nSubmitter:", block.submitter, "\nTransactions:")
# for i, transaction in enumerate(block.transactions):
#     print(f"Transaction {i+1}:")
#     print("\tSize:", transaction.size)
#     print("\tHash:", transaction.hash)
#     print("\tTimestamp:", transaction.timestamp)
#     print("\tPosition in the block:", transaction.position_in_the_block)
#     print("\tBlock number:", transaction.block_number)
#     print("\tType:", transaction.type)
#     print("\tFee:", transaction.fee)
#     print("\tNonce:", transaction.nonce)
#     print("\tReceiver:", transaction.receiver)
#     print("\tSender:", transaction.sender)
#
# print(GREEN + "Active voting power:" + RESET, sdk.get_active_voting_power())
# print(GREEN + "Total validators count:" + RESET, sdk.get_total_validators_count())
# print(GREEN + "Standby validators count:" + RESET, sdk.get_standby_validators_count())
# print(GREEN + "Active validators count:" + RESET, sdk.get_active_validators_count())
# print(GREEN + "Total delegators count:" + RESET, sdk.get_total_delegators_count())
# print(GREEN + "All validators:" + RESET)
# for i, validator in enumerate(sdk.get_all_validators()):
#     print(f"Validator {i + 1}:")
#     print("\tAddress:", validator.address)
#     print("\tIP address:", validator.ip)
#     print("\tIs bad actor", validator.bad_actor)
#     print("\tVoting Power:", validator.voting_power)
#     print("\tDelegators count:", validator.delegators_count)
#     print("\tShares:", validator.shares)
#     print("\tStatus:", validator.status)
#
# print(GREEN + "Standby validators:" + RESET, sdk.get_standby_validators())
# print(GREEN + "Active Validators:" + RESET, sdk.get_active_validators())
# print(GREEN + "Transactions from block 1 to 4:" + RESET, sdk.get_vm_data_txns(1, 4, 10023))
# print(GREEN + "Owner of vm 100:" + RESET, sdk.get_owner_of_vm(100))
# print(GREEN + "Nonce:" + RESET, sdk.get_nonce_of_address(address))
# print(GREEN + "Balance:" + RESET, sdk.get_balance_of_address(address))
# print(GREEN + "Guardian:" + RESET, sdk.get_guardian_of_address(address))
# print(GREEN + "Delegatees:" + RESET, sdk.get_delegatees(address))
# print(GREEN + "Validator:" + RESET, sdk.get_validator(address))
# print(GREEN + "Delegated PWR:" + RESET, sdk.get_delegated_pwr(address, "0xf6fe6a14b3aac06c2c102cf5f028df35157f9770"))
# print(GREEN + "Share value:" + RESET, sdk.get_share_value(address))

### Tests for the Governance update
print(ORANGE + "Tests for Governance Update" + RESET)
print(GREEN + "get_max_transaction_size:" + RESET, sdk.get_max_transaction_size())
print(GREEN + "get_validator_count_limit:" + RESET, sdk.get_validator_count_limit())
print(GREEN + "get_validator_slashing_fee:" + RESET, sdk.get_validator_slashing_fee())
print(GREEN + "get_vm_owner_transaction_fee_share:" + RESET, sdk.get_vm_owner_transaction_fee_share())
print(GREEN + "get_burn_percentage:" + RESET, sdk.get_burn_percentage())
print(GREEN + "get_validator_operational_fee:" + RESET, sdk.get_validator_operational_fee())
print(GREEN + "get_block_number:" + RESET, sdk.get_block_number())
print(GREEN + "get_block_timestamp:" + RESET, sdk.get_block_timestamp())
print(GREEN + "get_total_voting_power:" + RESET, sdk.get_total_voting_power())
print(GREEN + "get_pwr_rewards_per_year:" + RESET, sdk.get_pwr_rewards_per_year())
print(GREEN + "get_withdrawal_lock_time:" + RESET, sdk.get_withdrawal_lock_time())
print(GREEN + "get_validator_joining_fee:" + RESET, sdk.get_validator_joining_fee())
print(GREEN + "get_max_guardian_time:" + RESET, sdk.get_max_guardian_time())
print(GREEN + "get_vm_id_claiming_fee:" + RESET, sdk.get_vm_id_claiming_fee())
print(GREEN + "get_proposal_fee:" + RESET, sdk.get_proposal_fee())
print(GREEN + "get_proposal_validity_time:" + RESET, sdk.get_proposal_validity_time())
print(GREEN + "get_minimum_delegating_amount:" + RESET, sdk.get_minimum_delegating_amount())
early_withdraw_penalty = sdk.get_early_withdraw_penalty(1000000)
print(early_withdraw_penalty.penalty, early_withdraw_penalty.early_withdraw_available,
      early_withdraw_penalty.is_early_withdraw_available())
print(GREEN + "get_all_early_withdraw_penalties:" + RESET, sdk.get_all_early_withdraw_penalties())
