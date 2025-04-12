### Tests for the PWR Wallet functions

from pwrpy.pwrsdk import PWRPY
from pwrpy.pwrwallet import PWRWallet

sdk = PWRPY("https://pwrrpc.pwrlabs.io/")
GREEN = "\033[92m"
RESET = "\033[0m"
ORANGE = "\033[93m"

user_private_key = "0x98d47170a862d357016d4b4e9ddb0fa21cf779a3e10d73772046439ea25b78c6"
guardian_private_key = format(19025338099182849188500822369817708178555441129124871592504836170414925188851, 'x')
User = PWRWallet(pwrpy=PWRPY("https://pwrrpc.pwrlabs.io/"), private_key=user_private_key)
User.get_address()

Guardian = PWRWallet(pwrpy=PWRPY("https://pwrrpc.pwrlabs.io/"), private_key=guardian_private_key)

vmId = 897435
vm_address = sdk.get_vm_id_address(vmId)
print("VM ID address:", vm_address)
print("Owner of VM ID :", sdk.get_owner_of_vm(vmId))
print(f"{vm_address} is a VM Address: ", sdk.is_vm_address(vm_address))

# print(ORANGE + "Wallets :" + RESET)
# print(GREEN + "\tUser wallet address:" + RESET, User.get_address())
# print(GREEN + "\tGuardian wallet address:" + RESET, Guardian.get_address())

print(ORANGE + "Transfer PWR test:" + RESET)
response = User.transfer_pwr("0x8953f1c3B53Bd9739F78dc8B0CD5DB9686C40b09", 20, nonce=User.get_nonce().data)
print(GREEN + "\tTransfer PWR success:" + RESET, response.success)
print(GREEN + "\tTransfer PWR txn hash:" + RESET, response.data)
print(GREEN + "\tTransfer PWR error:" + RESET, response.message)


#
#
# print(ORANGE + "Delegate test:" + RESET)
# response = User.delegate("0x61Bd8fc1e30526Aaf1C4706Ada595d6d236d9883", 1000000000,  User.get_nonce().data)
# print(GREEN + "\tDelegate success:" + RESET, response.success)
# print(GREEN + "\tDelegate txn hash:" + RESET, response.data)
# print(GREEN + "\tDelegate error:" + RESET, response.message)
#
#
# print(ORANGE + "Claim VM ID test:" + RESET)
# response = User.claim_vm_id(vmId, User.get_nonce().data)
# print(GREEN + "\tClaim VM ID success:" + RESET, response.success)
# print(GREEN + "\tClaim VM ID txn hash:" + RESET, response.data)
# print(GREEN + "\tClaim VM ID error:" + RESET, response.message)
#
#
# print(ORANGE + "Send VM Data test:" + RESET)
# response = User.send_vm_data_transaction(vmId, b"Hello world", User.get_nonce().data)
# print(GREEN + "\tSend VM Data success:" + RESET, response.success)
# print(GREEN + "\tSend VM Data txn hash:" + RESET, response.data)
# print(GREEN + "\tSend VM Data error:" + RESET, response.message)
#
# print(ORANGE + "Send Payable VM Data test:" + RESET)
# response = User.send_payable_vm_data_transaction(vmId, 1 * 10**9, b"HELLO I AM A BIGGER MESSAGE", User.get_nonce().data)
# print(GREEN + "\tSend Payable VM Data success:" + RESET, response.success)
# print(GREEN + "\tSend Payable VM Data txn hash:" + RESET, response.data)
# print(GREEN + "\tSend Payable VM Data error:" + RESET, response.message)
#
# print(ORANGE + "Get Delegated PWR test:" + RESET)
# while sdk.get_delegated_pwr(User.get_address(), "0x61Bd8fc1e30526Aaf1C4706Ada595d6d236d9883") == 0:
#     time.sleep(1000)
#
# print("\tDelegated PWR:", sdk.get_delegated_pwr(User.get_address(), "0x61Bd8fc1e30526Aaf1C4706Ada595d6d236d9883"))
#
# print(ORANGE + "Withdraw test:" + RESET)
# response = User.withdraw("0x61Bd8fc1e30526Aaf1C4706Ada595d6d236d9883", 1, User.get_nonce().data)
# print(GREEN + "\tWithdraw success:" + RESET, response.success)
# print(GREEN + "\tWithdraw txn hash:" + RESET, response.data)
# print(GREEN + "\tWithdraw error:" + RESET, response.message)


# def guardian_test(User, Guardian):
#     try:
#         print(ORANGE + "Guardian Test:" + RESET)
#         r = User.set_guardian("0x61Bd8fc1e30526Aaf1C4706Ada595d6d236d9883", 1718110233, User.get_nonce().data)
#         print("Set Guardian success:", r.success)
#         print("Set Guardian txn hash:", r.data)
#         print("Set Guardian error:", r.message)
#
#         while sdk.get_guardian_of_address(User.get_address()) is None:
#             time.sleep(1)
#             print("Guardian still not set")
#
#         transfer_txn = User.get_signed_transfer_pwr_transaction("0x61Bd8fc1e30526Aaf1C4706Ada595d6d236d9883", 1000,
#                                                                 User.get_nonce().data)
#
#         guardian_nonce = Guardian.get_nonce()
#         r = Guardian.send_guardian_wrapped_transaction(transfer_txn, guardian_nonce)
#         print("Send Guardian Wrapped Transaction success:", r.success)
#         print("Send Guardian Wrapped Transaction txn hash:", r.success)
#         print("Send Guardian Wrapped Transaction error:", r.message)
#
#         print(ORANGE + "Withdraw PWR test:" + RESET)
#         response = User.withdraw_pwr("0x61Bd8fc1e30526Aaf1C4706Ada595d6d236d9883", 1000000000, User.get_nonce().data)
#         print(GREEN + "\tWithdraw PWR success:" + RESET, response.success)
#         print(GREEN + "\tWithdraw PWR txn hash:" + RESET, response.data)
#         print(GREEN + "\tWithdraw PWR error:" + RESET, response.message)
#
#         remove_guardian_txn = User.get_signed_remove_guardian_txn(User.get_nonce().data)
#
#         guardian_nonce += 1
#         r = Guardian.send_guardian_approval_transaction(remove_guardian_txn, guardian_nonce)
#         print("Remove Guardian success:", r.success)
#         print("Remove Guardian txn hash:", r.data)
#         print("Remove Guardian error:", r.message)
#
#     except Exception as e:
#         print("Guardian test failed:", e)
#
#
# guardian_test(User, Guardian)
