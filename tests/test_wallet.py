### Tests for the PWR Wallet functions
import os
import time

from pwrpy.pwrapisdk import PWRPY
from pwrpy.pwrwallet import PWRWallet
sdk = PWRPY()
GREEN = "\033[92m"
RESET = "\033[0m"
ORANGE = "\033[93m"

guardian_private_key = format(19025338099182849188500822369817708178555441129124871592504836170414925188851, 'x')
user = PWRWallet(pwrsdk=PWRPY(), private_key_hex="98d47170a862d357016d4b4e9ddb0fa21cf779a3e10d73772046439ea25b78c6")
guardian = PWRWallet(pwrsdk=PWRPY(), private_key_hex=guardian_private_key)

vmId = 897435

print(ORANGE + "Wallets :" + RESET)
print(GREEN + "\tUser wallet address:" + RESET, user.get_address())
print(GREEN + "\tGuardian wallet address:" + RESET, guardian.get_address())

nonce = user.get_nonce().data

print(ORANGE + "Transfer PWR test:" + RESET)
response = user.transfer_pwr("0x8953f1c3B53Bd9739F78dc8B0CD5DB9686C40b09", 1000000000, nonce)
print(GREEN + "\tTransfer PWR success:" + RESET, response.success)
print(GREEN + "\tTransfer PWR txn hash:" + RESET, response.txnHash)
print(GREEN + "\tTransfer PWR error:" + RESET, response.error)

nonce = nonce + 1

print(ORANGE + "Delegate test:" + RESET)
response = user.delegate("0x61Bd8fc1e30526Aaf1C4706Ada595d6d236d9883", 1000000000, nonce)
print(GREEN + "\tDelegate success:" + RESET, response.success)
print(GREEN + "\tDelegate txn hash:" + RESET, response.txnHash)
print(GREEN + "\tDelegate error:" + RESET, response.error)

nonce = nonce + 1

print(ORANGE + "Claim VM ID test:" + RESET)
response = user.claim_vm_id(vmId, nonce)
print(GREEN + "\tClaim VM ID success:" + RESET, response.success)
print(GREEN + "\tClaim VM ID txn hash:" + RESET, response.txnHash)
print(GREEN + "\tClaim VM ID error:" + RESET, response.error)

nonce = nonce + 1

print(ORANGE + "Send VM Data test:" + RESET)
response = user.send_vm_data_txn(vmId, b"Hello world", nonce)
print(GREEN + "\tSend VM Data success:" + RESET, response.success)
print(GREEN + "\tSend VM Data txn hash:" + RESET, response.txnHash)
print(GREEN + "\tSend VM Data error:" + RESET, response.error)

nonce = nonce + 1
print(ORANGE + "Send Payable VM Data test:" + RESET)
response = user.send_payable_vm_data_txn(vmId, 10*10**9, b"Hello world", nonce)
print(GREEN + "\tSend Payable VM Data success:" + RESET, response.success)
print(GREEN + "\tSend Payable VM Data txn hash:" + RESET, response.txnHash)
print(GREEN + "\tSend Payable VM Data error:" + RESET, response.error)


print(ORANGE + "Get Delegated PWR test:" + RESET)
while sdk.get_delegated_pwr(user.get_address(), "0x61Bd8fc1e30526Aaf1C4706Ada595d6d236d9883") == 0:
    time.sleep(1000)

print("\tDelegated PWR:", sdk.get_delegated_pwr(user.get_address(), "0x61Bd8fc1e30526Aaf1C4706Ada595d6d236d9883"))

nonce = nonce + 1

print(ORANGE + "Withdraw test:" + RESET)
response = user.withdraw("0x61Bd8fc1e30526Aaf1C4706Ada595d6d236d9883", 1, nonce)
print(GREEN + "\tWithdraw success:" + RESET, response.success)
print(GREEN + "\tWithdraw txn hash:" + RESET, response.txnHash)
print(GREEN + "\tWithdraw error:" + RESET, response.error)

def guardian_test(user, guardian):
    try:
        print(ORANGE + "Guardian Test:" + RESET)
        nonce = user.get_nonce().data
        r = user.set_guardian("0x61Bd8fc1e30526Aaf1C4706Ada595d6d236d9883", 1709910721, nonce)
        print("Set Guardian success:", r.success)
        print("Set Guardian txn hash:", r.txnHash)
        print("Set Guardian error:", r.error)

        while sdk.get_guardian_of_address(user.get_address()) is None:
            time.sleep(1)
            print("Guardian still not set")

        nonce += 1
        transfer_txn = user.get_signed_transfer_pwr_txn("0x61Bd8fc1e30526Aaf1C4706Ada595d6d236d9883", 1000, nonce)

        guardian_nonce = guardian.get_nonce()
        r = guardian.send_guardian_wrapped_transaction(transfer_txn, guardian_nonce)
        print("Send Guardian Wrapped Transaction success:", r.success)
        print("Send Guardian Wrapped Transaction txn hash:", r.success)
        print("Send Guardian Wrapped Transaction error:", r.error)

        nonce += 1
        print(ORANGE + "Withdraw PWR test:" + RESET)
        response = user.withdraw_pwr("0x61Bd8fc1e30526Aaf1C4706Ada595d6d236d9883", 1000000000 , nonce)
        print(GREEN + "\tWithdraw PWR success:" + RESET, response.success)
        print(GREEN + "\tWithdraw PWR txn hash:" + RESET, response.txnHash)
        print(GREEN + "\tWithdraw PWR error:" + RESET, response.error)

        remove_guardian_txn = user.get_signed_remove_guardian_txn(nonce)

        guardian_nonce += 1
        r = guardian.send_guardian_wrapped_transaction(remove_guardian_txn, guardian_nonce)
        print("Remove Guardian success:", r.success)
        print("Remove Guardian txn hash:", r.txnHash)
        print("Remove Guardian error:", r.error)

    except Exception as e:
        print("Guardian test failed:", e)


guardian_test(user, guardian)












