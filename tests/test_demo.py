

import os
from pwrpy.pwrapisdk import PWRPY
from pwrpy.pwrwallet import PWRWallet

wallet = PWRWallet(pwrsdk=PWRPY(os.environ.get("PRC_NODE_URL")),
                   private_key_hex=os.environ.get("PRIVATE_KEY_HEX"))


def test_get_address():
    assert wallet.get_address().startswith("0x") == True


def test_get_private_key():
    assert wallet.get_private_key() != None


def test_get_public_key():
    assert wallet.get_public_key() != None


def test_get_balance():
    assert wallet.get_balance() != None


def test_get_nonce():
    assert wallet.get_nonce() != None


def test_transfer_pwr():
    wallet2 = PWRWallet(pwrsdk=PWRPY(os.environ.get("PRC_NODE_URL")))
    r = wallet.transfer_pwr(wallet2.get_address(), 1)

    assert r.success == True


def test_send_vm_data_txn():
    r = wallet.send_vm_data_txn(1, [1])

    if r.success:
        print("Txn Hash: " + r.txnHash)
    if not r.success:
        print(r.error)
    assert r.success == True


def test_delegate():
    wallet2 = PWRWallet(pwrsdk=PWRPY(os.environ.get("PRC_NODE_URL")))

    r = wallet.delegate(wallet2.get_address(), 10000000)
    print("Nonce: " + str(wallet.get_nonce()))

    if not r.success:
        print(r.error)

    if r.success:
        print("Txn Hash: " + r.txnHash)
    assert r.error == "Validator doesn't exist"
