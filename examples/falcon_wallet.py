from pwrpy.falconwallet import Falcon512Wallet
from pwrpy.pwrsdk import PWRPY

def main():
    # wallet = Falcon512Wallet.new()
    # wallet.store_wallet("new_falcon.dat")
    wallet = Falcon512Wallet.load_wallet("new_falcon.dat")
    print(f"Address: {wallet.get_address()}")

    tx = wallet.transfer_pwr(wallet.get_address(), 1)
    if tx.success:
        print(f"TX Hash: 0x{tx.data.hex()}")
    else:
        print(f"TX Error: {tx.message}")

main()
