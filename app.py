import hashlib
import os
import coincurve
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from Crypto.Hash import keccak
from models.Validator import Validator
from pwrapisdk import PWRPY

from pwrwallet import PWRWallet
from dotenv import load_dotenv

load_dotenv(".env")


PRIVATE_KEY_HEX = os.environ.get("PRIVATE_KEY_HEX")

wallet = PWRWallet(PRIVATE_KEY_HEX)
target_address = "0xe744afead6a2115a3515506868840681c29f67e0"

print("Private Key:", wallet.get_private_key())
print("Public Key:", wallet.get_public_key())
print("Ethereum Address:", wallet.get_address())

nonce = wallet.get_nonce()

r = wallet.get_balance()
blocks_count = PWRPY.get_latest_block_number()

b = PWRPY.get_block_by_number(5)

print(r)
