import hashlib
import os
import coincurve
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from Crypto.Hash import keccak

from dotenv import load_dotenv

from pwrpy.pwrapisdk import PWRPY
from pwrpy.pwrwallet import PWRWallet


load_dotenv(".env")


PRIVATE_KEY_HEX = os.environ.get("PRIVATE_KEY_HEX")


wallet = PWRWallet(PRIVATE_KEY_HEX)
target_address = "0xe744afead6a2115a3515506868840681c29f67e0"

print("Private Key:", wallet.get_private_key())
print("Public Key:", wallet.get_public_key())
print("Ethereum Address:", wallet.get_address())

total_validators = PWRPY(os.environ.get("PRC_NODE_URL")
                         ).get_total_validators_count()

print(total_validators)
