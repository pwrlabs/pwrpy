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
from pwrapisdk import get_nonce_of_address, getBlockByNumber, getBlocksCount, getLatestBlockNumber

from pwrwallet import PWRWallet
from dotenv import load_dotenv

load_dotenv(".env")


PRIVATE_KEY_HEX = os.environ.get("PRIVATE_KEY_HEX")

wallet = PWRWallet(PRIVATE_KEY_HEX)
target_address = "0xe744afead6a2115a3515506868840681c29f67e0"

print("Private Key:", wallet.getPrivateKey())
print("Public Key:", wallet.getPublicKey())
print("Ethereum Address:", wallet.getAddress())

nonce = wallet.getNonce()

r = wallet.getBalance()
blocks_count = getLatestBlockNumber()

b = getBlockByNumber(5)

print(r)
