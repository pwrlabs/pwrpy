import oqs
from pwrpy.Utils.Deterministic import DeterministicSecureRandom
from pwrpy.Utils.falcon_wrapper import generate_keypair, generate_keypair_from_seed

class Falcon:
    @staticmethod
    def generate_keypair_512():
        """Generate Falcon-512 key pair."""
        key_pair = generate_keypair(9)
        return key_pair.public_key, key_pair.private_key

    @staticmethod
    def generate_keypair_512_from_seed(seed: bytes):
        """Generate Falcon-512 key pair from seed."""
        deterministic_random = DeterministicSecureRandom(seed)
        random_bytes = deterministic_random.next_bytes(48)
        deterministic_random = DeterministicSecureRandom(seed)
        deterministic_random.next_bytes(48)

        key_pair = generate_keypair_from_seed(9, random_bytes)
        return key_pair.public_key, key_pair.private_key

    @staticmethod
    def generate_keypair_1024():
        """Generate Falcon-1024 key pair."""
        key_pair = generate_keypair(10)
        return key_pair.public_key, key_pair.private_key

    @staticmethod
    def sign_512(message: bytes, secret_key: bytes) -> bytes:
        """Sign a message with Falcon-512."""
        signer = oqs.Signature("Falcon-512")
        signer.secret_key = secret_key
        signature = signer.sign(message)
        return signature

    @staticmethod
    def sign_1024(message: bytes, secret_key: bytes) -> bytes:
        """Sign a message with Falcon-1024."""
        signer = oqs.Signature("Falcon-1024")
        signer.secret_key = secret_key
        signature = signer.sign(message)
        return signature

    @staticmethod
    def verify_512(message: bytes, signature: bytes, public_key: bytes) -> bool:
        """Verify a Falcon-512 signature."""
        verifier = oqs.Signature("Falcon-512")
        is_valid = verifier.verify(message, signature, public_key)
        return is_valid

    @staticmethod
    def verify_1024(message: bytes, signature: bytes, public_key: bytes) -> bool:
        """Verify a Falcon-1024 signature."""
        verifier = oqs.Signature("Falcon-1024")
        is_valid = verifier.verify(message, signature, public_key)
        return is_valid
