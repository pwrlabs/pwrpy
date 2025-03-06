import oqs

class Falcon:
    @staticmethod
    def generate_keypair_512():
        """Generate Falcon-512 key pair."""
        signer = oqs.Signature("Falcon-512")
        public_key = signer.generate_keypair()
        secret_key = signer.export_secret_key()
        return public_key, secret_key  # No free() needed as caller may use it

    @staticmethod
    def generate_keypair_1024():
        """Generate Falcon-1024 key pair."""
        signer = oqs.Signature("Falcon-1024")
        public_key = signer.generate_keypair()
        secret_key = signer.export_secret_key()
        return public_key, secret_key

    @staticmethod
    def sign_512(message: bytes, secret_key: bytes) -> bytes:
        """Sign a message with Falcon-512."""
        signer = oqs.Signature("Falcon-512")
        signer.secret_key = secret_key  # Assign secret key (not an official method, workaround)
        signature = signer.sign(message)  # Sign message
        return signature

    @staticmethod
    def sign_1024(message: bytes, secret_key: bytes) -> bytes:
        """Sign a message with Falcon-1024."""
        signer = oqs.Signature("Falcon-1024")
        signer.secret_key = secret_key  # Workaround to assign secret key
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
