from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os

class AES256:
    ITERATION_COUNT = 65536
    KEY_LENGTH = 256
    SALT = b"your-salt-value"

    @staticmethod
    def generate_key(password: str) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # 256 bits = 32 bytes
            salt=AES256.SALT,
            iterations=AES256.ITERATION_COUNT,
            backend=default_backend()
        )
        return kdf.derive(password.encode())

    @staticmethod
    def generate_iv() -> bytes:
        return os.urandom(16)  # 16 bytes = 128 bits for AES

    @staticmethod
    def encrypt(data: bytes, password: str) -> bytes:
        key = AES256.generate_key(password)
        iv = AES256.generate_iv()
        
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        
        # Add PKCS7 padding
        pad_length = 16 - (len(data) % 16)
        padded_data = data + bytes([pad_length] * pad_length)
        
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        
        # Combine IV and encrypted data
        return iv + encrypted_data

    @staticmethod
    def decrypt(encrypted_data_with_iv: bytes, password: str) -> bytes:
        key = AES256.generate_key(password)
        
        # Split IV and encrypted data
        iv = encrypted_data_with_iv[:16]
        encrypted_data = encrypted_data_with_iv[16:]
        
        cipher = Cipher(
            algorithms.AES(key),
            modes.CBC(iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        
        padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
        
        # Remove PKCS7 padding
        pad_length = padded_data[-1]
        return padded_data[:-pad_length]

def main():
    # Example usage with BigInteger equivalent
    t = 9872156793
    
    try:
        # Convert integer to bytes
        data = t.to_bytes((t.bit_length() + 7) // 8, byteorder='big')
        
        # Encrypt
        encrypted_data = AES256.encrypt(data, "testlol")
        
        # Decrypt
        decrypted_data = AES256.decrypt(encrypted_data, "testlol")
        
        # Convert back to integer
        new_t = int.from_bytes(decrypted_data, byteorder='big')
        print(new_t)
        
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()