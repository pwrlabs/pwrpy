import hashlib
import struct
from typing import Union

class DeterministicSecureRandom:
    def __init__(self, seed: Union[bytes, bytearray]):
        """
        Initialize the deterministic secure random number generator.
        
        Args:
            seed: The seed bytes to use for generating random numbers
        """
        self.seed = bytes(seed)  # Ensure we have a copy of the seed
        self.counter = 0
        self._digest = hashlib.sha256()

    def next_bytes(self, length: int) -> bytes:
        """
        Generate the next sequence of random bytes.
        
        Args:
            length: The number of bytes to generate
            
        Returns:
            bytes: The generated random bytes
        """
        result = bytearray()
        while len(result) < length:
            self._digest = hashlib.sha256()
            self._digest.update(self.seed)
            self._digest.update(struct.pack('>I', self.counter))
            self.counter += 1
            
            hash_bytes = self._digest.digest()
            to_copy = min(len(hash_bytes), length - len(result))
            result.extend(hash_bytes[:to_copy])
            
        return bytes(result)
