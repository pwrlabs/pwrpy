import json
import requests
import hashlib
import struct
from typing import Union, Tuple
from pwrpy.Utils.AES256 import AES256

class PowerKv:
    def __init__(self, project_id: str, secret: str):
        if not project_id or project_id.strip() == '':
            raise ValueError("Project ID cannot be null or empty")
        if not secret or secret.strip() == '':
            raise ValueError("Secret cannot be null or empty")
        
        self.project_id = project_id
        self.secret = secret
        self.server_url = "https://powerkvbe.pwrlabs.io"
        
        # Create session with timeout
        self.session = requests.Session()
        self.session.timeout = 10.0  # 10 second timeout
    
    def get_server_url(self) -> str:
        return self.server_url
    
    def get_project_id(self) -> str:
        return self.project_id
    
    def _to_hex_string(self, data: bytes) -> str:
        """Convert bytes to hex string"""
        return data.hex()
    
    def _from_hex_string(self, hex_string: str) -> bytes:
        """Convert hex string to bytes"""
        # Handle both with and without 0x prefix
        if hex_string.startswith('0x') or hex_string.startswith('0X'):
            hex_string = hex_string[2:]
        return bytes.fromhex(hex_string)
    
    def _hash256(self, input_data: bytes) -> bytes:
        """PWRHash - Keccak256 hash function"""
        # Using SHA3-256 (Keccak256) from hashlib
        return hashlib.sha3_256(input_data).digest()
    
    def _pack_data(self, key: bytes, data: bytes) -> bytes:
        """Binary data packing (ByteBuffer equivalent)"""
        key_buffer = key if isinstance(key, bytes) else key.encode('utf-8')
        data_buffer = data if isinstance(data, bytes) else data.encode('utf-8')
        
        # Pack: 4 bytes (key length) + key + 4 bytes (data length) + data
        # Using big-endian format ('>I' = big-endian unsigned int)
        packed = struct.pack('>I', len(key_buffer)) + key_buffer + struct.pack('>I', len(data_buffer)) + data_buffer
        return packed
    
    def _unpack_data(self, packed_buffer: bytes) -> Tuple[bytes, bytes]:
        """Binary data unpacking"""
        offset = 0
        
        # Read key length (4 bytes, big-endian)
        key_length = struct.unpack('>I', packed_buffer[offset:offset+4])[0]
        offset += 4
        
        # Read key bytes
        key = packed_buffer[offset:offset+key_length]
        offset += key_length
        
        # Read data length (4 bytes, big-endian)
        data_length = struct.unpack('>I', packed_buffer[offset:offset+4])[0]
        offset += 4
        
        # Read data bytes
        data = packed_buffer[offset:offset+data_length]
        
        return key, data
    
    def _to_bytes(self, data: Union[str, bytes, int, float]) -> bytes:
        """Convert various data types to bytes"""
        if data is None:
            raise ValueError("Data cannot be None")
        
        if isinstance(data, bytes):
            return data
        elif isinstance(data, str):
            return data.encode('utf-8')
        elif isinstance(data, (int, float)):
            return str(data).encode('utf-8')
        else:
            raise ValueError("Data must be a string, bytes, or number")
    
    def put(self, key: Union[str, bytes, int, float], data: Union[str, bytes, int, float]) -> bool:
        """Store data with the given key"""
        key_bytes = self._to_bytes(key)
        data_bytes = self._to_bytes(data)
        
        # Hash the key with Keccak256
        key_hash = self._hash256(key_bytes)
        
        # Pack the original key and data
        packed_data = self._pack_data(key_bytes, data_bytes)
        
        # Encrypt the packed data
        encrypted_data = AES256.encrypt(packed_data, self.secret)
        
        url = self.server_url + "/storeData"
        payload = {
            "projectId": self.project_id,
            "secret": self.secret,
            "key": self._to_hex_string(key_hash),
            "value": self._to_hex_string(encrypted_data)
        }
        
        try:
            response = self.session.post(
                url,
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=10.0
            )
            
            if response.status_code == 200:
                return True
            else:
                raise RuntimeError(f"storeData failed: {response.status_code} - {response.text}")
                
        except requests.exceptions.Timeout:
            raise RuntimeError("Request timeout")
        except requests.exceptions.RequestException as e:
            raise RuntimeError(f"Network error: {e}")
    
    def get_value(self, key: Union[str, bytes, int, float]) -> bytes:
        """Retrieve data for the given key"""
        key_bytes = self._to_bytes(key)
        
        # Hash the key with Keccak256
        key_hash = self._hash256(key_bytes)
        key_hex = self._to_hex_string(key_hash)
        
        url = f"{self.server_url}/getValue"
        params = {
            "projectId": self.project_id,
            "key": key_hex
        }
        
        try:
            response = self.session.get(url, params=params, timeout=10.0)
            
            if response.status_code == 200:
                try:
                    response_obj = response.json()
                    value_hex = response_obj["value"]
                    
                    # Handle both with/without 0x prefix
                    clean_hex = value_hex
                    if clean_hex.startswith('0x') or clean_hex.startswith('0X'):
                        clean_hex = clean_hex[2:]
                    
                    encrypted_value = self._from_hex_string(clean_hex)
                    
                    # Decrypt the data
                    decrypted_data = AES256.decrypt(encrypted_value, self.secret)
                    
                    # Unpack the data to get original key and data
                    original_key, actual_data = self._unpack_data(decrypted_data)
                    
                    return actual_data
                except (json.JSONDecodeError, KeyError, ValueError) as e:
                    raise RuntimeError(f"Unexpected response shape from /getValue: {response.text}")
            else:
                # Parse error message
                try:
                    error_obj = response.json()
                    message = error_obj.get("message", f"HTTP {response.status_code}")
                except (json.JSONDecodeError, ValueError):
                    message = f"HTTP {response.status_code} — {response.text}"
                
                raise RuntimeError(f"getValue failed: {message}")
                
        except requests.exceptions.Timeout:
            raise RuntimeError("GET /getValue failed (network/timeout)")
        except requests.exceptions.RequestException as e:
            raise RuntimeError(f"Network error: {e}")
    
    def get_string_value(self, key: Union[str, bytes, int, float]) -> str:
        """Retrieve data as string"""
        data = self.get_value(key)
        return data.decode('utf-8')
    
    def get_int_value(self, key: Union[str, bytes, int, float]) -> int:
        """Retrieve data as integer"""
        data = self.get_value(key)
        return int(data.decode('utf-8'))
    
    def get_long_value(self, key: Union[str, bytes, int, float]) -> int:
        """Retrieve data as long (same as int in Python)"""
        data = self.get_value(key)
        return int(data.decode('utf-8'))
    
    def get_double_value(self, key: Union[str, bytes, int, float]) -> float:
        """Retrieve data as float"""
        data = self.get_value(key)
        return float(data.decode('utf-8'))
