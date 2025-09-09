import json
import requests
from typing import Union, Optional
import time

class PowerKv:
    def __init__(self, project_id: str, secret: str):
        if not project_id or project_id.strip() == '':
            raise ValueError("Project ID cannot be null or empty")
        if not secret or secret.strip() == '':
            raise ValueError("Secret cannot be null or empty")
        
        self.project_id = project_id
        self.secret = secret
        self.server_url = "https://pwrnosqlvida.pwrlabs.io/"
        
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
        
        url = self.server_url + "/storeData"
        payload = {
            "projectId": self.project_id,
            "secret": self.secret,
            "key": self._to_hex_string(key_bytes),
            "value": self._to_hex_string(data_bytes)
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
                # Parse error message
                try:
                    error_obj = response.json()
                    message = error_obj.get("message", f"HTTP {response.status_code}")
                except (json.JSONDecodeError, ValueError):
                    message = f"HTTP {response.status_code} — {response.text}"
                
                raise RuntimeError(f"storeData failed: {message}")
                
        except requests.exceptions.Timeout:
            raise RuntimeError("Request timeout")
        except requests.exceptions.RequestException as e:
            raise RuntimeError(f"Network error: {e}")
    
    def get_value(self, key: Union[str, bytes, int, float]) -> bytes:
        """Retrieve data for the given key"""
        key_bytes = self._to_bytes(key)
        key_hex = self._to_hex_string(key_bytes)
        
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
                    return self._from_hex_string(value_hex)
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
