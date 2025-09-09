import threading
import time
from typing import Union, Optional, Dict
from concurrent.futures import ThreadPoolExecutor
import logging
from power_kv import PowerKv

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class ByteArrayWrapper:
    """Wrapper for bytes to use as dictionary keys"""
    def __init__(self, data: bytes):
        self.data = data
        self.hash_value = data.hex()
    
    def __eq__(self, other):
        return isinstance(other, ByteArrayWrapper) and self.data == other.data
    
    def __hash__(self):
        return hash(self.hash_value)
    
    def __str__(self):
        return self.hash_value

class PowerKvCached:
    def __init__(self, project_id: str, secret: str):
        self.db = PowerKv(project_id, secret)
        self.cache: Dict[ByteArrayWrapper, bytes] = {}
        self.cache_lock = threading.RLock()
        self.is_shutdown = False
        
        # Thread pool for background writes (similar to Java's ThreadPoolExecutor)
        self.executor = ThreadPoolExecutor(
            max_workers=1000000,  # Large pool like Java version
            thread_name_prefix="NonDaemonThread"
        )
        self.active_writes = set()
        self.active_writes_lock = threading.Lock()
    
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
    
    def put(self, key: Union[str, bytes, int, float], value: Union[str, bytes, int, float]) -> None:
        """Store data with the given key (non-blocking)"""
        if self.is_shutdown:
            raise RuntimeError("PowerKvCached has been shut down")
        
        key_bytes = self._to_bytes(key)
        value_bytes = self._to_bytes(value)
        
        key_wrapper = ByteArrayWrapper(key_bytes)
        
        with self.cache_lock:
            old_value = self.cache.get(key_wrapper)
            # Update cache immediately
            self.cache[key_wrapper] = value_bytes
        
        # If oldValue is same as new value, no need to update db
        # If oldValue is None, it means this key is being inserted for the first time, so we need to update db
        if old_value is None or old_value != value_bytes:
            # Start background write (non-blocking)
            future = self.executor.submit(self._background_write, key_bytes, value_bytes, key_wrapper)
            
            with self.active_writes_lock:
                self.active_writes.add(future)
            
            # Remove from active writes when done
            future.add_done_callback(lambda f: self._remove_active_write(f))
    
    def _remove_active_write(self, future):
        """Remove completed write from active writes set"""
        with self.active_writes_lock:
            self.active_writes.discard(future)
    
    def _background_write(self, key_bytes: bytes, value_bytes: bytes, key_wrapper: ByteArrayWrapper) -> None:
        """Background write with retry logic"""
        if self.is_shutdown:
            return
        
        try:
            # Retry until success or cache is updated with different value
            while not self.is_shutdown:
                with self.cache_lock:
                    current_cached_value = self.cache.get(key_wrapper)
                
                # If cache is updated with different value, stop this background write
                if current_cached_value is None or current_cached_value != value_bytes:
                    logger.info(f"Cache updated for key, stopping background write: {key_bytes.decode('utf-8', errors='replace')}")
                    return
                
                try:
                    success = self.db.put(key_bytes, value_bytes)
                    if success:
                        logger.info(f"Successfully updated key on PWR Chain: {key_bytes.decode('utf-8', errors='replace')}")
                        return
                    else:
                        logger.warning(f"Failed to update key on PWR Chain, retrying: {key_bytes.decode('utf-8', errors='replace')}")
                        
                        # Check if another thread has already updated the value
                        try:
                            remote_value = self.db.get_value(key_bytes)
                            if remote_value and remote_value == value_bytes:
                                logger.info(f"Value already updated by another process: {key_bytes.decode('utf-8', errors='replace')}")
                                return
                        except Exception:
                            # Ignore errors when checking remote value
                            pass
                        
                        # Wait 10ms before retry (like Java version)
                        time.sleep(0.01)
                        
                except Exception as e:
                    logger.error(f"Error updating key on PWR Chain: {key_bytes.decode('utf-8', errors='replace')}", exc_info=True)
                    # Wait 10ms before retry
                    time.sleep(0.01)
                    
        except Exception as e:
            logger.error(f"Unexpected error in background write: {e}", exc_info=True)
    
    def get_value(self, key: Union[str, bytes, int, float]) -> Optional[bytes]:
        """Retrieve data for the given key"""
        key_bytes = self._to_bytes(key)
        key_wrapper = ByteArrayWrapper(key_bytes)
        
        # Check cache first
        with self.cache_lock:
            cached_value = self.cache.get(key_wrapper)
            if cached_value is not None:
                return cached_value
        
        # If not in cache, fetch from remote
        try:
            value = self.db.get_value(key_bytes)
            if value is not None:
                # Cache the retrieved value
                with self.cache_lock:
                    self.cache[key_wrapper] = value
            return value
        except Exception as e:
            logger.error(f"Error retrieving value: {e}")
            return None
    
    def get_string_value(self, key: Union[str, bytes, int, float]) -> Optional[str]:
        """Retrieve data as string"""
        value = self.get_value(key)
        if value is None:
            return None
        return value.decode('utf-8')
    
    def get_int_value(self, key: Union[str, bytes, int, float]) -> Optional[int]:
        """Retrieve data as integer"""
        value = self.get_value(key)
        if value is None:
            return None
        return int(value.decode('utf-8'))
    
    def get_long_value(self, key: Union[str, bytes, int, float]) -> Optional[int]:
        """Retrieve data as long (same as int in Python)"""
        value = self.get_value(key)
        if value is None:
            return None
        return int(value.decode('utf-8'))
    
    def get_double_value(self, key: Union[str, bytes, int, float]) -> Optional[float]:
        """Retrieve data as float"""
        value = self.get_value(key)
        if value is None:
            return None
        return float(value.decode('utf-8'))
    
    def shutdown(self) -> None:
        """Gracefully shutdown the cached client"""
        logger.info("Shutting down PowerKvCached...")
        self.is_shutdown = True
        
        # Wait for all active writes to complete (max 60 seconds like Java version)
        max_wait_time = 60.0  # 60 seconds
        start_time = time.time()
        
        while len(self.active_writes) > 0 and (time.time() - start_time) < max_wait_time:
            with self.active_writes_lock:
                active_count = len(self.active_writes)
            logger.info(f"Waiting for {active_count} background writes to complete...")
            time.sleep(0.1)
        
        # Shutdown the executor
        self.executor.shutdown(wait=False)
        
        with self.active_writes_lock:
            final_count = len(self.active_writes)
        
        if final_count > 0:
            logger.warning(f"Forced shutdown with {final_count} writes still active")
        else:
            logger.info("All background writes completed")
