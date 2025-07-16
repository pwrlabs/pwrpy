from typing import Callable, Optional
from pwrpy.models.Transaction import VidaDataTransaction
import threading
import time
import logging
import signal
import atexit
from threading import Lock


class AtomicBoolean:
    """Thread-safe atomic boolean implementation"""
    def __init__(self, initial_value: bool = False):
        self._value = initial_value
        self._lock = Lock()
    
    def get(self) -> bool:
        with self._lock:
            return self._value
    
    def set(self, value: bool) -> None:
        with self._lock:
            self._value = value
    
    def compare_and_set(self, expected: bool, new_value: bool) -> bool:
        with self._lock:
            if self._value == expected:
                self._value = new_value
                return True
            return False


class AtomicLong:
    """Thread-safe atomic long implementation"""
    def __init__(self, initial_value: int = 0):
        self._value = initial_value
        self._lock = Lock()
    
    def get(self) -> int:
        with self._lock:
            return self._value
    
    def set(self, value: int) -> None:
        with self._lock:
            self._value = value


class VidaTransactionSubscription:
    def __init__(self, 
                rpc: 'PWRPY', # type: ignore
                vida_id: int,
                starting_block: int,
                handler: Callable[['VidaDataTransaction'], None],
                poll_interval: int = 100,
                block_saver: Optional[Callable[[int], None]] = None):
        
        # Set up logger
        self.logger = logging.getLogger(f"{__name__}.VidaTransactionSubscription")
        
        self.rpc = rpc
        self.vida_id = vida_id
        self.starting_block = starting_block
        self.handler = handler
        self.poll_interval = poll_interval
        self.block_saver = block_saver
        
        # Thread-safe atomic state management
        self.latest_checked_block = AtomicLong(starting_block)
        self.running = AtomicBoolean(False)
        self.wants_to_pause = AtomicBoolean(False)
        self.stop = AtomicBoolean(False)
        self.paused = AtomicBoolean(False)
        
        # Thread reference for proper cleanup
        self._thread: Optional[threading.Thread] = None
        
        # Add shutdown hook
        atexit.register(self._shutdown_hook)

    def start(self):
        if self.running.get():
            self.logger.error("VidaTransactionSubscription is already running")
            return
        else:
            self.running.set(True)
            self.wants_to_pause.set(False)
            self.stop.set(False)

        self.latest_checked_block.set(self.starting_block - 1)

        def run():
            while True and not self.stop.get():
                if self.wants_to_pause.get():
                    if not self.paused.get():
                        self.paused.set(True)
                    continue

                # Clear paused flag if we're not wanting to pause
                if not self.wants_to_pause.get() and self.paused.get():
                    self.paused.set(False)

                try:
                    latest_block = self.rpc.get_block_number()
                    
                    if latest_block == self.latest_checked_block.get():
                        continue

                    max_block_to_check = min(latest_block, self.latest_checked_block.get() + 1000)

                    transactions = self.rpc.get_vida_data_transactions(
                        self.latest_checked_block.get() + 1, max_block_to_check, self.vida_id)

                    for txn in transactions:
                        try:
                            self.handler(txn)
                        except Exception as e:
                            self.logger.error(f"Failed to process VIDA transaction: {getattr(txn, 'transaction_hash', 'unknown')} - {e}")

                    self.latest_checked_block.set(max_block_to_check)
                    
                    if self.block_saver is not None:
                        try:
                            self.block_saver(self.latest_checked_block.get())
                        except Exception as e:
                            self.logger.error(f"Failed to save latest checked block: {self.latest_checked_block.get()} - {e}")

                except Exception as e:
                    self.logger.error(f"Failed to fetch VIDA transactions: {e}")
                finally:
                    time.sleep(self.poll_interval / 1000)

            self.running.set(False)

        self._thread = threading.Thread(
            target=run,
            name=f"VidaTransactionSubscription:VIDA-ID-{self.vida_id}",
        )
        self._thread.start()

    def pause(self):
        self.wants_to_pause.set(True)
        
        # Wait until paused is set to True
        while not self.paused.get():
            try:
                time.sleep(0.01)  # Wait until paused is set to True
            except KeyboardInterrupt:
                break

    def resume(self):
        self.wants_to_pause.set(False)

    def stop(self):
        self.pause()
        self.stop.set(True)
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=10)  # Give it a moment to stop

    def is_running(self) -> bool:
        return self.running.get()

    def is_paused(self) -> bool:
        return self.wants_to_pause.get()

    def is_stopped(self) -> bool:
        return self.stop.get()
    
    def get_starting_block(self) -> int:
        return self.starting_block
    
    def get_latest_checked_block(self) -> int:
        return self.latest_checked_block.get()
    
    def set_latest_checked_block(self, block_number: int) -> None:
        """Set the latest checked block number."""
        self.latest_checked_block.set(block_number)
    
    def get_vida_id(self) -> int:
        return self.vida_id
    
    def get_handler(self) -> Callable[['VidaDataTransaction'], None]:
        return self.handler
    
    def get_pwrj(self) -> 'PWRPY':  # type: ignore
        """Get the PWRPY instance."""
        return self.rpc
    
    def _shutdown_hook(self):
        """Graceful shutdown hook."""
        if self.running.get():
            self.logger.info(f"Shutting down VidaTransactionSubscription for VIDA-ID: {self.vida_id}")
            self.stop()
            self.logger.info(f"VidaTransactionSubscription for VIDA-ID: {self.vida_id} has been stopped.")
        