from typing import Callable, Optional
from pwrpy.models.Transaction import VmDataTransaction
import threading
import time

class VidaTransactionSubscription:
    def __init__(self, 
                rpc: 'PWRPY', 
                vida_id: int, 
                starting_block: int, 
                handler: Callable[['VmDataTransaction'], None],
                poll_interval: int = 100):
        self.rpc = rpc
        self.vida_id = vida_id
        self.starting_block = starting_block
        self.current_block = starting_block
        self.handler = handler
        self.poll_interval = poll_interval
        
        self.running = threading.Event()
        self.paused = threading.Event()
        self.stopped = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start(self):
        if self.running.is_set():
            print("VidaTransactionSubscription is already running")
            return

        self.running.set()
        self.paused.clear()
        self.stopped.clear()

        def run():
            current_block = self.starting_block

            while not self.stopped.is_set():
                if self.paused.is_set():
                    continue

                try:
                    latest_block = self.rpc.get_latest_block_number()
                    effective_latest_block = min(latest_block, current_block + 1000)

                    if effective_latest_block >= current_block:
                        txns = self.rpc.get_vm_data_txns(
                            current_block, 
                            effective_latest_block, 
                            self.vida_id
                        )
                        
                        for txn in txns:
                            try:
                                self.handler(txn)
                            except Exception as e:
                                print(f"Error processing transaction: {e}")

                        current_block = effective_latest_block + 1

                    time.sleep(0.1)
                    
                except Exception as e:
                    print(f"Error in subscription: {e}")
                    time.sleep(0.1)

            self.running.clear()

        self._thread = threading.Thread(
            target=run,
            name=f"VidaTransactionSubscription:VIDA-ID-{self.vida_id}"
        )
        self._thread.daemon = True
        self._thread.start()

    def pause(self):
        self.paused.set()

    def resume(self):
        self.paused.clear()

    def stop(self):
        self.stopped.set()

    def is_running(self) -> bool:
        return self.running.is_set()

    def is_paused(self) -> bool:
        return self.paused.is_set()

    def is_stopped(self) -> bool:
        return self.stopped.is_set()
    
    def get_starting_block(self) -> int:
        return self.starting_block
    
    def get_vida_id(self) -> int:
        return self.vida_id
    
    def get_handler(self) -> Callable[['VmDataTransaction'], None]:
        return self.handler
    