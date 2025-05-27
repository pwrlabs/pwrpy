from typing import Callable
from pwrpy.models.Transaction import VidaDataTransaction
import threading
import time

class VidaTransactionSubscription:
    def __init__(self, 
                rpc: 'PWRPY', # type: ignore
                vida_id: int,
                starting_block: int,
                handler: Callable[['VidaDataTransaction'], None],
                poll_interval: int = 100):
        self.rpc = rpc
        self.vida_id = vida_id
        self.starting_block = starting_block
        self.latest_checked_block = starting_block
        self.handler = handler
        self.poll_interval = poll_interval
        
        self.running = threading.Event()
        self.paused = threading.Event()
        self.stopped = threading.Event()

    def start(self):
        if self.running.is_set():
            print("VidaTransactionSubscription is already running")
            return
        else:
            self.running.set()
            self.paused.clear()
            self.stopped.clear()

        def run():
            current_block = self.starting_block

            while not self.stopped.is_set():
                if self.paused.is_set():
                    continue

                try:
                    latest_block = self.rpc.get_block_number()

                    effective_latest_block = latest_block
                    if latest_block > current_block + 1000:
                        effective_latest_block = current_block + 1000
                    
                    if effective_latest_block >= current_block:
                        transactions = self.rpc.get_vida_data_transactions(
                            current_block, effective_latest_block, self.vida_id)

                        for txn in transactions:
                            self.handler(txn)

                        self.latest_checked_block = effective_latest_block
                        current_block = effective_latest_block + 1
                except Exception as e:
                    print(f"Error fetching transactions: {e}")
                finally:
                    time.sleep(self.poll_interval / 1000)
            self.running.clear()
        
        thread = threading.Thread(
            target=run,
            name=f"VidaTransactionSubscription:VIDA-ID-{self.vida_id}",
        )
        thread.start()


    def pause(self):
        self.paused.set()

    def resume(self):
        self.paused.clear()

    def stop(self):
        self.stopped.set()
        self.running.clear()

    def is_running(self) -> bool:
        return self.running.is_set()

    def is_paused(self) -> bool:
        return self.paused.is_set()

    def is_stopped(self) -> bool:
        return self.stopped.is_set()
    
    def get_starting_block(self) -> int:
        return self.starting_block
    
    def get_latest_checked_block(self) -> int:
        return self.latest_checked_block
    
    def get_vida_id(self) -> int:
        return self.vida_id
    
    def get_handler(self) -> Callable[['VidaDataTransaction'], None]:
        return self.handler
    