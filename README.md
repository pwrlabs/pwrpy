# PWRPY

PWRPY is a Python library for interacting with the PWR network.
It provides an easy interface for wallet management and sending transactions on PWR.

<div align="center">
<!-- markdownlint-restore -->

[![Pull Requests welcome](https://img.shields.io/badge/PRs-welcome-ff69b4.svg?style=flat-square)](https://github.com/pwrlabs/pwrpy/issues?q=is%3Aissue+is%3Aopen+label%3A%22help+wanted%22)
[![pypi](https://img.shields.io/pypi/v/pwrpy)](https://pypi.org/project/pwrpy/)
<a href="https://github.com/pwrlabs/pwrpy/blob/main/LICENSE/">
  <img src="https://img.shields.io/badge/license-MIT-black">
</a>
<!-- <a href="https://github.com/pwrlabs/pwrpy/stargazers">
  <img src='https://img.shields.io/github/stars/pwrlabs/pwrpy?color=yellow' />
</a> -->
<a href="https://pwrlabs.io/">
  <img src="https://img.shields.io/badge/powered_by-PWR Chain-navy">
</a>
<a href="https://www.youtube.com/@pwrlabs">
  <img src="https://img.shields.io/badge/Community%20calls-Youtube-red?logo=youtube"/>
</a>
<a href="https://twitter.com/pwrlabs">
  <img src="https://img.shields.io/twitter/follow/pwrlabs?style=social"/>
</a>

</div>

## Installation

```bash
# latest official release (main branch)
pip3 install pwrpy
```

## 🌐 Documentation

How to [Guides](https://docs.pwrlabs.io/pwrchain/overview) 🔜 & [API](https://docs.pwrlabs.io/developers/sdks/overview) 💻

Play with [Code Examples](https://github.com/keep-pwr-strong/pwr-examples/) 🎮

## 💫 Getting Started

**Import the library:**

```python
from pwrpy.pwrsdk import PWRPY
from pwrpy.pwrwallet import PWRWallet
```

**Set your rpc and wallet:**

```python
private_key = "0xac0974bec...f80"
pwr = PWRPY("https://pwrrpc.pwrlabs.io/")
wallet = PWRWallet(private_key)
```

**Get wallet address:**

```python
address = wallet.get_address()
```

**Get wallet balance:**

```python
balance = wallet.get_balance()
```

**Get private key:**

```python
pk = wallet.get_private_key()
```

**Transfer PWR tokens:**

```python
response = wallet.transfer_pwr("recipientAddress", 100000)
```

Sending a transcation to the PWR Chain returns a Response object, which specified if the transaction was a success, and returns relevant data.
If the transaction was a success, you can retrieive the transaction hash, if it failed, you can fetch the error.

```python
response = wallet.transfer_pwr("recipientAddress", 100000)
if response.success:
    print("Transfer:", response.__dict__)
else:
    print("FAILED!")
```

**Send data to a VIDA:**

```python
data = "Hello World!"
response = wallet.send_vida_data(123, data.encode())
if response.success:
    print("SendVidaData:", response.__dict__)
else:
    print("FAILED!")
```

### Other Static Calls

**Get RPC Node Url:**

Returns currently set RPC node URL.

```python
url = pwr.get_rpc_node_url()
```

**Get Fee Per Byte: **

Gets the latest fee-per-byte rate.

```python
fee = pwr.get_fee_per_byte()
```

**Get Balance Of Address:**

Gets the balance of a specific address.

```python
balance = pwr.get_balance_of_address('0x...')
```

**Get Nonce Of Address:**

Gets the nonce/transaction count of a specific address.

```python
nonce = pwr.get_nonce_of_address('0x...')
```

**Get VIDA Data:**

```python
start_block = 843500
end_block = 843750
vida_id = 123

transactions = pwr.get_vida_data_txns(start_block, end_block, vida_id)
for txs in transactions:
    print("Data:", txs.data)
```

**Broadcast Txn:**

Broadcasts a signed transaction to the network.

```python
signedTransaction = "..."
broadcast = pwr.broadcast_transaction(signedTransaction)
```

## ✏️ Contributing

If you consider to contribute to this project please read [CONTRIBUTING.md](https://github.com/pwrlabs/pwrpy/blob/main/CONTRIBUTING.md) first.

You can also join our dedicated channel for [pwrpy](https://discord.com/channels/1141787507189624992/1167387492153032735) on the [PWR Chain Discord](https://discord.com/invite/YASmBk9EME)

## 📜 License

Copyright (c) 2025 PWR Labs

Licensed under the [MIT license](https://github.com/pwrlabs/pwrpy/blob/main/LICENSE).
