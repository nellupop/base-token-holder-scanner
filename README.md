# Base Token Holder Scanner

A small Python utility for scanning token holders on Base and identifying contract holders that do not look like common Coinbase Smart Wallets or standard account abstraction/proxy wallet deployments.

## What it does

- Fetches token holder addresses from the BaseScan API.
- Checks each holder with `eth_getCode` on a Base RPC endpoint.
- Filters out EOAs.
- Filters out common wallet patterns, including:
  - EIP-1167 minimal proxies
  - proxy-like wallet shells and dispatcher contracts
  - optionally, exact code hashes added to the allow/deny list in the script
- Prints the remaining contract holders as potential custom targets.

## Files

- `base_token_holder_scanner.py` - main scanner
- `requirements.txt` - Python dependency list

## Prerequisites

- Python 3.10+
- A BaseScan API key
- A Base RPC URL from a provider such as:
  - Alchemy
  - Infura
  - any RPC provider that supports Base

## Setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Environment variables

You can pass values through flags or environment variables:

- `BASESCAN_API_KEY` - BaseScan API key
- `BASE_RPC_URL` - Base RPC URL
- `RPC_URL` - fallback RPC URL variable

## Usage

```bash
python base_token_holder_scanner.py \
  --token-address 0xYourTokenContractAddress \
  --basescan-api-key YOUR_BASESCAN_KEY \
  --rpc-url https://base-mainnet.g.alchemy.com/v2/YOUR_KEY
```

Optional flags:

- `--page-size 100` - BaseScan page size per request
- `--max-holders 500` - inspect only the first N holders
- `--output json|text` - print JSON or one address per line

## Output

The script prints a JSON array like this:

```json
[
  {
    "address": "0x...",
    "balance": "123.45",
    "code_hash": "...",
    "code_size_bytes": 1024
  }
]
```

These are the contract holders that were not recognized as common wallet/proxy patterns.

## Notes on wallet filtering

The built-in filters are intentionally conservative. They are designed to remove the common smart-wallet/proxy patterns that tend to generate false positives when hunting for custom on-chain contracts.

If you discover a recurring wallet implementation that should be excluded, add its runtime bytecode hash to the `COMMON_WALLET_CODE_HASHES` set in the script.
