#!/usr/bin/env python3
"""Scan Base token holders and surface contract addresses that do not match common wallet patterns.

The script:
1. Pulls token holders from BaseScan.
2. Checks each holder with eth_getCode against an RPC endpoint.
3. Filters out common wallet patterns such as minimal proxies and other proxy-like AA wallet deployments.
4. Prints candidate custom contract holders.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

import requests
from eth_hash.auto import keccak

BASESCAN_API_URL = "https://api.basescan.org/api"
MINIMAL_PROXY_RUNTIME_RE = re.compile(
    r"^0x363d3d373d3d3d363d73[0-9a-fA-F]{40}5af43d82803e903d91602b57fd5bf3$"
)

# Known or common bytecode/code-hash fingerprints can be added here over time.
# The default list is intentionally conservative: it filters out proxy-like and
# clone-like deployments that are very commonly used by smart wallet factories.
COMMON_WALLET_CODE_HASHES = {
    # Add exact keccak256 hashes of common wallet runtimes here if you want to
    # hard-filter specific implementations observed in the wild.
}


@dataclass(frozen=True)
class Holder:
    address: str
    balance: Optional[str] = None
    raw: Optional[dict] = None


class ScanError(RuntimeError):
    pass


def normalize_address(address: str) -> str:
    address = address.strip()
    if not address.startswith("0x"):
        address = "0x" + address
    if len(address) != 42:
        raise ValueError(f"Invalid address length: {address}")
    return address.lower()


def keccak_hex(bytecode_hex: str) -> str:
    return keccak(bytes.fromhex(bytecode_hex.removeprefix("0x"))).hex()


def fetch_token_holders(
    token_address: str,
    api_key: str,
    page_size: int = 100,
    max_holders: Optional[int] = None,
    timeout: int = 30,
) -> List[Holder]:
    holders: List[Holder] = []
    page = 1

    while True:
        params = {
            "module": "token",
            "action": "tokenholderlist",
            "contractaddress": token_address,
            "page": page,
            "offset": page_size,
            "apikey": api_key,
        }
        response = requests.get(BASESCAN_API_URL, params=params, timeout=timeout)
        response.raise_for_status()
        data = response.json()

        if data.get("status") not in {"1", 1, True}:
            message = data.get("message") or data.get("result") or "Unknown BaseScan error"
            raise ScanError(f"BaseScan request failed: {message}")

        result = data.get("result") or []
        if not isinstance(result, list):
            raise ScanError(f"Unexpected BaseScan result payload: {result!r}")

        for item in result:
            address = item.get("TokenHolderAddress") or item.get("address") or item.get("holderAddress")
            if not address:
                continue
            holders.append(
                Holder(
                    address=normalize_address(address),
                    balance=item.get("TokenHolderQuantity") or item.get("balance"),
                    raw=item,
                )
            )
            if max_holders is not None and len(holders) >= max_holders:
                return holders

        if len(result) < page_size:
            break
        page += 1

    return holders


def rpc_call(rpc_url: str, method: str, params: Sequence[object], timeout: int = 30) -> object:
    payload = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": list(params),
    }
    response = requests.post(rpc_url, json=payload, timeout=timeout)
    response.raise_for_status()
    data = response.json()
    if "error" in data:
        raise ScanError(data["error"].get("message", "RPC error"))
    return data.get("result")


def get_code(rpc_url: str, address: str, timeout: int = 30) -> str:
    result = rpc_call(rpc_url, "eth_getCode", [address, "latest"], timeout=timeout)
    if not isinstance(result, str):
        raise ScanError(f"Unexpected eth_getCode response for {address}: {result!r}")
    return result.lower()


def is_minimal_proxy(bytecode: str) -> bool:
    return bool(MINIMAL_PROXY_RUNTIME_RE.match(bytecode))


def is_proxy_like(bytecode: str) -> bool:
    if bytecode in {"0x", "0x0"}:
        return False

    # EIP-1167 clones are the canonical minimal proxy pattern.
    if is_minimal_proxy(bytecode):
        return True

    # Generic proxy heuristic: small runtime with a DELEGATECALL path.
    # This catches many standard wallet proxy deployments, including common
    # smart-account shells and AA wallet proxies.
    raw = bytecode.removeprefix("0x")
    if len(raw) <= 900 and "5af4" in raw and "f4" in raw:
        # Delegatecall opcode appears in the implementation trampoline.
        return True

    # UUPS / transparent / beacon proxies often expose recognizable dispatcher
    # structures even when the exact implementation differs.
    proxy_markers = [
        "3659cfe6",  # proxiableUUID() selector in many UUPS contexts
        "5c60da1b",  # implementation() selector in some proxy families
        "f851a440",  # admin() selector
    ]
    if any(marker in raw for marker in proxy_markers):
        return True

    return False


def is_common_wallet(bytecode: str) -> bool:
    if bytecode in {"0x", "0x0"}:
        return False

    if is_minimal_proxy(bytecode):
        return True

    if is_proxy_like(bytecode):
        return True

    code_hash = keccak_hex(bytecode)
    if code_hash in COMMON_WALLET_CODE_HASHES:
        return True

    return False


def scan(
    token_address: str,
    basescan_api_key: str,
    rpc_url: str,
    page_size: int,
    max_holders: Optional[int],
) -> List[Dict[str, object]]:
    holders = fetch_token_holders(
        token_address=token_address,
        api_key=basescan_api_key,
        page_size=page_size,
        max_holders=max_holders,
    )

    interesting: List[Dict[str, object]] = []
    seen_codes: Dict[str, str] = {}

    for holder in holders:
        code = seen_codes.get(holder.address)
        if code is None:
            code = get_code(rpc_url, holder.address)
            seen_codes[holder.address] = code

        if code in {"0x", "0x0"}:
            continue

        if is_common_wallet(code):
            continue

        interesting.append(
            {
                "address": holder.address,
                "balance": holder.balance,
                "code_hash": keccak(bytes.fromhex(code.removeprefix("0x"))).hex(),
                "code_size_bytes": len(code.removeprefix("0x")) // 2,
            }
        )

    return interesting


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Identify contract holders on Base that are not standard wallet/proxy patterns.",
    )
    parser.add_argument("--token-address", required=True, help="Base token contract address to scan")
    parser.add_argument(
        "--basescan-api-key",
        default=os.getenv("BASESCAN_API_KEY"),
        help="BaseScan API key (or set BASESCAN_API_KEY)",
    )
    parser.add_argument(
        "--rpc-url",
        default=os.getenv("BASE_RPC_URL") or os.getenv("RPC_URL"),
        help="Base RPC URL for eth_getCode (or set BASE_RPC_URL / RPC_URL)",
    )
    parser.add_argument("--page-size", type=int, default=100, help="BaseScan page size")
    parser.add_argument(
        "--max-holders",
        type=int,
        default=None,
        help="Optional cap on the number of holders to inspect",
    )
    parser.add_argument(
        "--output",
        choices=["json", "text"],
        default="json",
        help="Output format",
    )
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.basescan_api_key:
        parser.error("--basescan-api-key or BASESCAN_API_KEY is required")
    if not args.rpc_url:
        parser.error("--rpc-url or BASE_RPC_URL/RPC_URL is required")

    token_address = normalize_address(args.token_address)

    try:
        results = scan(
            token_address=token_address,
            basescan_api_key=args.basescan_api_key,
            rpc_url=args.rpc_url,
            page_size=args.page_size,
            max_holders=args.max_holders,
        )
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if args.output == "json":
        print(json.dumps(results, indent=2))
    else:
        for row in results:
            print(row["address"])

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
