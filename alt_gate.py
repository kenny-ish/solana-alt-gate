#!/usr/bin/env python3
"""Read-only Solana RPC checks. Python 3.10+, standard library only."""

import argparse
import base64
import binascii
import json
import math
import struct
import sys
import urllib.error
import urllib.parse
import urllib.request

ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
SYSVAR_OWNER = "Sysvar1111111111111111111111111111111111111"


def b58encode(raw):
    n = int.from_bytes(raw, "big")
    out = ""
    while n:
        n, digit = divmod(n, 58)
        out = ALPHABET[digit] + out
    return "1" * (len(raw) - len(raw.lstrip(b"\0"))) + out


def pubkey(text):
    if not isinstance(text, str) or not 32 <= len(text) <= 44:
        raise ValueError("public key must be a base58-encoded 32-byte value")
    n = 0
    for char in text:
        if char not in ALPHABET:
            raise ValueError("invalid base58 character")
        n = n * 58 + ALPHABET.index(char)
    raw = b"\0" * (len(text) - len(text.lstrip("1")))
    raw += n.to_bytes((n.bit_length() + 7) // 8, "big")
    if len(raw) != 32:
        raise ValueError("public key must contain 32 bytes")
    return raw


def rpc_call(url, method, params, timeout=15):
    parts = urllib.parse.urlsplit(url)
    if parts.scheme not in ("https", "http") or not parts.netloc:
        raise ValueError("RPC URL must use http or https")
    if not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("timeout must be positive and finite")
    body = json.dumps({"jsonrpc": "2.0", "id": 1,
                       "method": method, "params": params}).encode()
    request = urllib.request.Request(
        url, data=body, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = response.read(1_048_577)
    except (OSError, urllib.error.URLError) as exc:
        raise ValueError("RPC transport failed: " + type(exc).__name__) from None
    if len(payload) > 1_048_576:
        raise ValueError("RPC response exceeds 1 MiB")
    try:
        envelope = json.loads(payload)
    except (ValueError, UnicodeError):
        raise ValueError("RPC returned invalid JSON") from None
    if not isinstance(envelope, dict) or envelope.get("jsonrpc") != "2.0":
        raise ValueError("invalid JSON-RPC envelope")
    if type(envelope.get("id")) is not int or envelope["id"] != 1:
        raise ValueError("JSON-RPC response ID mismatch")
    if "error" in envelope:
        raise ValueError("RPC returned an error; check endpoint access and inputs")
    if "result" not in envelope:
        raise ValueError("JSON-RPC result is missing")
    return envelope["result"]


def account_data(account, owner):
    if not isinstance(account, dict):
        raise ValueError("account does not exist")
    if account.get("owner") != owner or account.get("executable") is not False:
        raise ValueError("unexpected account owner or executable flag")
    data = account.get("data")
    if (not isinstance(data, list) or len(data) != 2 or data[1] != "base64"
            or not isinstance(data[0], str)):
        raise ValueError("expected base64 account data")
    try:
        raw = base64.b64decode(data[0], validate=True)
    except (ValueError, binascii.Error):
        raise ValueError("invalid base64 account data") from None
    if "space" in account and account["space"] != len(raw):
        raise ValueError("account space does not match data length")
    return raw


def snapshot(result):
    if not isinstance(result, dict) or not isinstance(result.get("context"), dict):
        raise ValueError("missing RPC context")
    slot = result["context"].get("slot")
    values = result.get("value")
    if type(slot) is not int or not 0 <= slot < 2**64:
        raise ValueError("invalid context slot")
    if not isinstance(values, list) or len(values) != 2:
        raise ValueError("expected two accounts in one RPC snapshot")
    return slot, values


def parser_base(description):
    parser = argparse.ArgumentParser(description=description)
    parser.add_argument("--rpc", required=True, help="user-supplied JSON-RPC URL")
    parser.add_argument("--commitment", choices=("finalized", "confirmed"),
                        default="finalized")
    parser.add_argument("--timeout", type=float, default=15, help="seconds, default 15")
    return parser


ALT_OWNER = "AddressLookupTab1e1111111111111111111111111"
SLOT_HASHES = "SysvarS1otHashes111111111111111111111111111"
MAX_U64 = 2**64 - 1


def decode_meta(header, account_size):
    """Decode the exact 56-byte metadata prefix, not a synthetic full account."""
    if (len(header) != 56 or account_size < 56 or
            (account_size - 56) % 32 or (account_size - 56) // 32 > 256):
        raise ValueError("invalid lookup-table size")
    tag, deactivation, extended, start, authority_tag = struct.unpack_from(
        "<IQQBB", header)
    count = (account_size - 56) // 32
    if tag != 1 or authority_tag not in (0, 1) or start > count:
        raise ValueError("invalid lookup-table metadata")
    return {"deactivation_slot": deactivation, "last_extended_slot": extended,
            "extension_start": start, "address_count": count,
            "frozen": authority_tag == 0}


def decode_slot_hashes(raw):
    if len(raw) < 8:
        raise ValueError("truncated SlotHashes")
    count = struct.unpack_from("<Q", raw)[0]
    end = 8 + count * 40
    if count > 512 or len(raw) < end or any(raw[end:]):
        raise ValueError("invalid SlotHashes length or padding")
    slots = [struct.unpack_from("<Q", raw, 8 + i * 40)[0] for i in range(count)]
    if any(a <= b for a, b in zip(slots, slots[1:])):
        raise ValueError("SlotHashes must be strictly descending")
    return slots


def evaluate(meta, slot, hashes, indexes):
    extended = meta["last_extended_slot"]
    deactivation = meta["deactivation_slot"]
    if extended > slot or (deactivation != MAX_U64 and deactivation > slot):
        raise ValueError("table metadata is ahead of the snapshot")
    if any(s > slot for s in hashes):
        raise ValueError("SlotHashes is ahead of the snapshot")
    if deactivation == MAX_U64:
        status, cooldown = "active", None
    elif deactivation == slot:
        status, cooldown = "deactivating", 513
    elif deactivation in hashes:
        status, cooldown = "deactivating", 512 - hashes.index(deactivation)
    else:
        status, cooldown = "deactivated", 0
    count = meta["address_count"]
    warmed = count if slot > extended else meta["extension_start"]
    usable = 0 if status == "deactivated" else warmed
    checks = []
    for index in indexes:
        if type(index) is not int or not 0 <= index <= 255:
            raise ValueError("indexes must be integers from 0 to 255")
        if index >= count:
            reason = "out-of-range"
        elif status == "deactivated":
            reason = "inactive"
        elif index >= warmed:
            reason = "warming"
        else:
            reason = "ready"
        checks.append({"index": index, "status": reason})
    passed = (status != "deactivated" and
              (all(c["status"] == "ready" for c in checks) if checks else usable == count))
    return {"status": status, "cooldown_blocks": cooldown,
            "last_extended_slot": extended, "address_count": count,
            "usable_addresses": usable, "warming_addresses": count - warmed,
            "frozen": meta["frozen"], "index_checks": checks,
            "lookup_gate": "pass" if passed else "blocked"}


def inspect_table(rpc, address, indexes=(), commitment="finalized"):
    pubkey(address)
    result = rpc("getMultipleAccounts", [[address, SLOT_HASHES],
                 {"encoding": "base64", "commitment": commitment}])
    slot, values = snapshot(result)
    raw = account_data(values[0], ALT_OWNER)
    meta = decode_meta(raw[:56], len(raw))
    hashes = decode_slot_hashes(account_data(values[1], SYSVAR_OWNER))
    report = evaluate(meta, slot, hashes, indexes)
    return {"table": address, "context_slot": slot, **report}


def main(argv=None, rpc=None):
    parser = parser_base("Check lookup-table lifecycle and index usability.")
    parser.add_argument("table", help="address lookup table public key")
    parser.add_argument("--index", type=int, action="append", default=[],
                        help="zero-based index; repeat for more than one")
    args = parser.parse_args(argv)
    try:
        if any(not 0 <= i <= 255 for i in args.index):
            raise ValueError("indexes must be from 0 to 255")
        call = rpc or (lambda method, params: rpc_call(
            args.rpc, method, params, args.timeout))
        report = inspect_table(call, args.table, args.index, args.commitment)
        print(json.dumps(report, indent=2, sort_keys=True))
        return 0 if report["lookup_gate"] == "pass" else 1
    except ValueError as exc:
        print("error: " + str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
