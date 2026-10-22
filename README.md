# Solana ALT Gate

Check whether an address lookup table and its requested indexes are usable in a single Solana RPC snapshot. It catches same-slot warmup and deactivation cooldown mistakes before a versioned transaction is built.

## Example

Actual mainnet-beta output collected on 2026-10-10 UTC. Later runs will differ.

    python alt_gate.py --rpc https://api.mainnet-beta.solana.com E43LrxzrfXQkGwFQvuyFXn9HD4zWPwYxFGKurZxJQUep --index 106

    {
      "address_count": 178,
      "context_slot": 455201067,
      "cooldown_blocks": null,
      "frozen": false,
      "index_checks": [
        {
          "index": 106,
          "status": "ready"
        }
      ],
      "last_extended_slot": 455200815,
      "lookup_gate": "pass",
      "status": "active",
      "table": "E43LrxzrfXQkGwFQvuyFXn9HD4zWPwYxFGKurZxJQUep",
      "usable_addresses": 178,
      "warming_addresses": 0
    }

## Usage

`python alt_gate.py --rpc URL TABLE [--index N ...] [--commitment finalized|confirmed] [--timeout SECONDS]`

`TABLE` is a lookup-table public key. Repeat `--index` for zero-based indexes from 0 to 255. Without indexes, the gate checks all stored addresses. The default commitment is finalized and the timeout is 15 seconds. Exit codes: 0 means the requested lookup gate passes, 1 means blocked, and 2 means invalid input or unavailable data.

## How it works

One `getMultipleAccounts` call reads the table and SlotHashes at the same bank. The program validates owners and binary layouts. New addresses are unavailable in the extension slot. A deactivating table remains usable while its deactivation slot is retained in SlotHashes.

`cooldown_blocks` follows the runtime counter, not a wall-clock or skipped-slot estimate. Frozen tables can still be used. A passing result covers this snapshot only, not a future transaction or the authority needed to close a table.

The offline tests contain a real mainnet metadata prefix and a SlotHashes prefix captured on 2026-10-10 UTC. Expected fields were checked against RPC `jsonParsed` output. SlotHashes contains bank hashes, not the blockhash returned by `getBlock`.

Layout and lifecycle reference: [Solana lookup-table state](https://raw.githubusercontent.com/solana-labs/solana/master/sdk/program/src/address_lookup_table/state.rs). Python 3.10 or newer is required. No dependencies or keys are needed. MIT licensed.

## Tests

`python -m unittest -v`
