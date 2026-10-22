import base64
import contextlib
import io
import json
import struct
import unittest
from unittest import mock
import alt_gate as m

# Mainnet RPC capture on 2026-10-10 UTC; account fields checked with jsonParsed.
REAL_ADDRESS = 'E43LrxzrfXQkGwFQvuyFXn9HD4zWPwYxFGKurZxJQUep'
REAL_SLOT = 455201441
REAL_HEADER = 'AQAAAP//////////xdEhGwAAAAC+AVeoxYiVA/klF9FcToPCEDmNrc6I200jPyYzR9ND6H4iAAA='
REAL_SPACE = 6360
EXPECTED = {'address_count': 197, 'last_extended_slot': 455201221, 'extension_start': 190}
REAL_HASH_PREFIX = 'AAIAAAAAAACg0iEbAAAAALuZL6NOOiJUB7xRXqwMwiBow/DJo02+81Apj5FMA+Jh'
HASH_SLOT = 455201440
HASH_VALUE = 'DdJieTfPxt9WkXgW4txmU5YpAPJSnfJoQFmdBy3BYus6'


def table_data(count=3, extended=100, start=1, deactivation=m.MAX_U64, frozen=False):
    header = struct.pack("<IQQBB", 1, deactivation, extended, start, int(not frozen))
    return header.ljust(56, b"\0") + b"\x07" * (32 * count)


def hashes_data(slots):
    return struct.pack("<Q", len(slots)) + b"".join(
        struct.pack("<Q", s) + bytes(32) for s in slots)


def account(raw, owner):
    return {"owner": owner, "executable": False,
            "data": [base64.b64encode(raw).decode(), "base64"], "space": len(raw)}


def fake_rpc(slot=101, table=None):
    result = {"context": {"slot": slot}, "value": [
        account(table if table is not None else table_data(), m.ALT_OWNER),
        account(hashes_data([100, 99]), m.SYSVAR_OWNER)]}
    return mock.Mock(return_value=result)


class AltTests(unittest.TestCase):
    def meta(self, **kwargs):
        raw = table_data(**kwargs)
        return m.decode_meta(raw[:56], len(raw))

    def test_mainnet_header(self):
        # Exact mainnet metadata prefix, not a fabricated full account.
        raw = base64.b64decode(REAL_HEADER)
        meta = m.decode_meta(raw, REAL_SPACE)
        self.assertEqual(meta["address_count"], EXPECTED["address_count"])
        self.assertEqual(meta["last_extended_slot"], EXPECTED["last_extended_slot"])
        self.assertEqual(meta["extension_start"], EXPECTED["extension_start"])
        self.assertEqual(meta["deactivation_slot"], m.MAX_U64)
        result = m.evaluate(meta, REAL_SLOT, [], [0, EXPECTED["address_count"] - 1])
        self.assertEqual(result["usable_addresses"], EXPECTED["address_count"])
        self.assertEqual(result["lookup_gate"], "pass")

    def test_mainnet_slot_hash(self):
        # The first 48 bytes of the real SlotHashes account include Vec length.
        prefix = base64.b64decode(REAL_HASH_PREFIX)
        self.assertEqual(struct.unpack_from("<Q", prefix)[0], 512)
        self.assertEqual(struct.unpack_from("<Q", prefix, 8)[0], HASH_SLOT)
        self.assertEqual(m.b58encode(prefix[16:48]), HASH_VALUE)

    def test_warmup_and_next_slot(self):
        result = m.evaluate(self.meta(), 100, [99], [0, 1, 3])
        self.assertEqual([c["status"] for c in result["index_checks"]],
                         ["ready", "warming", "out-of-range"])
        self.assertEqual(result["usable_addresses"], 1)
        self.assertEqual(m.evaluate(self.meta(), 101, [100], [2])["lookup_gate"], "pass")

    def test_default_checks_all_addresses(self):
        self.assertEqual(m.evaluate(self.meta(), 100, [99], [])["lookup_gate"], "blocked")
        self.assertEqual(m.evaluate(self.meta(), 101, [100], [])["lookup_gate"], "pass")

    def test_cooldown_boundaries(self):
        meta = self.meta(deactivation=100)
        self.assertEqual(m.evaluate(meta, 100, [99], [0])["cooldown_blocks"], 513)
        result = m.evaluate(meta, 102, [101, 100, 99], [0])
        self.assertEqual((result["status"], result["cooldown_blocks"]), ("deactivating", 511))
        self.assertEqual(result["lookup_gate"], "pass")
        result = m.evaluate(meta, 700, [699, 698], [0])
        self.assertEqual((result["status"], result["usable_addresses"]), ("deactivated", 0))
        self.assertEqual(result["index_checks"][0]["status"], "inactive")

    def test_frozen_table_still_usable(self):
        result = m.evaluate(self.meta(frozen=True), 101, [100], [0])
        self.assertTrue(result["frozen"])
        self.assertEqual(result["lookup_gate"], "pass")

    def test_invalid_meta(self):
        for raw in (b"", table_data()[:-1], table_data(count=257),
                    table_data(count=0, start=1), b"\0" * 56):
            with self.assertRaises(ValueError):
                m.decode_meta(raw[:56], len(raw))
        raw = bytearray(table_data())
        raw[21] = 2
        with self.assertRaises(ValueError):
            m.decode_meta(raw[:56], len(raw))

    def test_hashes_validation(self):
        self.assertEqual(m.decode_slot_hashes(hashes_data([100, 98])), [100, 98])
        self.assertEqual(m.decode_slot_hashes(hashes_data([]) + bytes(40)), [])
        for raw in (b"", hashes_data([1, 1]), hashes_data([1, 2]),
                    hashes_data([1])[:-1], struct.pack("<Q", 513), hashes_data([]) + b"x"):
            with self.assertRaises(ValueError):
                m.decode_slot_hashes(raw)

    def test_future_metadata_and_bad_indexes(self):
        for meta, slot, hashes, indexes in [
                (self.meta(), 99, [], []), (self.meta(deactivation=110), 101, [], []),
                (self.meta(), 101, [102], []), (self.meta(), 101, [], [-1]),
                (self.meta(), 101, [], [256]), (self.meta(), 101, [], [True])]:
            with self.assertRaises(ValueError):
                m.evaluate(meta, slot, hashes, indexes)

    def test_one_snapshot_request(self):
        rpc = fake_rpc()
        result = m.inspect_table(rpc, REAL_ADDRESS, [2])
        self.assertEqual(result["lookup_gate"], "pass")
        rpc.assert_called_once_with("getMultipleAccounts", [[REAL_ADDRESS, m.SLOT_HASHES],
                                    {"encoding": "base64", "commitment": "finalized"}])

    def test_cli_exit_codes(self):
        args = ["--rpc", "https://rpc.invalid", REAL_ADDRESS, "--index", "2"]
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(m.main(args, rpc=fake_rpc()), 0)
            self.assertEqual(m.main(args, rpc=fake_rpc(slot=100)), 1)
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(m.main(args + ["--index", "256"], rpc=fake_rpc()), 2)

    def test_empty_table(self):
        result = m.evaluate(self.meta(count=0, start=0), 101, [], [0])
        self.assertEqual(result["index_checks"][0]["status"], "out-of-range")
        self.assertEqual(result["lookup_gate"], "blocked")


class TransportTests(unittest.TestCase):
    def response(self, payload):
        response = mock.MagicMock()
        response.__enter__.return_value.read.return_value = payload
        return response

    def test_transport_success_and_request(self):
        payload = b'{"jsonrpc":"2.0","id":1,"result":{"ok":true}}'
        with mock.patch.object(m.urllib.request, "urlopen", return_value=self.response(payload)) as opened:
            self.assertEqual(m.rpc_call("https://rpc.invalid", "getMultipleAccounts", []), {"ok": True})
        request = opened.call_args.args[0]
        self.assertEqual(json.loads(request.data)["method"], "getMultipleAccounts")

    def test_transport_bad_responses(self):
        cases = [b'{}', b'[]', b'bad', b'\xff',
                 b'{"jsonrpc":"2.0","id":2,"result":0}',
                 b'{"jsonrpc":"2.0","id":1,"error":{"code":-32602}}',
                 b'{"jsonrpc":"2.0","id":1}', b' ' * 1_048_577]
        for payload in cases:
            with self.subTest(payload=payload[:60]):
                with mock.patch.object(m.urllib.request, "urlopen", return_value=self.response(payload)):
                    with self.assertRaises(ValueError):
                        m.rpc_call("https://rpc.invalid", "getMultipleAccounts", [])

    def test_transport_failure_and_validation(self):
        with mock.patch.object(m.urllib.request, "urlopen", side_effect=TimeoutError):
            with self.assertRaises(ValueError):
                m.rpc_call("https://rpc.invalid", "getMultipleAccounts", [])
        for url, timeout in [("file:///tmp/a", 1), ("https://rpc.invalid", 0),
                             ("https://rpc.invalid", float("nan"))]:
            with self.assertRaises(ValueError):
                m.rpc_call(url, "getMultipleAccounts", [], timeout)

    def test_pubkeys(self):
        for raw in (bytes(32), bytes(range(32)), b"\xff" * 32):
            self.assertEqual(m.pubkey(m.b58encode(raw)), raw)
        for value in ("O" * 32, "1" * 31, "1" * 33, "z" * 44):
            with self.assertRaises(ValueError):
                m.pubkey(value)

    def test_account_validation(self):
        valid = {"owner": "owner", "executable": False, "data": ["AA==", "base64"]}
        self.assertEqual(m.account_data(valid, "owner"), b"\0")
        for change in ({"owner": "other"}, {"executable": True},
                       {"data": ["!", "base64"]}, {"data": ["AA==", "jsonParsed"]},
                       {"space": 2}):
            with self.assertRaises(ValueError):
                m.account_data({**valid, **change}, "owner")
        with self.assertRaises(ValueError):
            m.account_data(None, "owner")

    def test_snapshot_validation(self):
        for result in (None, {}, {"context": {"slot": True}, "value": [None, None]},
                       {"context": {"slot": 1}, "value": []}):
            with self.assertRaises(ValueError):
                m.snapshot(result)


if __name__ == "__main__":
    unittest.main()
