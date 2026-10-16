"""Boundary and state-machine tests. Native currency is tested separately."""
import http.client
import importlib.util
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location("companion", Path(__file__).with_name("companion.py"))
c = importlib.util.module_from_spec(spec)
spec.loader.exec_module(c)
GENESIS = "a" * 64
ADDRESS = "G" * 95


class Native:
    def __init__(self):
        self.calls = []
        self.fail_relay = False
        self.fail_pin = False
        self.fail_store = False
        self.observed = False
        self.name = None

    def daemon(self, method, params=None):
        if method == "get_info":
            return {"nettype": "testnet", "height": 40}
        if method == 'get_transactions':
            return {'txs': [{'tx_hash':'c'*64,'in_pool':False,'block_height':20}] if self.observed else []}
        if method == 'get_block':
            return {'block_header':{'height':20},'json':json.dumps({'tx_hashes':['c'*64]})}
        return {"block_header": {"hash": "b" * 64 if self.fail_pin else GENESIS}}

    def __call__(self, method, params=None):
        self.calls.append((method, params or {}))
        if method == "get_address":
            return {"address": ADDRESS}
        if method == "get_balance":
            return {"balance": 1000000000000, "unlocked_balance": 900000000000}
        if method == "get_transfers":
            return {"in": []}
        if method == "validate_address":
            return {"valid": True}
        if method == "transfer":
            return {"amount": params["destinations"][0]["amount"], "fee": 23000000,
                    "tx_hash": "c" * 64, "tx_metadata": "dd" * 100}
        if method == "relay_tx":
            if self.fail_relay:
                raise OSError("Simulated lost transport response")
            return {"tx_hash": "c" * 64}
        if method == "store" and self.fail_store:
            raise c.WalletError("Disk full", 503)
        if method == "get_transfer_by_txid":
            if self.observed:
                return {"transfer": {"txid": "c" * 64, "type": "out"}}
            raise c.WalletError("Not found")
        if method == "query_key":
            return {"key": "disposable words " * 13}
        return {}


class WalletTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.native = Native()
        self.now = [1000]
        self.wallet = c.Wallet(self.native, self.native.daemon, Path(self.temp.name), GENESIS, clock=lambda: self.now[0])
        self.wallet.open_name = "alice"
        self.wallet.backed_up = True

    def test_decimal_boundaries(self):
        for value, amount in [("0.00000000001", 1), ("1", c.ATOMIC), ("184467440.73709551615", (1 << 64) - 1)]:
            self.assertEqual(c.amount_atomic(value), amount)
        for value in ["0", "-1", "1e3", "1.000000000001", "184467440.73709551616", " 1", "01", 1, float("nan")]:
            with self.subTest(value=value), self.assertRaises(c.WalletError):
                c.amount_atomic(value)

    def test_prepare_does_not_relay_and_metadata_never_reaches_ui(self):
        quote = self.wallet.operate("prepare", {"address": ADDRESS, "amount": "1"})
        self.assertNotIn("metadata", json.dumps(quote))
        calls = dict(self.native.calls)
        self.assertTrue(calls["transfer"]["do_not_relay"])
        self.assertFalse(calls["transfer"]["get_tx_key"])
        self.assertNotIn("relay_tx", calls)
        self.assertEqual(quote["totalAtomic"], "100023000000")

    def test_confirm_once_and_bound_to_review(self):
        quote = self.wallet.operate("prepare", {"address": ADDRESS, "amount": "1"})
        with self.assertRaises(c.WalletError):
            self.wallet.operate("confirm", {"id": "wrong"})
        self.assertEqual(self.wallet.operate("confirm", {"id": quote["id"]})["status"], "submitted")
        with self.assertRaises(c.WalletError):
            self.wallet.operate("confirm", {"id": quote["id"]})
        self.assertEqual(sum(m == "relay_tx" for m, _ in self.native.calls), 1)

    def test_ambiguous_relay_is_consumed_without_retry(self):
        quote = self.wallet.operate("prepare", {"address": ADDRESS, "amount": "1"})
        self.native.fail_relay = True
        self.assertEqual(self.wallet.operate("confirm", {"id": quote["id"]})["status"], "unknown")
        with self.assertRaises(c.WalletError):
            self.wallet.operate("confirm", {"id": quote["id"]})
        self.assertEqual(sum(m == "relay_tx" for m, _ in self.native.calls), 1)

    def test_lost_response_survives_restart_and_blocks_new_send(self):
        quote = self.wallet.operate("prepare", {"address": ADDRESS, "amount": "1"})
        self.native.fail_relay = True
        self.wallet.operate("confirm", {"id": quote["id"]})
        reloaded = c.Wallet(self.native, self.native.daemon, self.temp.name, GENESIS)
        reloaded.open_name, reloaded.backed_up = "alice", True
        self.assertEqual(reloaded.state()["lastSend"]["txHash"], quote["txHash"])
        with self.assertRaises(c.WalletError):
            reloaded.operate("prepare", {"address": ADDRESS, "amount": "1"})
        reloaded.operate("refresh", {})
        self.assertFalse(reloaded.send_record()["observed"])
        self.native.observed = True
        reloaded.operate("refresh", {})
        self.assertTrue(reloaded.send_record()["observed"])
        reloaded.operate("prepare", {"address": ADDRESS, "amount": "1"})
        self.assertEqual(sum(m == "relay_tx" for m, _ in self.native.calls), 1)

    def test_payment_record_exists_before_native_relay(self):
        quote = self.wallet.operate("prepare", {"address": ADDRESS, "amount": "1"})
        original = self.wallet.rpc
        def inspect(method, params=None):
            if method == "relay_tx":
                record = self.wallet.send_record()
                self.assertEqual(record["status"], "relaying")
                self.assertEqual(record["txHash"], quote["txHash"])
                self.assertNotIn("metadata", json.dumps(record))
            return original(method, params)
        self.wallet.rpc = inspect
        self.wallet.operate("confirm", {"id": quote["id"]})

    def test_wallet_history_without_matching_node_evidence_stays_unresolved(self):
        quote = self.wallet.operate('prepare', {'address': ADDRESS, 'amount': '1'})
        self.native.fail_relay = True
        self.wallet.operate('confirm', {'id': quote['id']})
        self.native.observed = True
        real_daemon = self.wallet.daemon
        for reply in ({'txs':[]}, {'txs':[{'tx_hash':'d'*64,'in_pool':False,'block_height':20}]},
                      {'txs':[{'tx_hash':'c'*64,'in_pool':True}]}):
            self.wallet.daemon = lambda method, params=None: reply if method == 'get_transactions' else real_daemon(method,params)
            self.wallet.operate('refresh', {})
            self.assertFalse(self.wallet.send_record()['observed'])
        self.wallet.daemon = real_daemon
        self.wallet.operate('refresh', {})
        self.assertTrue(self.wallet.send_record()['observed'])
        self.assertEqual(sum(m == 'relay_tx' for m, _ in self.native.calls), 1)

    def test_store_failure_preserves_submitted_hash(self):
        quote = self.wallet.operate("prepare", {"address": ADDRESS, "amount": "1"})
        self.native.fail_store = True
        result = self.wallet.operate("confirm", {"id": quote["id"]})
        self.assertEqual(result["status"], "submitted")
        self.assertEqual(result["txHash"], quote["txHash"])
        self.assertIn("saving", result["message"])
        self.assertFalse(self.wallet.send_record()["observed"])

    def test_record_failure_prevents_relay(self):
        quote = self.wallet.operate("prepare", {"address": ADDRESS, "amount": "1"})
        def fail(_):
            raise OSError("Disk full")
        self.wallet.save_send_record = fail
        with self.assertRaises(OSError):
            self.wallet.operate("confirm", {"id": quote["id"]})
        self.assertNotIn("relay_tx", dict(self.native.calls))

    def test_corrupt_payment_record_cannot_be_treated_as_reconciled(self):
        quote = self.wallet.operate("prepare", {"address": ADDRESS, "amount": "1"})
        self.native.fail_relay = True
        self.wallet.operate("confirm", {"id": quote["id"]})
        path = Path(self.temp.name) / "alice.last-send.json"
        original = json.loads(path.read_text())
        for change in ({"observed": "false"}, {"observed": True}, {"genesis": "b" * 64},
                       {"amountAtomic": "-1"}, {"totalAtomic": "0"}):
            path.write_text(json.dumps({**original, **change}))
            with self.assertRaises(c.WalletError):
                self.wallet.operate("prepare", {"address": ADDRESS, "amount": "1"})
        path.write_text('{"truncated":')
        with self.assertRaises(c.WalletError):
            self.wallet.send_record()
        self.assertEqual(sum(m == "relay_tx" for m, _ in self.native.calls), 1)

    def test_pending_review_cannot_cross_wallets(self):
        quote = self.wallet.operate("prepare", {"address": ADDRESS, "amount": "1"})
        self.wallet.open_name = "bob"
        with self.assertRaises(c.WalletError):
            self.wallet.operate("confirm", {"id": quote["id"]})
        self.assertNotIn("relay_tx", dict(self.native.calls))
        self.wallet.lock()
        self.assertIsNone(self.wallet.pending)

    def test_directory_cannot_change_network_identity(self):
        with self.assertRaises(c.WalletError):
            c.Wallet(self.native, self.native.daemon, self.temp.name, "b" * 64)

    def test_review_expiry_and_idle_lock(self):
        quote = self.wallet.operate("prepare", {"address": ADDRESS, "amount": "1"})
        self.now[0] += 121
        with self.assertRaises(c.WalletError):
            self.wallet.operate("confirm", {"id": quote["id"]})
        self.now[0] += 301
        self.wallet.expire()
        self.assertIsNone(self.wallet.open_name)
        self.assertIn("close_wallet", dict(self.native.calls))

    def test_identity_checked_again_before_relay(self):
        quote = self.wallet.operate("prepare", {"address": ADDRESS, "amount": "1"})
        self.native.fail_pin = True
        with self.assertRaises(c.WalletError):
            self.wallet.operate("confirm", {"id": quote["id"]})
        self.assertNotIn("relay_tx", dict(self.native.calls))

    def test_cancel_and_backup_gate(self):
        self.wallet.backed_up = False
        with self.assertRaises(c.WalletError):
            self.wallet.operate("prepare", {"address": ADDRESS, "amount": "1"})
        self.wallet.backed_up = True
        self.wallet.operate("prepare", {"address": ADDRESS, "amount": "1"})
        self.wallet.operate("cancel", {})
        self.assertIsNone(self.wallet.pending)
        self.assertNotIn("relay_tx", dict(self.native.calls))

    def test_path_traversal_and_symlinks_refused(self):
        for name in ["../wallet", "/tmp/wallet", ".", "alice.keys", "a/b", "a\\b", ""]:
            with self.assertRaises(c.WalletError):
                self.wallet.filename(name)
        target = Path(self.temp.name) / "outside"
        target.write_text("sentinel")
        try:
            (Path(self.temp.name) / "bad.keys").symlink_to(target)
        except OSError:
            self.skipTest("Host does not permit unprivileged symlinks")
        with self.assertRaises(c.WalletError):
            self.wallet.filename("bad", existing=True)
        self.assertEqual(target.read_text(), "sentinel")


class HTTPTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.native = Native()
        wallet = c.Wallet(self.native, self.native.daemon, self.temp.name, GENESIS)
        self.server = c.Server(wallet)
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.start()
        self.cookie = self.csrf = ""
        self.addCleanup(self.stop)

    def stop(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(5)
        self.temp.cleanup()

    def request(self, path, data=None, headers=None, method="POST"):
        connection = http.client.HTTPConnection(self.server.server_address[0], self.server.server_port, timeout=3)
        body = json.dumps(data if data is not None else {}).encode()
        defaults = {"Host": self.server.origin[7:], "Origin": self.server.origin, "Content-Type": "application/json",
                    "Cookie": self.cookie, "X-Meep-CSRF": self.csrf}
        defaults.update(headers or {})
        connection.request(method, path, body=body if method == "POST" else None, headers=defaults)
        response = connection.getresponse()
        raw = response.read()
        result = (response.status, dict(response.getheaders()), raw)
        connection.close()
        return result

    def session(self):
        status, headers, body = self.request("/api/session", {"token": self.server.bootstrap})
        self.assertEqual(status, 200)
        self.cookie = headers["Set-Cookie"].split(";", 1)[0]
        self.csrf = json.loads(body)["csrf"]
        self.assertIn("HttpOnly", headers["Set-Cookie"])
        self.assertIn("SameSite=Strict", headers["Set-Cookie"])

    def test_unauthenticated_and_cross_origin_requests_rejected(self):
        self.assertEqual(self.request("/api/state")[0], 401)
        self.session()
        for headers in [{"Origin": "https://evil.example"}, {"Host": "evil.example"},
                        {"X-Meep-CSRF": "wrong"}, {"Sec-Fetch-Site": "cross-site"}]:
            with self.subTest(headers=headers):
                self.assertEqual(self.request("/api/state", headers=headers)[0], 403)
        self.assertEqual(self.request("/api/state")[0], 200)

    def test_one_use_capability_no_generic_rpc_no_cors(self):
        old = self.server.bootstrap
        self.session()
        cookie = self.cookie
        self.cookie = ""
        self.assertEqual(self.request("/api/session", {"token": old})[0], 403)
        self.cookie = cookie
        self.assertEqual(self.request("/json_rpc", {"method": "query_key"})[0], 404)
        self.assertEqual(self.request("/api/query_key")[0], 404)
        self.assertEqual(self.request("/api/state", method="OPTIONS")[0], 403)
        _, headers, _ = self.request("/", method="GET")
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertIn("frame-ancestors 'none'", headers["Content-Security-Policy"])
        self.assertNotIn("Access-Control-Allow-Origin", headers)

    def test_absolute_session_expiry(self):
        self.session()
        self.server.created -= 3601
        self.assertEqual(self.request("/api/state")[0], 403)

    def test_adjacent_local_service_host_cannot_use_wallet_session(self):
        self.session()
        self.assertEqual(self.request("/api/state", headers={"Host": "127.0.0.1:" + str(self.server.server_port)})[0], 403)

    def test_reserved_hostname_rejects_non_loopback_resolution(self):
        answers = [(2, 1, 6, '', ('192.168.68.84', 0))]
        with mock.patch.object(c.socket, 'getaddrinfo', return_value=answers):
            with self.assertRaisesRegex(ValueError, 'exclusively to loopback'):
                c.Server(self.server.wallet, host='meep-' + 'a' * 32 + '.localhost')

    def test_busy_operation_and_request_limit(self):
        self.session()
        self.server.request_lock.acquire()
        try:
            self.assertEqual(self.request("/api/state")[0], 409)
        finally:
            self.server.request_lock.release()
        self.assertEqual(self.request("/api/state", {"large": "x" * 16385})[0], 413)


if __name__ == "__main__":
    unittest.main()
