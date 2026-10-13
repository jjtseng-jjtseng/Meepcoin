#!/usr/bin/env python3
"""Finite real native-wallet UI-API rehearsal. Only fresh disposable keys/data.

Optionally pauses for an actual browser transfer after the API currency tests.
No recovery words, passwords, private links or signed metadata enter receipts.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import signal
import socket
import subprocess
import sys
import time
import urllib.request

spec = importlib.util.spec_from_file_location("companion", Path(__file__).with_name("companion.py"))
c = importlib.util.module_from_spec(spec)
spec.loader.exec_module(c)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binaries", type=Path, required=True)
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--browser-seconds", type=int, default=0)
    a = parser.parse_args()
    assert 0 <= a.browser_seconds <= 900
    os.umask(0o077)
    root = a.run_dir.resolve()
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    children, logs = [], []
    started = time.monotonic()
    b = a.binaries.resolve(strict=True)
    port = c.free_port()
    daemon = c.RPC(port)
    password = "fresh-disposable-test-password"
    seeds = []

    def launch(name, argv):
        log = (root / (name + ".log")).open("xb")
        logs.append(log)
        def limits():
            import resource
            os.nice(10)
            resource.setrlimit(resource.RLIMIT_AS, (2 * 1024**3, 2 * 1024**3))
            resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        process = subprocess.Popen(argv, cwd=root, stdin=subprocess.DEVNULL, stdout=log,
                                   stderr=subprocess.STDOUT, start_new_session=True, preexec_fn=limits)
        children.append((name, process))
        return process

    def wait_for(fn, seconds=45):
        until = time.monotonic() + seconds
        while time.monotonic() < until:
            if any(p.poll() is not None for _, p in children):
                raise RuntimeError("Owned child exited early")
            try:
                value = fn()
                if value:
                    return value
            except (OSError, c.WalletError, ValueError):
                pass
            time.sleep(.25)
        raise RuntimeError("Finite wait expired")

    def mine(count, address):
        return daemon("generateblocks", {"amount_of_blocks": count, "wallet_address": address})

    def pool():
        request = urllib.request.Request(f"http://127.0.0.1:{port}/get_transaction_pool", data=b"{}", headers={"Content-Type": "application/json"})
        with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request, timeout=10) as response:
            result = json.load(response)
        return [tx["id_hash"] for tx in result.get("transactions", [])]

    try:
        cfg = root / "empty.conf"
        cfg.write_text("")
        launch("daemon", [str(b / "meepcoind"), "--config-file", str(cfg), "--data-dir", str(root / "chain"),
            "--regtest", "--keep-fakechain", "--fixed-difficulty", "20", "--offline", "--no-zmq",
            "--disable-dns-checkpoints", "--check-updates", "disabled", "--no-igd", "--out-peers", "0", "--in-peers", "0",
            "--rpc-bind-ip", "127.0.0.1", "--rpc-bind-port", str(port), "--rpc-ssl", "disabled",
            "--max-concurrency", "1", "--prep-blocks-threads", "1", "--non-interactive",
            "--log-file", str(root / "node-internal.log"), "--log-level", "0"])
        wait_for(lambda: daemon("get_info"))
        genesis = daemon("get_block_header_by_height", {"height": 0})["block_header"]["hash"]
        wallets = root / "wallets"
        companion = launch("companion", [sys.executable, str(Path(__file__).with_name("companion.py")),
            "--wallet-rpc", str(b / "meepcoin-wallet-rpc"), "--wallet-dir", str(wallets),
            "--daemon-port", str(port), "--genesis", genesis, "--network", "regtest",
            "--seconds", str(max(300, a.browser_seconds + 240))])
        link = wallets / "OPEN_WALLET.html"
        wait_for(lambda: link.exists())
        match = re.search(r'href="(http://127\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+)/#connect=([a-zA-Z0-9_-]+)"', link.read_text())
        assert match
        origin, token = match.groups()
        cookie, csrf = "", ""
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

        def api(action, data=None, expect=200):
            request = urllib.request.Request(origin + "/api/" + action,
                data=json.dumps(data or {}).encode(), headers={"Origin": origin, "Content-Type": "application/json",
                "Cookie": cookie, "X-Meep-CSRF": csrf})
            try:
                response = opener.open(request, timeout=100)
            except urllib.error.HTTPError as error:
                response = error
            with response:
                result = json.load(response)
                assert response.status == expect, (action, response.status, result)
                return result, response.headers

        session, headers = api("session", {"token": token})
        cookie = headers["Set-Cookie"].split(";", 1)[0]
        csrf = session["csrf"]
        token = ""
        alice, _ = api("create", {"name": "alice", "password": password})
        seeds.append(alice.pop("seed"))
        address_a = alice["address"]
        api("backup-confirm", {"confirmed": True})
        api("lock")
        bob, _ = api("create", {"name": "bob", "password": password})
        seed_b = bob.pop("seed")
        seeds.append(seed_b)
        address_b = bob["address"]
        api("backup-confirm", {"confirmed": True})
        api("lock")
        api("open", {"name": "alice", "password": password})
        mine(64, address_a)
        before, _ = api("refresh")
        assert int(before["unlockedAtomic"]) >= c.ATOMIC
        request = {"address": address_b, "amount": "1.00000000000"}
        cancelled, _ = api("prepare", request)
        assert pool() == []
        api("cancel")
        api("confirm", {"id": cancelled["id"]}, expect=409)
        quote, _ = api("prepare", request)
        assert pool() == []
        assert not any("metadata" in key.lower() or "key" in key.lower() for key in quote)
        sent, _ = api("confirm", {"id": quote["id"]})
        assert sent["status"] == "submitted" and sent["txHash"] == quote["txHash"]
        assert pool() == [sent["txHash"]]
        api("confirm", {"id": quote["id"]}, expect=409)
        h0 = daemon("get_info")["height"]
        mine(12, address_a)
        after, _ = api("refresh")
        h1 = daemon("get_info")["height"]
        rewards = sum(daemon("get_block_header_by_height", {"height": h})["block_header"]["reward"] for h in range(h0, h1))
        assert int(after["balanceAtomic"]) == int(before["balanceAtomic"]) + rewards - c.ATOMIC - int(quote["feeAtomic"])
        api("lock")
        bob_state, _ = api("open", {"name": "bob", "password": password})
        assert bob_state["balanceAtomic"] == str(c.ATOMIC)
        reveal, _ = api("backup", {"password": password})
        assert reveal.pop("seed") == seed_b
        api("lock")
        restored, _ = api("restore", {"name": "bob-recovered", "password": password, "seed": seed_b, "restoreHeight": 0})
        assert restored["address"] == address_b and restored["balanceAtomic"] == str(c.ATOMIC)
        api("lock")
        api("open", {"name": "alice", "password": "deliberately-wrong-password"}, expect=400)
        locked, _ = api("state")
        assert locked["opened"] is None
        result = {"status": "REAL_NATIVE_LOCAL_WALLET_API_PASS", "genesis": genesis,
                  "regtestFixedDifficulty": 20, "publicExposure": False, "exactAtomicDecimals": True,
                  "nativeDigestAuthentication": True, "encryptedWalletFiles": True,
                  "prepareAndCancelNeverRelayed": True, "confirmRelaysOnce": True,
                  "amountAtomic": str(c.ATOMIC), "feeAtomic": quote["feeAtomic"], "txHash": sent["txHash"],
                  "exactSenderAccounting": True, "exactRecipientAccounting": True,
                  "recoverySameAddressAndBalance": True, "passwordRequiredForBackup": True,
                  "wrongPasswordRemainsLocked": True, "browser": "NOT_RUN"}
        (root / "NATIVE_API_RESULT.json").write_text(json.dumps(result, indent=2) + "\n")
        if a.browser_seconds:
            # Give the browser its own new one-use capability, using a deliberate
            # process restart. Never share the API test's authenticated session.
            companion.terminate()
            assert companion.wait(timeout=30) == 0
            children.remove(("companion", companion))
            companion = launch("browser-companion", [sys.executable, str(Path(__file__).with_name("companion.py")),
                "--wallet-rpc", str(b / "meepcoin-wallet-rpc"), "--wallet-dir", str(wallets),
                "--daemon-port", str(port), "--genesis", genesis, "--network", "regtest",
                "--seconds", str(a.browser_seconds + 60)])
            wait_for(lambda: link.exists())
            match = re.search(r'href="(http://127\.[0-9]+\.[0-9]+\.[0-9]+:[0-9]+)/#connect=([a-zA-Z0-9_-]+)"', link.read_text())
            assert match
            origin = match.group(1)
            # Private capability stays in its 0600 link file. Safe metadata contains
            # only public addresses, the known disposable password is in test source.
            ready = {"origin": origin, "recipient": address_b, "walletName": "alice",
                     "privateLinkFile": str(link), "deadlineSeconds": a.browser_seconds}
            (root / "BROWSER_READY.json").write_text(json.dumps(ready, indent=2) + "\n")
            print(json.dumps({"status": "BROWSER_READY", "origin": origin, "runDir": str(root)}), flush=True)
            browser_ids = wait_for(pool, a.browser_seconds)
            assert len(browser_ids) == 1
            mine(12, address_a)
            (root / "BROWSER_CONFIRMED.json").write_text(json.dumps({"txHash": browser_ids[0], "confirmed": True}) + "\n")
            wait_for(lambda: (root / "BROWSER_DONE.json").exists(), min(180, a.browser_seconds))
            browser = json.loads((root / "BROWSER_DONE.json").read_text())
            assert browser.get("visibleNativeTransfer") is True
            result["browser"] = browser
        for name, path in [("wallet-core", Path(__file__).with_name("companion.py")),
                           ("wallet-page", Path(__file__).with_name("web") / "app.js")]:
            result[name + "Sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
        # Verify the actual native logs did not expose this run's known secrets.
        forbidden = [password.encode(), *(seed.encode() for seed in seeds)]
        for path in root.rglob("*.log"):
            raw = path.read_bytes()
            assert not any(value in raw for value in forbidden), "Secret detected in native logs"
        result["nativeLogsNoSeedOrPassword"] = True
        (root / "RESULT.json").write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps(result), flush=True)
    finally:
        cleanup = []
        for name, child in reversed(children):
            if child.poll() is None:
                os.killpg(child.pid, signal.SIGTERM)
                try:
                    child.wait(timeout=30)
                except subprocess.TimeoutExpired:
                    os.killpg(child.pid, signal.SIGKILL)
                    child.wait(timeout=10)
            try:
                os.killpg(child.pid, 0)
                empty = False
            except ProcessLookupError:
                empty = True
            cleanup.append({"name": name, "exitCode": child.returncode, "ownedGroupEmpty": empty})
        for log in logs:
            log.close()
        # The companion gives its native child a separate process group. Check
        # those explicit owned identities too, not only the Python parent group.
        for receipt in (root / "wallets").glob("session-*/PROCESS.json"):
            pid = json.loads(receipt.read_text())["nativePid"]
            try:
                os.killpg(pid, 0)
                empty = False
            except ProcessLookupError:
                empty = True
            cleanup.append({"name": "native-wallet-child", "pid": pid, "ownedGroupEmpty": empty})
        (root / "CLEANUP.json").write_text(json.dumps({"processes": cleanup, "seconds": time.monotonic()-started}, indent=2) + "\n")
        assert all(row["ownedGroupEmpty"] for row in cleanup)


if __name__ == "__main__":
    main()
