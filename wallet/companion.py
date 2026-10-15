#!/usr/bin/env python3
"""Single-user loopback wallet UI. Never deploy this service on a public host.

The native wallet owns encryption, keys and signing. This process accepts only
same-origin, authenticated UI operations, not arbitrary wallet RPC methods.
"""
import argparse
import hashlib
import hmac
import http.client
import http.cookies
import http.server
import ipaddress
import json
import os
import platform
from pathlib import Path
import re
import secrets
import signal
import socket
import stat
import subprocess
import threading
import time
import urllib.error
import urllib.request

ATOMIC = 100_000_000_000
MAX_AMOUNT = (1 << 64) - 1
SLUG = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_-]{0,47}\Z")
HASH = re.compile(r"[0-9a-f]{64}\Z")
ASSETS = {"/": ("index.html", "text/html; charset=utf-8"),
          "/app.js": ("app.js", "text/javascript; charset=utf-8"),
          "/style.css": ("style.css", "text/css; charset=utf-8")}


class WalletError(Exception):
    def __init__(self, code, status=400):
        self.code, self.status = code, status


def amount_atomic(value):
    if not isinstance(value, str) or not re.fullmatch(r"(?:0|[1-9][0-9]{0,8})(?:\.[0-9]{1,11})?", value):
        raise WalletError("Use a positive decimal amount with at most 11 decimal places.")
    whole, _, fraction = value.partition(".")
    result = int(whole) * ATOMIC + int(fraction.ljust(11, "0") or "0")
    if not 0 < result <= MAX_AMOUNT:
        raise WalletError("Amount is outside the supported range.")
    return result


def private_directory(path):
    path = Path(path).absolute()
    if path.is_symlink():
        raise WalletError("Wallet directory must not be a symlink.")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if os.name != "nt" and (path.stat().st_uid != os.getuid() or stat.S_IMODE(path.stat().st_mode) & 0o077):
        raise WalletError("Wallet directory must be owned by you with mode 0700.")
    return path.resolve(strict=True)


class RPC:
    def __init__(self, port, username=None, password=None):
        self.port = port
        self.url = f"http://127.0.0.1:{port}/json_rpc"
        self.auth = None
        if username:
            manager = urllib.request.HTTPPasswordMgrWithDefaultRealm()
            manager.add_password(None, self.url, username, password)
            self.auth = urllib.request.HTTPDigestAuthHandler(manager)

    def __call__(self, method, params=None):
        payload = json.dumps({"jsonrpc": "2.0", "id": "local-wallet", "method": method, "params": params or {}}).encode()
        request = urllib.request.Request(self.url, data=payload, headers={"Content-Type": "application/json"})
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=90)
        try:
            headers = {"Content-Type": "application/json"}
            connection.request("POST", "/json_rpc", payload, headers)
            response = connection.getresponse()
            raw = response.read(4 * 1024 * 1024 + 1)
            if response.status == 401 and self.auth:
                # Epee's Digest nonce belongs to this TCP connection. urllib's
                # automatic retry opens a new connection and makes it stale.
                # Use stdlib Digest construction, with the offered MD5 challenge,
                # on this same connection. Do not implement signing cryptography.
                challenges = response.headers.get_all("WWW-Authenticate", [])
                challenge = next((value for value in challenges if re.search(r"algorithm=MD5(?:,|$)", value)), None)
                if not challenge:
                    raise WalletError("Unsupported native authentication challenge.", 502)
                scheme, fields = challenge.split(" ", 1)
                if scheme.lower() != "digest":
                    raise WalletError("Native Digest authentication required.", 502)
                parsed = urllib.request.parse_keqv_list(urllib.request.parse_http_list(fields))
                headers["Authorization"] = "Digest " + self.auth.get_authorization(request, parsed)
                connection.request("POST", "/json_rpc", payload, headers)
                response = connection.getresponse()
                raw = response.read(4 * 1024 * 1024 + 1)
            if response.status != 200:
                raise WalletError("Native authentication or transport failed.", 503)
            if len(raw) > 4 * 1024 * 1024:
                raise WalletError("Native response too large.", 502)
            result = json.loads(raw)
        except (OSError, ValueError, http.client.HTTPException):
            raise WalletError("Native wallet or node is unavailable. No automatic send retry.", 503) from None
        finally:
            connection.close()
        if "error" in result:
            # Native errors can echo input, including a seed or password. Never forward them.
            raise WalletError(f"Native operation rejected (code {int(result['error'].get('code', -1))}).")
        if not isinstance(result.get("result"), dict):
            raise WalletError("Invalid native response.", 502)
        return result["result"]


class Wallet:
    def __init__(self, rpc, daemon, directory, genesis, network="testnet", clock=time.monotonic):
        if not HASH.fullmatch(genesis):
            raise ValueError("Pinned genesis is required")
        self.rpc, self.daemon, self.directory = rpc, daemon, Path(directory)
        self.genesis, self.network, self.clock = genesis, network, clock
        identity = self.directory / "NETWORK.json"
        expected_identity = {"genesis": genesis, "network": network}
        if identity.is_symlink():
            raise WalletError("Symlink network identity refused.")
        if identity.exists():
            if json.loads(identity.read_text()) != expected_identity:
                raise WalletError("This wallet directory belongs to a different genesis or network.")
        else:
            if any(self.directory.glob("*.keys")):
                raise WalletError("Existing unbound wallet files are refused. Use a new companion directory.")
            with identity.open("x") as out:
                json.dump(expected_identity, out)
            identity.chmod(0o600)
        self.open_name = None
        self.pending = None
        self.last_activity = clock()
        self.backed_up = False
        self.mutex = threading.RLock()

    def backup_marker(self):
        return self.directory / (self.open_name + ".backup-confirmed")

    def send_record(self):
        if not self.open_name:
            return None
        path = self.directory / (self.open_name + ".last-send.json")
        if path.is_symlink():
            raise WalletError("Symlink payment record refused.")
        if not path.exists():
            return None
        record = json.loads(path.read_text())
        if record.get("wallet") != self.open_name or not HASH.fullmatch(record.get("txHash", "")):
            raise WalletError("Invalid local payment record. Sending is blocked.", 503)
        return record

    def save_send_record(self, record):
        # Write before relay, so an interrupted response or companion restart
        # cannot erase the hash. This contains public payment details, no keys,
        # passwords, recovery words or signed transaction metadata.
        path = self.directory / (self.open_name + ".last-send.json")
        if path.is_symlink():
            raise WalletError("Symlink payment record refused.")
        temporary = path.with_name(path.name + "." + secrets.token_hex(8))
        try:
            with temporary.open("x") as out:
                temporary.chmod(0o600)
                json.dump(record, out)
                out.flush()
                os.fsync(out.fileno())
            os.replace(temporary, path)
            if os.name == "posix":
                fd = os.open(self.directory, os.O_RDONLY)
                try:
                    os.fsync(fd)
                finally:
                    os.close(fd)
        finally:
            temporary.unlink(missing_ok=True)

    def reconcile_send(self):
        record = self.send_record()
        if record and not record.get("observed"):
            try:
                transfer = self.rpc("get_transfer_by_txid", {"txid": record["txHash"]})["transfer"]
            except (WalletError, KeyError):
                return
            if transfer.get("txid") == record["txHash"] and transfer.get("type") in ("out", "pending", "failed"):
                record.update(observed=True, status=transfer["type"])
                self.save_send_record(record)

    def pin(self):
        info = self.daemon("get_info")
        header = self.daemon("get_block_header_by_height", {"height": 0})["block_header"]
        expected = {"testnet": "testnet", "regtest": "fakechain"}[self.network]
        if header["hash"] != self.genesis or info.get("nettype") != expected or info.get("offline") is False and self.network == "regtest":
            raise WalletError("Node identity differs from the pinned wallet network.", 503)
        return info

    def filename(self, name, existing=False):
        if not isinstance(name, str) or not SLUG.fullmatch(name):
            raise WalletError("Wallet name must be 1-48 letters, digits, underscores or hyphens.")
        path = self.directory / name
        for target in (path, self.directory / (name + ".keys")):
            if target.is_symlink():
                raise WalletError("Symlink wallet files are refused.")
        if existing and not (self.directory / (name + ".keys")).is_file():
            raise WalletError("Wallet does not exist.")
        if not existing and (path.exists() or (self.directory / (name + ".keys")).exists()):
            raise WalletError("Choose a new wallet name; existing files are never overwritten.")
        return name

    def password(self, value, creating=False):
        if not isinstance(value, str) or not 1 <= len(value) <= 256 or "\0" in value:
            raise WalletError("Enter a wallet password.")
        if creating and len(value) < 12:
            raise WalletError("Use a wallet password of at least 12 characters.")
        return value

    def lock(self):
        self.pending = None
        if self.open_name is not None:
            try:
                self.rpc("store")
            finally:
                self.rpc("close_wallet")
                self.open_name = None
                self.backed_up = False

    def expire(self):
        with self.mutex:
            if self.open_name and self.clock() - self.last_activity >= 300:
                self.lock()
            if self.pending and self.clock() >= self.pending["expires"]:
                self.pending = None

    def state(self):
        wallets = sorted(p.name[:-5] for p in self.directory.glob("*.keys") if p.is_file() and not p.is_symlink() and SLUG.fullmatch(p.name[:-5]))
        result = {"wallets": wallets, "opened": self.open_name, "network": self.network,
                  "genesis": self.genesis, "backupConfirmed": self.backed_up,
                  "idleLockSeconds": max(0, int(300 - (self.clock() - self.last_activity))),
                  "pendingReviewId": self.pending["quote"]["id"] if self.pending else None,
                  "lastSend": self.send_record(), "custody": "local-native-wallet"}
        if self.open_name:
            info = self.pin()
            address = self.rpc("get_address")["address"]
            balance = self.rpc("get_balance")
            result.update(address=address, balanceAtomic=str(balance["balance"]),
                          unlockedAtomic=str(balance["unlocked_balance"]), height=info["height"])
            transfers = self.rpc("get_transfers", {"in": True, "out": True, "pending": True, "failed": True, "pool": True})
            result["transfers"] = [{"kind": kind, "txHash": t["txid"], "amountAtomic": str(t["amount"]),
                                    "feeAtomic": str(t.get("fee", 0)), "height": t.get("height", 0),
                                    "confirmations": t.get("confirmations", 0)}
                                   for kind, rows in transfers.items() if kind in ("in", "out", "pending", "failed", "pool")
                                   for t in rows][-100:]
        return result

    def operate(self, action, data):
        with self.mutex:
            self.expire()
            if action == "state":
                return self.state()
            self.last_activity = self.clock()
            if action == "lock":
                self.lock()
                return {"locked": True}
            if action in ("create", "restore", "open"):
                self.pin()
                if self.open_name:
                    raise WalletError("Lock the current wallet first.")
                self.pending = None
                name = self.filename(data.get("name"), existing=action == "open")
                password = self.password(data.get("password"), creating=action != "open")
                if action == "create":
                    self.rpc("create_wallet", {"filename": name, "password": password, "language": "English"})
                elif action == "restore":
                    seed = data.get("seed")
                    if not isinstance(seed, str) or not re.fullmatch(r"[a-zA-Z ]{30,800}", seed):
                        raise WalletError("Enter the recovery words in order.")
                    height = data.get("restoreHeight", 0)
                    if not isinstance(height, int) or isinstance(height, bool) or not 0 <= height <= 0xffffffff:
                        raise WalletError("Restore height is invalid.")
                    self.rpc("restore_deterministic_wallet", {"filename": name, "password": password,
                             "seed": seed, "restore_height": height, "language": "English", "autosave_current": False})
                else:
                    self.rpc("open_wallet", {"filename": name, "password": password})
                self.open_name = name
                marker = self.backup_marker()
                self.backed_up = action == "restore" or marker.is_file() and not marker.is_symlink()
                if action == "create":
                    # Recovery words are delivered only to this authenticated loopback UI.
                    return {"created": name, "seed": self.rpc("query_key", {"key_type": "mnemonic"})["key"],
                            "address": self.rpc("get_address")["address"]}
                self.rpc("refresh")
                self.reconcile_send()
                return self.state()
            if not self.open_name:
                raise WalletError("Unlock a wallet first.")
            if action == "backup-confirm":
                if data.get("confirmed") is not True:
                    raise WalletError("Confirm that you recorded the recovery words offline.")
                self.backed_up = True
                marker = self.backup_marker()
                if marker.is_symlink():
                    raise WalletError("Symlink backup marker refused.")
                if not marker.exists():
                    with marker.open("x") as out:
                        out.write("Recovery words confirmed offline by this local user.\n")
                    marker.chmod(0o600)
                return {"backupConfirmed": True}
            if action == "backup":
                password = self.password(data.get("password"))
                name = self.open_name
                self.lock()
                self.rpc("open_wallet", {"filename": name, "password": password})
                self.open_name = name
                self.backed_up = self.backup_marker().is_file() and not self.backup_marker().is_symlink()
                return {"seed": self.rpc("query_key", {"key_type": "mnemonic"})["key"]}
            if action == "refresh":
                self.pin()
                self.rpc("refresh")
                self.reconcile_send()
                return self.state()
            if action == "prepare":
                self.pin()
                previous = self.send_record()
                if previous and not previous.get("observed"):
                    raise WalletError("Previous payment outcome is unresolved. Refresh and check its saved hash before sending again.", 409)
                if not self.backed_up:
                    raise WalletError("Record and confirm your recovery words first.")
                if self.pending:
                    raise WalletError("Cancel or confirm the existing review first.")
                address = data.get("address")
                if not isinstance(address, str) or not re.fullmatch(r"[1-9A-HJ-NP-Za-km-z]{90,120}", address):
                    raise WalletError("Destination address is invalid.")
                validation = self.rpc("validate_address", {"address": address, "any_net_type": False, "allow_openalias": False})
                if validation.get("valid") is not True:
                    raise WalletError("Destination is invalid for this network.")
                amount = amount_atomic(data.get("amount"))
                tx = self.rpc("transfer", {"destinations": [{"address": address, "amount": amount}],
                     "account_index": 0, "priority": 0, "ring_size": 16, "do_not_relay": True,
                     "get_tx_metadata": True, "get_tx_key": False, "get_tx_hex": False})
                if tx.get("amount") != amount or not HASH.fullmatch(tx.get("tx_hash", "")) or not isinstance(tx.get("fee"), int) or tx["fee"] <= 0:
                    raise WalletError("Native transaction review was inconsistent.", 502)
                metadata = tx.get("tx_metadata", "")
                if not isinstance(metadata, str) or not re.fullmatch(r"[0-9a-fA-F]{2,2000000}", metadata):
                    raise WalletError("Native transaction metadata is invalid.", 502)
                quote = {"id": secrets.token_hex(24), "address": address, "amountAtomic": str(amount),
                         "feeAtomic": str(tx["fee"]), "totalAtomic": str(amount + tx["fee"]),
                         "txHash": tx["tx_hash"], "expiresInSeconds": 120}
                self.pending = {"quote": quote, "metadata": metadata, "expires": self.clock() + 120, "wallet": self.open_name}
                return quote
            if action == "cancel":
                self.pending = None
                return {"cancelled": True}
            if action == "confirm":
                self.pin()
                pending = self.pending
                if not pending or pending["wallet"] != self.open_name or not hmac.compare_digest(str(data.get("id", "")), pending["quote"]["id"]):
                    raise WalletError("Transaction review expired or was already used.", 409)
                self.pending = None  # Consume before RPC: an uncertain relay is never retried automatically.
                record = {key: pending["quote"][key] for key in ("txHash", "address", "amountAtomic", "totalAtomic")}
                record.update(wallet=self.open_name, status="relaying", observed=False)
                self.save_send_record(record)  # Failure here means relay has NOT happened.
                try:
                    tx = self.rpc("relay_tx", {"hex": pending["metadata"]})
                    if tx.get("tx_hash") != pending["quote"]["txHash"]:
                        raise WalletError("Unexpected relay identity.", 502)
                    record["status"] = "submitted"
                    message = "Submitted; awaiting canonical confirmation."
                    try:
                        self.rpc("store")
                    except Exception:
                        message = "Submitted, but saving the local wallet failed. Retain this hash and refresh before continuing."
                except Exception:
                    record["status"] = "unknown"
                    message = "Relay outcome is uncertain. Refresh and check this saved hash before making another transfer."
                try:
                    self.save_send_record(record)
                except Exception:
                    message += " Payment record update failed; the pre-relay hash remains recorded."
                return {"status": record["status"], "txHash": record["txHash"], "message": message}
            raise WalletError("Unknown operation.", 404)


class Server(http.server.ThreadingHTTPServer):
    daemon_threads = False
    request_queue_size = 8
    allow_reuse_address = False

    def __init__(self, wallet, port=0, lifetime=1800, host=None):
        self.wallet = wallet
        self.bootstrap = secrets.token_urlsafe(32)
        self.session, self.csrf = None, None
        self.created = time.monotonic()
        self.bootstrap_expires = self.created + 120
        self.lifetime = lifetime
        self.request_lock = threading.Lock()
        self.slots = threading.BoundedSemaphore(8)
        # Cookies have no port isolation. Give this local app a separate host
        # cookie jar instead of sharing credentials with every 127.0.0.1 app.
        if host is None and platform.system() == "Darwin":
            # macOS does not bind arbitrary 127/8 addresses without an admin alias.
            # A unique reserved localhost name preserves host-only cookie isolation.
            host = "meep-" + secrets.token_hex(16) + ".localhost"
        host = host or f"127.77.{secrets.randbelow(254)+1}.{secrets.randbelow(254)+1}"
        if re.fullmatch(r"meep-[0-9a-f]{32}\.localhost", host):
            addresses = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
            if not addresses or any(not ipaddress.ip_address(row[4][0]).is_loopback for row in addresses):
                raise ValueError("Reserved wallet hostname must resolve exclusively to loopback")
            bind_host = "127.0.0.1"
        else:
            if not ipaddress.ip_address(host).is_loopback:
                raise ValueError("Only loopback wallet hosts are allowed")
            bind_host = host
        super().__init__((bind_host, port), Handler)
        self.origin = f"http://{host}:{self.server_port}"
        self.cookie_name = "meep_local_" + str(self.server_port)
        self.assets = {route: ((Path(__file__).parent / "web" / filename).read_bytes(), mime)
                       for route, (filename, mime) in ASSETS.items()}

    def process_request(self, request, client_address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.slots.release()

    def valid_cookie(self, headers):
        try:
            cookie = http.cookies.SimpleCookie(headers.get("Cookie", ""))
            value = cookie[self.cookie_name].value
        except (KeyError, http.cookies.CookieError):
            return False
        return self.session is not None and hmac.compare_digest(value, self.session)


class Handler(http.server.BaseHTTPRequestHandler):
    server_version = "MeepCoinLocal/1"
    sys_version = ""

    def setup(self):
        super().setup()
        self.connection.settimeout(5)
        # Socket timeout alone permits a byte-at-a-time slow sender forever.
        self.read_deadline = threading.Timer(5, self.expire_read)
        self.read_deadline.daemon = True
        self.read_deadline.start()

    def expire_read(self):
        try:
            self.connection.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass

    def finish(self):
        self.read_deadline.cancel()
        super().finish()

    def log_message(self, *_):
        pass  # Never log request paths, credentials, recovery words or RPC bodies.

    def reply(self, status, data, mime="application/json", cookie=None):
        raw = data if isinstance(data, bytes) else json.dumps(data).encode()
        self.send_response(status)
        for name, value in {"Content-Type": mime, "Content-Length": str(len(raw)),
            "Cache-Control": "no-store", "Pragma": "no-cache", "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer", "Cross-Origin-Resource-Policy": "same-origin",
            "Cross-Origin-Opener-Policy": "same-origin", "X-Frame-Options": "DENY",
            "Content-Security-Policy": "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; worker-src 'none'",
            "Permissions-Policy": "camera=(), microphone=(), geolocation=()", "Connection": "close"}.items():
            self.send_header(name, value)
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(raw)
        self.close_connection = True

    def boundary(self, post=False):
        if not ipaddress.ip_address(self.client_address[0]).is_loopback or self.headers.get_all("Host") != [self.server.origin[7:]]:
            raise WalletError("Local host required.", 403)
        if time.monotonic() - self.server.created >= self.server.lifetime:
            raise WalletError("Local wallet session expired. Restart the companion deliberately.", 403)
        if self.headers.get("Sec-Fetch-Site") not in (None, "none", "same-origin"):
            raise WalletError("Cross-site requests are refused.", 403)
        if post and self.headers.get_all("Origin") != [self.server.origin]:
            raise WalletError("Same-origin request required.", 403)
        if not post and self.headers.get("Origin") not in (None, self.server.origin):
            raise WalletError("Same-origin request required.", 403)

    def do_GET(self):
        try:
            self.read_deadline.cancel()
            self.boundary()
            if self.path in self.server.assets:
                raw, mime = self.server.assets[self.path]
                self.reply(200, raw, mime)
            else:
                raise WalletError("Not found.", 404)
        except WalletError as error:
            self.reply(error.status, {"error": error.code})

    def do_POST(self):
        acquired = False
        try:
            if self.headers.get("Transfer-Encoding") or len(self.headers.get_all("Content-Length", [])) != 1:
                raise WalletError("Explicit request size required.", 400)
            if self.headers.get("Content-Type") != "application/json":
                raise WalletError("JSON required.", 415)
            try:
                size = int(self.headers["Content-Length"])
            except ValueError:
                raise WalletError("Invalid request size.") from None
            if not 0 < size <= 16384:
                # Drain only a small bounded oversized body so clients can read
                # the 413 instead of a TCP reset caused by unread request bytes.
                if 0 < size <= 65536:
                    self.rfile.read(size)
                raise WalletError("Request too large.", 413)
            raw = self.rfile.read(size)
            self.read_deadline.cancel()
            if len(raw) != size:
                raise WalletError("Incomplete request.")
            self.boundary(post=True)
            if self.path != "/api/session" and not self.server.valid_cookie(self.headers):
                raise WalletError("Open the private companion link to connect.", 401)
            if self.path != "/api/session" and (not self.server.csrf or not hmac.compare_digest(self.headers.get("X-Meep-CSRF", ""), self.server.csrf)):
                raise WalletError("Session confirmation required.", 403)
            data = json.loads(raw)
            if not isinstance(data, dict):
                raise WalletError("JSON object required.")
            acquired = self.server.request_lock.acquire(blocking=False)
            if not acquired:
                raise WalletError("Another wallet operation is in progress.", 409)
            if self.path == "/api/session":
                if self.server.valid_cookie(self.headers):
                    self.reply(200, {"csrf": self.server.csrf})
                    return
                token = data.get("token", "")
                if time.monotonic() >= self.server.bootstrap_expires or not self.server.bootstrap or not isinstance(token, str) or not hmac.compare_digest(token, self.server.bootstrap):
                    raise WalletError("Private connection link is invalid or already used.", 403)
                self.server.bootstrap = None
                self.server.session, self.server.csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
                cookie = f"{self.server.cookie_name}={self.server.session}; HttpOnly; SameSite=Strict; Path=/"
                self.reply(200, {"csrf": self.server.csrf}, cookie=cookie)
                return
            if not re.fullmatch(r"/api/(state|create|restore|open|lock|backup|backup-confirm|refresh|prepare|cancel|confirm)", self.path):
                raise WalletError("Not found.", 404)
            self.reply(200, self.server.wallet.operate(self.path[5:], data))
        except WalletError as error:
            self.reply(error.status, {"error": error.code})
        except (ValueError, TypeError, KeyError):
            self.reply(400, {"error": "Malformed operation or native response."})
        except Exception:
            self.reply(500, {"error": "Local wallet operation failed. No automatic retry."})
        finally:
            if acquired:
                self.server.request_lock.release()

    def do_OPTIONS(self):
        self.reply(403, {"error": "Cross-origin access is not supported."})


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wallet-rpc", type=Path, required=True)
    parser.add_argument("--wallet-dir", type=Path, required=True)
    parser.add_argument("--daemon-port", type=int, required=True)
    parser.add_argument("--genesis", required=True)
    parser.add_argument("--network", choices=("testnet", "regtest"), default="testnet")
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--host", help="Loopback host; defaults to an isolated numeric host or unique macOS localhost name")
    parser.add_argument("--seconds", type=int, default=1800)
    args = parser.parse_args()
    if not 60 <= args.seconds <= 3600 or not 1 <= args.daemon_port <= 65535 or not 0 <= args.port <= 65535:
        parser.error("Invalid port or lifetime (60-3600 seconds)")
    os.umask(0o077)
    directory = private_directory(args.wallet_dir)
    executable = args.wallet_rpc.resolve(strict=True)
    run = directory / ("session-" + secrets.token_hex(8))
    run.mkdir(mode=0o700)
    port = free_port()
    user, password = "local", secrets.token_hex(32)
    cfg = run / "wallet.conf"
    cfg.write_text(f"rpc-login={user}:{password}\n", encoding="ascii")
    cfg.chmod(0o600)
    daemon = RPC(args.daemon_port)
    wallet = Wallet(RPC(port, user, password), daemon, directory, args.genesis, args.network)
    try:
        wallet.pin()  # Fail before any wallet file or signing process opens on a foreign node.
    except BaseException:
        cfg.unlink(missing_ok=True)
        raise
    argv = [str(executable), "--config-file", str(cfg), "--wallet-dir", str(directory),
            "--shared-ringdb-dir", str(run / "ringdb"), "--daemon-address", f"127.0.0.1:{args.daemon_port}",
            "--daemon-ssl", "disabled", "--rpc-bind-ip", "127.0.0.1", "--rpc-bind-port", str(port),
            "--rpc-ssl", "disabled", "--no-dns", "--non-interactive", "--max-concurrency", "1",
            "--log-file", str(run / "native.log"), "--log-level", "0", "--max-log-files", "1", "--max-log-file-size", "1048576"]
    if args.network == "testnet":
        argv.append("--testnet")
    output = (run / "process.log").open("xb")
    def resource_limits():
        import resource
        os.nice(10)
        if platform.system() == "Linux":
            resource.setrlimit(resource.RLIMIT_AS, (2 * 1024**3, 2 * 1024**3))
        # Darwin rejects RLIMIT_AS and reserves large virtual regions. CPU, file,
        # core and session limits still apply; actual RSS is qualified separately.
        resource.setrlimit(resource.RLIMIT_CPU, (args.seconds + 30,) * 2)
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        resource.setrlimit(resource.RLIMIT_FSIZE, (128 * 1024**2, 128 * 1024**2))
    child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=output, stderr=subprocess.STDOUT,
                             start_new_session=os.name != "nt", preexec_fn=resource_limits if os.name == "posix" else None)
    (run / "PROCESS.json").write_text(json.dumps({"nativePid": child.pid}) + "\n")
    server = None
    try:
        until = time.monotonic() + 30
        while True:
            if child.poll() is not None:
                raise WalletError("Native wallet exited during startup.")
            try:
                wallet.rpc("get_version")
                break
            except WalletError:
                if time.monotonic() >= until:
                    raise WalletError("Native wallet startup timed out.") from None
                time.sleep(0.2)
        server = Server(wallet, args.port, args.seconds, args.host)
        server.timeout = 0.5
        # Private capability is written to a 0600 file, never stdout or a process argument.
        link = directory / "OPEN_WALLET.html"
        link.write_text('<!doctype html><meta name="referrer" content="no-referrer"><title>Open local MeepCoin wallet</title>'
                        f'<a href="{server.origin}/#connect={server.bootstrap}">Open your local MeepCoin wallet</a>')
        link.chmod(0o600)
        print(json.dumps({"status": "LOCAL_WALLET_READY", "origin": server.origin,
                          "openFile": str(link), "seconds": args.seconds, "publicExposure": False}), flush=True)
        def interrupted(*_):
            raise KeyboardInterrupt()
        for sig in (signal.SIGINT, signal.SIGTERM):
            signal.signal(sig, interrupted)
        while time.monotonic() - server.created < args.seconds and child.poll() is None:
            server.handle_request()
            wallet.expire()
    finally:
        if server:
            server.server_close()
        try:
            wallet.lock()
        finally:
            if child.poll() is None:
                child.terminate()
                try:
                    child.wait(timeout=20)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=10)
            output.close()
            cfg.unlink(missing_ok=True)
            (directory / "OPEN_WALLET.html").unlink(missing_ok=True)
        print(json.dumps({"status": "LOCAL_WALLET_STOPPED", "nativeExitCode": child.returncode}), flush=True)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
    except WalletError as error:
        raise SystemExit(error.code) from None
