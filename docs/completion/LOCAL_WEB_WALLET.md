# Local browser wallet companion

MeepCoin can have a browser wallet without placing spending keys on the mining
server. The first implementation is `wallet/companion.py`: a single-user browser
interface backed by the existing native wallet on that same user's computer.
It is an experimental testnet tool. It is not a custodial website service or a
standalone browser signing engine.

## What runs where

The browser displays addresses, balances, recovery words and transfer reviews.
The local companion permits a small set of wallet operations. Native wallet RPC
creates and encrypts wallet files, derives keys, builds transactions and signs.
The separately running local node scans the exact pinned testnet. The public
mining website needs only the public reward address.

Run this companion on the wallet owner's computer. Never deploy it on the public
mining host, forward it to the Internet, or ask participants to enter their words
into `meepcoin.me`, a chatbot or a support form. The remote Pi browser rehearsal
uses disposable test wallets and a temporary private SSH forward; that test
arrangement is not the participant custody model.

## Run on a qualified Linux native installation

The current complete native distribution is Debian 13 ARM64. The interface's
Windows HTTP tests do not qualify a Windows native wallet package. macOS native
packaging, macOS random-loopback binding, mobile and browser endurance remain
unqualified.

Use Python 3.11 or later. No Python package installation is needed. Start the
node separately using the exact announced release, fresh network and private
peer configuration; its RPC must listen on numeric loopback. The earlier
qualification and deployment epochs have expired. This command does not start
or revive a public testnet.

The recommended launcher derives the network identity from the installed release
and verifies its complete checksum list before contacting the local node:

```sh
python3 wallet/launch.py \
  --release /absolute/release \
  --wallet-dir /absolute/private/meep-wallets \
  --daemon-port 49081 \
  --seconds 1800
```

Add `--verify-only` to check the package and local node without starting the
companion or creating a wallet directory. A different native version, network or
genesis is refused before wallet access. The launcher currently accepts only the
qualified Debian 13 ARM64 testnet17 package. Check the downloaded archive against
its independently obtained published hash before extracting it: a checksum list
inside an archive detects local corruption but cannot authenticate its publisher.
The launcher starts no node, service or public network.

For developers who deliberately configure the exact identity themselves, the
underlying companion remains directly available:

```sh
python3 wallet/companion.py \
  --wallet-rpc /absolute/release/bin/meepcoin-wallet-rpc \
  --wallet-dir /absolute/private/meep-wallets \
  --daemon-port 49081 \
  --network testnet \
  --genesis EXACT_64_CHARACTER_RELEASE_GENESIS_HASH \
  --seconds 1800
```

The directory must be owned by the current user, mode 0700, and initially empty.
It is bound to the announced network and genesis. A directory containing
unbound native wallet files is refused; use the native CLI for those files.
Do not use an existing personal wallet as a qualification fixture.

The companion prints a local origin and a private `OPEN_WALLET.html` file path.
Copy the link address from that private file into the browser address bar within
two minutes. Do not publish the file or link. Some browsers classify clicking a
`file:` link as cross-site; cross-site page navigation is deliberately refused.
The one-use connection fragment is removed from the address bar before API
requests. Reload resumes the same authenticated browser session. Deliberately
restart the companion for a fresh session when the absolute lifetime ends.

Create a new named wallet with a password of at least 12 characters. Record its
words offline and confirm the backup. Share the public address with the mining
invitation operator. Refresh to inspect total and unlocked native balances;
coinbase rewards mature after ten blocks, with no guaranteed elapsed time.

To send, paste the recipient's address and a decimal amount. The native wallet
validates the address without DNS/OpenAlias and builds an unrelayed transaction.
Review the exact recipient, amount and network fee before the separate Confirm
button. Cancel and expiry discard the signed metadata without broadcasting.
Amounts use integers with eleven decimal places; the interface never rounds
money with floating-point arithmetic.

If a send reply is interrupted, refresh and check the saved transaction hash.
A private, durable local record is written before relay. A new send is blocked
until the native wallet observes that hash as outgoing, pending or failed. No
automatic retry or automatic resend is performed. A submission is not a
canonical confirmation. Keep the original record if manual investigation is
needed; deleting it to retry defeats this protection.

Lock before leaving. Recovery-word reveal requires the password again. Words
clear on confirmation, lock, tab hiding, page exit, freezing or after two minutes.
The native wallet locks after five minutes without an explicit action. A hidden
tab requests immediate lock; the native idle timer is the fallback for an abrupt
browser exit. The whole companion stops after its absolute session deadline.

Restore words into a new wallet name on the same exact network. The interface
scans from genesis and never overwrites the original. Compare address, balances
and transactions before retiring any backup.

## Security boundary and limitations

The bridge listens only on a random numeric loopback address. Its dedicated
127.77.x.y host isolates cookies from unrelated apps using 127.0.0.1. It checks
Host, Origin, Fetch Metadata, a one-use bootstrap capability, an HttpOnly
SameSite=Strict session cookie and CSRF token. It exposes no arbitrary native
RPC, CORS, external scripts, browser storage, service workers or analytics.
Native wallet RPC has independent random Digest credentials in a private file;
they are not passed on the command line. Native errors and request bodies are
not forwarded into logs. Request size, concurrent requests and input reading
time are bounded. Recovery inputs disable spellcheck and autocorrect.

HTTP here is deliberately confined to numeric loopback; it is not a public
HTTPS wallet endpoint. These controls do not protect an already compromised
computer, malicious browser extension or malicious replacement of the local
software. JavaScript and Python cannot promise memory zeroization. Linux
filesystem modes are enforced; Windows native filesystem protection and signing
distribution still need qualification. Source review and finite tests do not
constitute an external security audit.

A later standalone website wallet would need a qualified native/Wasm signing
implementation, browser key encryption/storage and recovery design, dependency
and update controls, exact transaction parity tests, multiple-browser testing,
and independent wallet review. It must not send recovery words or spending keys
to the mining service.

## Reproduce the finite checks

```sh
python3 -m unittest discover -s wallet -p test_companion.py -v
python3 wallet/verify_native.py \
  --binaries /absolute/release/bin \
  --run-dir /absolute/new/disposable-rehearsal
```

The native verifier starts a fresh offline regtest node and disposable native
wallets. It verifies no relay during review/cancel, one relay on confirmation,
exact amount/fee/reward accounting, password failure, backup reauthentication,
seed restoration and owned-process cleanup. `--browser-seconds 900` additionally
waits for a visible browser transfer; an API-only run is explicitly not a
browser pass. Its retained public receipts exclude wallets, recovery words,
passwords and private connection links. Keep the full test directory private.

The newer integrated browser verifier exercises real UI creation, browser mining,
native reward accounting, payment cancellation/confirmation, recipient credit and
recovery in one run. See [PARTICIPANT_REHEARSAL_20261013.md](PARTICIPANT_REHEARSAL_20261013.md)
for the dedicated-unit command, exact results and limitations. Chromium 151 on
Debian 13 ARM64 passed with its sandbox enabled and an isolated headless profile;
the wallet-switch test also verifies that a previous wallet's recipient and amount
are cleared. An earlier Chrome-extension navigation block does not qualify or
disqualify ordinary Chrome wallet use. Safari wallet use and full Windows/macOS
native installations remain unqualified.
