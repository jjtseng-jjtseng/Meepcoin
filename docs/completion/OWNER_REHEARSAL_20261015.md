# Signed two-device release and finite operator procedure

This document describes `0.2.0-rehearsal.5`. It supersedes the older participant
installation qualification only for this separately identified owner-device
experiment. Historical releases and failed attempts remain evidence. This is
testcoin software; unrestricted public enrollment remains disabled pending an
independent human consensus, cryptography and security review.

## Release and support scope

The qualified installation targets are Debian 13 ARM64 and macOS 26 ARM64, with
Python 3.11 or later and OpenSSH signature verification. The Pi uses Chromium
151.0.7922.173; the Mac uses Chrome 155.0.8059.80 and Homebrew Python 3.14.3.
The native daemon, wallet RPC and wallet CLI are bundled with their non-system
libraries. A participant does not need a compiler or Node. The browser
automation helpers included in the archive are qualification tools, not
participant prerequisites. Mac binaries have verified ad-hoc signatures;
Apple Developer ID signing and notarization are not established.

| Identity | Value |
|---|---|
| Native version | `0.2.0-testnet17-review (MeepCoin; Monero base 0.18.5.1)-release` |
| Genesis UTC seconds | `1792125000` |
| Genesis hash | `a74575a80c66f643d8d267b6edfb4e1c3138c82aff367fe5e934b1fc40662b80` |
| Native source commit | `18c46542ec561ae1b87518b90c603af24688928c` |
| Packaged wallet/gateway source commit | `bf54c77b26f67d4c48cc209cccfb6ea6cae4f3a8` |
| Wallet source archive SHA-256 | `405686c3f982ddd3c1b6e6a32554b2cd5dc37169b1fa74c898374f83eccba17b` |
| Wasm SHA-256 | `84480d148e3c7559d8b4ba90b3a4f8d9acf7ec2180d50d713b46eac5f28bd35d` |
| Absolute epoch | 2026-10-16 04:39:28 through 05:39:28 UTC |

| Archive | Bytes | SHA-256 |
|---|---:|---|
| `meepcoin-0.2.0-rehearsal.5-debian13-arm64.tar.gz` | 27,849,437 | `32162adc5e222de6d9d8c2eddd5a9752d3de7fe8356a77259287990010bbd249` |
| `meepcoin-0.2.0-rehearsal.5-macos26-arm64.tar.gz` | 34,775,396 | `965f549b02f65f0d55055ff2e4cf1ce2766ae784c89742100403334135a26926` |

Download the archive, matching `.json` and `.json.sig`, `install-participant.py`
and `publisher-ed25519.pub` from the authenticated owner GitHub draft release.
Establish the publisher fingerprint using the already trusted owner channel:
`SHA256:eSYZj5YQKK0qWiprSlEBj3eH3dT66DjdaAQ6bGDEqjI`.
A public key supplied alongside an untrusted download is insufficient. Run the
installer into a new private application directory; it verifies the signed
descriptor, archive bytes, safe extraction, platform and every installed file.
Use `wallet/manage.py verify --release /absolute/new/application` afterwards.
The Pi package checks 100 files and Mac checks 99, plus `SHA256SUMS` itself.

The participant archives remain byte-for-byte bound to `bf54c77`. The separately
signed operator archive is `meepcoin-0.2.0-rehearsal.5-operator.2-debian13-arm64.tar.gz`
(79,920,908 bytes), SHA-256
`ed5b908dd72a9c852f912760bf5cdd322d07933b5db768841fbfeb4da905dfed`.
It contains 417 individually hashed files and a manifest. Its signature namespace
is `meepcoin-operator-release`; participant descriptors use `meepcoin-release`.
The manifest binds the staged base source to `bf54c77` and two reviewed operator
overlays: `bf823008e816fb9764c189c10888b26d0c6b1cc6` preserves executable mode
on six root-owned runtime files without changing their bytes;
`cbb736bc022831a35dba74c01ba114e01e99d612` tolerates an already revoked/missing
unit during batched expiry stop while still independently requiring every owned
cgroup to be empty. The installed helper SHA-256 is
`3f02cd33abb96be7ffa8b301b7d4c2552ec7ac348373cfb5ad5e91868819607a`.
The operator archive is an archival replay bundle for the prepared Pi account,
pinned runtime and tunnel arrangement, rather than a general hosting installer.
No wallet, chain database, private key, invitation or tunnel credential is shipped.

Subsequent source commits `e603de2` and `a9cde81` improve qualification drivers
only: settle the native idle-lock state before unlock, and compare recovered
history using every full serialized row as a multiset, preserving duplicates.
They do not change these immutable participant archives. Initial failed tests
remain recorded; their corrected follow-up checks are identified separately.

## Participant procedure

Application files and persistent data occupy different private directories.
Use a fresh data directory for a new genesis, and retain old wallet/data
directories. Generate an individual access key with `wallet/session.py keygen
--data-dir /absolute/private/data`. Send only the public key to the operator.
The authenticated peer descriptor binds the exact network, pinned SSH host
key, intended native P2P destination and its maximum lifetime. The gateway
epoch and operator revocation can close it earlier; the effective end is the
earliest of those bounds. The one-shot timer closes existing authenticated
sessions at the gateway deadline. The first scope is
the owner's home LAN; outside-home access and general peer discovery are
unqualified.

Start with the installed Python launcher:

```sh
python3 -B /absolute/application/wallet/session.py start \
  --release /absolute/application --data-dir /absolute/private/data \
  --peer /absolute/private/peer.json --seconds 1800
python3 -B /absolute/application/wallet/session.py status \
  --data-dir /absolute/private/data
python3 -B /absolute/application/wallet/session.py stop \
  --data-dir /absolute/private/data
```

On the Mac use `/opt/homebrew/bin/python3`. Follow the local private wallet
link created by the companion, create an encrypted wallet and privately record
its recovery words in order. Confirm the backup, clear the words and lock the
wallet. Never paste passwords, recovery words, private access keys or capability
URLs into GitHub issues. Recovery always uses a different wallet name and
refuses to overwrite an existing destination. Reload locks the wallet.

The public website can open the local companion workflow, while wallet secrets
and native wallet RPC remain on the participant computer. The public mining
service receives a public reward address only. Public mining requires an
individual invitation, deliberate Start and one worker. Stop, hide and reload
terminate work; returning never resumes automatically. The user controls CPU
use. Mobile, Safari wallet use, Windows native installation, Intel Mac,
sustained heat/battery behavior and host power-loss durability are unqualified.

One MEEP is 100,000,000,000 atomic units. Coinbase maturity is ten blocks;
decoy availability may delay spending beyond maturity. Review recipient,
amount and fee before explicitly confirming. An interrupted send stays
unresolved until exact-hash reconciliation; do not resend because an HTTP
response was lost. The supply parameter is 25 million MEEP with permanent
0.125 MEEP per-block tail emission, rather than a fixed supply cap.

## Operator procedure and limits

Use a dedicated unprivileged `meepcoin` account, new versioned application and
data paths, private loopback native RPC/P2P, and individually pinned restricted
SSH forwarding routes. Routes permit only native P2P, with no shell, TTY,
agent, arbitrary destination or operator-wallet access. Stop the exact
participant service to revoke its active connection. This does not revoke the
other participant.

`scripts/private/deploy-rehearsal.py` implements setup, node, private peers,
gateway, tunnel, status, telemetry, stop, expiry, cold backup and offline
restore. Run it as an administrator with `--genesis` and the explicit inputs.
Setup verifies installed hashes and refuses occupied ports or an earlier active
deployment. The runtime preserves `bin`, `libexec` and bundled `lib` layout.
The gateway creates its epoch once. Restart retains that exact epoch and
refuses expiry; never edit a saved epoch to extend it.

The operator's exact five cgroups close through a one-shot absolute-expiry
timer, including already authenticated SSH children. Original finite service
caps provide an additional earlier bound. This systemd version cannot change
RuntimeMaxSec on a running unit; do not use that as a live-expiry mechanism.
No service is enabled for boot or automatically renewed.

The operator slice permits at most one CPU, 128 tasks, sampled aggregate RSS
below 1.5 GiB, at least 1 GiB disk headroom and bounded logs. Connector CPU is
30%, each peer 20%; service temporary filesystems are 16 MiB. Participants
enforce a 2 GiB native memory budget and bounded lifetime. Five-second
telemetry has a maximum acceptable gap of 15 seconds. The qualification
observer has its own 4200-second finite lifetime; when it runs directly, its
terminal receipt and exit must be checked rather than a nonexistent unit. The invitation cap of
eight is an admission limit; the exercised load is two devices.

If native RPC is lost, readiness closes, browser work stops and restoration
requires an explicit new Start. A canonical-progress age of 600 seconds
persistently closes mining admission, including after gateway restart. Preserve
the database and explain the stall; never reset or credit balances silently.
ASERT targets 60 seconds with a 900-second half-life, fixed genesis anchor and
difficulty floor 20. Low participation and departures can produce long delays;
there is no promised block or payment completion time.

For an incident use the
[GitHub issue tracker](https://github.com/jjtseng-jjtseng/Meepcoin/issues/new/choose).
Close admission first, preserve exact source/artifact identities, timestamps,
canonical tip and bounded nonsecret logs. GitHub issues are public; exclude
private URLs, keys and wallet files. An AI chatbot is not the incident channel.

Stop the exact owned services and prove their cgroups empty before backing up.
The `backup` action copies the complete stopped chain into a new directory and
compares every file hash. `restore` opens a separate copy with the same binary
in offline mode; compare genesis, height and canonical tip, then stop it.
Retain the original backup. Never copy a live LMDB directory as this procedure.

For upgrades, install a new versioned application without overwriting data.
Only the same network and proven native compatibility may reuse a data
directory. Keep wallet backups separately. Removal deletes only the selected
application after stop; retaining the data directory retains wallets. A stale
socket is recoverable only with the original session nonce/inode and terminal
live-ownership proof. Saved process IDs never authorize killing processes.

## Evidence and admission

The final evidence packet records actual browser/native blocks, wallet payment
and recovery, continuous telemetry, failure drills, expiry, cold restoration,
independent review and release hashes. A result is complete only when its
recorded empirical criterion passed. The initial plan received a non-coding
review score of 9.4/10 before implementation. Final work scoring is a separate
gate and cannot replace an independent human consensus/security audit.

The one-hour qualification network is archival after expiry. A later experiment
needs newly scheduled compile-time genesis, newly signed packages and an
explicit exposure decision. Keep unrestricted enrollment disabled until the
human review and availability-policy decision are complete.
