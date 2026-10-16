# Two-device participant installation qualification, October 15, 2026

The 13 installation requirements passed on the owner's Pi and Mac for a finite,
private home-LAN testnet session. The exact distribution is
`0.1.0-participant.2`. This is an archived qualification release: the invitations
have expired and all temporary services have stopped. It is not an active public
testnet invitation. A new experiment needs a newly scheduled, reviewed release
and its own fresh network identity and deployment rehearsal.

## Qualified computers and prerequisites

| Computer | Actually tested platform | Browser | Participant Python |
|---|---|---|---|
| Pi | Debian 13.6, ARM64, Linux 6.18.39, 4 CPUs, 8 GiB RAM | Chromium 151.0.7922.173 | 3.13.5 |
| Mac | macOS 26.6.2 build 25G83, Apple ARM64, 10 CPUs, 16 GiB RAM | Chrome 155.0.8059.79 | Homebrew Python 3.14.3 |

The participant needs Python 3.11 or later, `ssh`, `ssh-keygen` with SSH signature
verification, a supported desktop browser, and at least 1 GiB free for installation.
Python uses only its standard library. No participant compiler, Node, npm,
Playwright, build dependencies or Python packages are required. The Mac's system
Python 3.9.6 was actually refused. On the tested Mac use
`/opt/homebrew/bin/python3`; the build prefix also provided Python 3.13.16,
which is the runtime recorded when assembling the manifest.

The distribution bundles 26 non-system shared libraries on Debian and 22 on
macOS. Mach-O libraries were relocated and their ad-hoc signatures verified.
There is no Apple Developer ID signature or notarization. The qualification
used the command-line installer and did not disable Gatekeeper or change a
security policy. Windows native packages, Intel Macs, other Linux distributions,
mobile, Safari wallet use and sustained heat/battery behavior are unqualified.
The Safari attempt stopped when its automation window reported `hidden`;
the visibility safeguard remains intact.

## Exact identity and authenticated download

| Field | Pinned value |
|---|---|
| Participant release | `0.1.0-participant.2` |
| Native source | `4849c54c1bec27414290c4815c30d1e4ee98e3f0` |
| Packaged wallet source | `675381d129b8ae12fe1b16e6771eacc20dbbfdfa` |
| Wallet source tar SHA-256 | `3357ef28d9dc10ec171ffbc4a3f4c75322ec041ec321edb234d3bff48598fadd` |
| Native version | `0.2.0-testnet17-review (MeepCoin; Monero base 0.18.5.1)-release` |
| Network | `testnet17` |
| Genesis timestamp | `1792093877` |
| Genesis hash | `e07bde6f629fecb01fd8bfc115f6d88112a6ea9c14312a8286c068e3ebc57782` |

The owner's authenticated GitHub draft release is tagged
`participant-0.1.0-test.2` in
[jjtseng-jjtseng/Meepcoin](https://github.com/jjtseng-jjtseng/Meepcoin/releases).
Draft assets are owner/repository-collaborator downloads. They are intentionally
not a public distribution or public launch. The tested LAN download servers
were stopped after qualification. The installed copies remain on the two
participant computers.

Download `install-participant.py`, the selected platform's `.tar.gz`, `.json`
and `.json.sig`, and `publisher-ed25519.pub`. Use an authenticated GitHub owner
session, or transfer these exact files over an already authenticated SSH
connection. Keep the three platform files together in one private download
directory. Do not trust a new public key merely because it accompanies a download.
Establish the following fingerprint through the already trusted owner/source
channel; the qualification distributed the public key over pinned SSH:

```text
SHA256:eSYZj5YQKK0qWiprSlEBj3eH3dT66DjdaAQ6bGDEqjI
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIArmhm28DWKz9yQU8nsuSOotTxfsfjL9p3Je0DAUNLvq
```

`ssh-keygen -lf publisher-ed25519.pub` must show that fingerprint. The private
publisher key stays on the operator's Pi and is never included in an asset.
The signed descriptor uses signer `meepcoin`, namespace `meepcoin-release`.
The installer verifies the signature, archive size/hash, safe extraction,
platform, manifest and every installed file before publishing the application.

| Archive | Bytes | SHA-256 |
|---|---:|---|
| `meepcoin-0.1.0-participant.2-debian13-arm64.tar.gz` | 27,810,569 | `f07503bb42218bc1ca09f0b7fa90241f8466dc0b59e0972f6aba823dce65b53a` |
| `meepcoin-0.1.0-participant.2-macos26-arm64.tar.gz` | 34,726,397 | `78feb4eeec681a1009aa9974f3d41e22cbeac38dac815ccc5096b345d27e2461` |

The following example is for a private local download directory. On the Mac set
`PYTHON=/opt/homebrew/bin/python3` and `PLATFORM=macos26-arm64`; on the Pi use
the values below. A supported later active release must supply its own exact
version and descriptor. These commands never overwrite an installed application.

```sh
PYTHON=python3
PLATFORM=debian13-arm64
DOWNLOADS="$HOME/MeepCoinDownloads"
APPS="$HOME/MeepCoinApps"
RELEASE="$APPS/0.1.0-participant.2"
mkdir -m 700 "$APPS"
"$PYTHON" "$DOWNLOADS/install-participant.py" \
  --descriptor-url "file://$DOWNLOADS/meepcoin-0.1.0-participant.2-$PLATFORM.json" \
  --publisher-key "$DOWNLOADS/publisher-ed25519.pub" \
  --destination "$RELEASE"
"$PYTHON" -B "$RELEASE/wallet/manage.py" verify --release "$RELEASE"
```

Expect `SIGNED_PARTICIPANT_INSTALL_PASS`, 85 verified files and
`PARTICIPANT_RELEASE_PREFLIGHT_PASS`. The 86th archive file is `SHA256SUMS`
itself. Installed-file checks detect corruption; the signed archive and trusted
publisher key establish release authenticity. They do not defend against another
process with the same operating-system account deliberately replacing the
application and its verifier.

## Private storage and individual access

Application files and participant data must be separate, owned by the participant
and private. Never select an existing wallet or unrelated database directory.
The qualification used:

| Computer | Application | Persistent participant data |
|---|---|---|
| Pi | `~/meepcoin-participant-20261015/installed-2` | `~/MeepCoinData-20261015` |
| Mac | `~/meepcoin-participant-20261015/installed-2` | `~/MeepCoinData-20261015` |

The data directory contains `node/`, `wallets/`, the private participant SSH key,
session logs and cleanup receipts. Directories are mode 0700; private keys and
wallet key files are mode 0600. It is not a download or website directory.
There was about 198 GiB free on the Pi and 129 GiB on the Mac when measured.
Blockchain growth needs a separate operating-period storage budget.

For a new active invitation, generate its access identity locally:

```sh
DATA="$HOME/MeepCoinData"
"$PYTHON" -B "$RELEASE/wallet/session.py" keygen --data-dir "$DATA"
```

Give the operator only `participant-key.pub`. The private access key and wallet
keys stay on the participant computer. Key generation refuses an existing
identity. The operator returns an authenticated mode-0600 peer descriptor with
the participant's endpoint, pinned Ed25519 server public key, exact genesis and
UTC expiry. A descriptor obtained from an unknown source is not a trusted
invitation. The initial route deliberately accepts only this owner's LAN
operator user and the one native P2P target `127.0.0.1:49280`.

Each participant has a distinct restricted SSH endpoint and key. It grants
only that P2P forward: no shell, operator RPC, other destination, remote forward,
agent, TTY, X11 or stream-local forwarding. The operator uses a separate finite
Linux user-service cgroup for each participant, with CPU 20%, memory 128 MiB,
32 tasks and `KillMode=control-group`. Revocation stops that cgroup and verifies
it empty, disconnecting already authenticated clients as well as the listener.
The operator must preserve failed attempt logs and use a new state path for a
new attempt. See `scripts/private/participant-peer-service.py`.

This initial release qualifies home-LAN access only. It requires no router,
domain, public RPC or port-forwarding change. Outside-home access, general
participant enrollment and permissionless peer discovery require their own
design and qualification.

## Start, inspect, stop and restart

During an approved active private session, use its unexpired descriptor:

```sh
"$PYTHON" -B "$RELEASE/wallet/session.py" start \
  --release "$RELEASE" --data-dir "$DATA" \
  --peer "$HOME/private-meepcoin-peer.json" --seconds 1800
```

Keep this terminal running. Wait for `PARTICIPANT_READY`, a private peer count
above zero and the intended genesis. In a second terminal:

```sh
"$PYTHON" -B "$RELEASE/wallet/session.py" status --data-dir "$DATA"
"$PYTHON" -B "$RELEASE/wallet/session.py" stop --data-dir "$DATA"
```

Status reports local/target height, synchronization, peer count and measured
native RSS. The default session is 30 minutes, allowed range 60–3600 seconds,
also bounded by invitation expiry. Stop, Ctrl+C, expiry or a lost peer tunnel
ends the session without automatic restart. Wait for `PARTICIPANT_STOPPED`,
`gracefulCleanup: true` and two empty recorded native process groups. Restart
uses the same data directory and the still-compatible release; it does not
reset the database. An expired descriptor needs a newly approved invitation.

Occupied ports, foreign network identity, unbound existing data, checksum
damage or unexpected process exits produce an error and a session log. Inspect
the recorded failure; do not delete wallets, kill unknown processes or erase a
database to work around it. A stale control socket after an unclean crash is
deliberately refused; operator recovery must first establish ownership and
process state. SIGKILL/power-loss recovery is not qualified by the graceful
stop checks in this release.

The native RPC, wallet RPC and wallet HTTP interfaces bind only to loopback.
On macOS the wallet uses a unique reserved `meep-<random>.localhost` hostname
to isolate its host-only session cookie from adjacent loopback applications.
Exact Host/Origin checks remain enabled. Native CPU/file limits apply; Linux
also has an address-space limit. The session samples combined native RSS every
two seconds and stops above 2 GiB. That sampled guard is not a kernel resident
memory ceiling. Qualified deadline runs peaked at 133,248 KiB on the Pi and
117,168 KiB on the Mac. Browser memory is outside that native-only metric.

## Wallet onboarding and recovery

After readiness, open `$DATA/wallets/OPEN_WALLET.html` in the supported local
browser and click its link within 120 seconds. The bootstrap link is private,
one-use and expires. Do not copy it into chat or a support ticket. It is removed
on session cleanup. The companion opens no existing wallet automatically.

1. Create a new wallet with a unique name and a strong private password.
2. Record the recovery words privately, in their exact order, outside the
   application/data directories. The words can recover spending authority;
   anyone holding them can control the wallet.
3. Confirm that the backup was recorded. The page clears the displayed words.
4. Lock the wallet, then unlock it with the password. Wrong passwords are refused;
   reloading the page also locks it.
5. Rehearse recovery into a **different wallet name**, never over the original.
   Enter the words only in the local companion. Compare the full restored
   receive address with the original and verify the original still unlocks.

The qualification performed these actions through actual browser forms on both
computers using disposable wallets. Recovery words and random passwords stayed
in the browser/test process memory and the participant's native wallet; no keys,
words or passwords were exported in evidence. The preserved test wallets are
qualification fixtures, not usable personal accounts with delivered passwords.
Create your own wallet privately during an approved active session.

Do not enter recovery words or a wallet password into `meepcoin.me`, the mining
host, GitHub issues, an AI chatbot or a support form. The website can use a public
reward address. This installation test did not mine blocks or send payments;
the separate historical mining/payment rehearsal remains separately scoped.

## Compatible upgrades and removal

Download and authenticate an update into a **new** application directory, stop
the session and wait for cleanup. Initial upgrades allow companion-only changes:
platform, network, genesis, native version and all three native binaries must
remain identical. A different native/network release requires separate
qualification and separate data; it cannot silently adopt this wallet/database.

```sh
"$PYTHON" -B "$NEW_RELEASE/wallet/manage.py" upgrade \
  --from-release "$RELEASE" --release "$NEW_RELEASE" --data-dir "$DATA"
"$PYTHON" -B "$NEW_RELEASE/wallet/session.py" start \
  --release "$NEW_RELEASE" --data-dir "$DATA" \
  --peer "$HOME/private-meepcoin-peer.json" --seconds 1800
```

Selection writes `SELECTED_RELEASE.json`; use the explicitly selected new path
for subsequent start commands. It does not replace an application in place.
The actual `.1` to `.2` rehearsal checked byte-identical wallet/database files
during selection, reopened the same database, unlocked the old encrypted wallet
with the same address and then stopped at a real one-minute deadline.

After stopping, remove an old verified application using:

```sh
"$PYTHON" -B "$NEW_RELEASE/wallet/manage.py" remove \
  --release "$OLD_RELEASE" --data-dir "$DATA"
```

Removal deletes only that verified application. The actual test retained all
wallet/database bytes and the participant identity. It refused overlapping
application/data paths. This is deliberately not an erase-wallet command.
Preserve your private backup independently before any later data maintenance.

## Recorded finish line

`wallet/QUALIFICATION_20261015.json` maps all 13 requirements to observed
results on both computers. Private raw receipts retain 59 Pi and 49 Mac files,
each independently checked against its SHA-256 inventory. Signed archives were
independently verified again after transfer. The earlier listener-only
revocation failure is preserved and superseded by the real cgroup revocation
pass; it was not treated as a successful disconnection.

All owned participant, operator and download listeners were closed. Private
wallets and databases remain on their respective devices. Robot/camera and
unrelated workloads were not changed. No public service, real-value wallet,
public mining or automatic follow-up was started by this qualification.
