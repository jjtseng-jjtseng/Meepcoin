# Current checkpoint - October 16, 2026

The latest release and empirical scope are recorded in
[REHEARSAL_RESULTS_20261016.md](REHEARSAL_RESULTS_20261016.md) and
[OWNER_REHEARSAL_20261015.md](OWNER_REHEARSAL_20261015.md). The historical
checkpoints below retain their original identities and limitations. The fresh
network has a fixed 05:39:28 UTC expiry; a broader public launch remains gated
by independent human review. Consult the final closure/review receipt for
terminal status, rather than treating historical success as current service uptime.

---

# Readiness after the bounded deployment rehearsal

The deployed desktop invitation rehearsal is complete for its recorded finite
scope. It stopped and expired; it is not a continuously operating public network.
The next six product areas are distinct from that completed deployment checklist.

| Area | Current evidence | Still required |
|---|---|---|
| Usable wallets | Local browser companion: encrypted native create/open, backup reauthentication, exact decimal send/fee review, cancellation, interrupted-send journal, lock and seed restore. The wallet launcher and node starter verify 3,341 installed release files. Real node startup, deadline, repeated stop, cold reopen, identity refusal and private loopback peer handshake pass. Installation commands are documented. | Issue the next fresh release and restricted participant private peer credentials, then qualify installation on a separate participant machine. Complete Windows/macOS native distributions only if those platforms are advertised. Standalone website signing is a separate future feature. |
| Participant journey | One integrated real Chromium journey now passes: create two wallets through the UI, browser-mine a native block, reconcile the exact reward, cancel without relay, confirm one payment, verify its native fee and canonical height, receive exactly 1 MEEP, and recover the same recipient address/balance. | Repeat the complete journey on a fresh v17 release through the actual public HTTPS invitation endpoint, with the participant's installed wallet and intended private node connection. The new integrated pass uses offline regtest, not the deployed v17 endpoint. |
| Longer operations | Existing resource limits, private native RPC/P2P, expiry, restoration and bounded invitation tests remain qualified. New wallet rehearsals cleanly stop their owned children. | Declare and rehearse a longer duration, capacity and failure budget before broadening the previous eight-invitation, one-hour exposure. Persistent participant wallets belong on participant devices. |
| Quiet-chain behavior | v17 difficulty modeling and finite native boundary/reorg checks exist. The wallet separates total from unlocked balances, explains ten-block coinbase maturity and promises no elapsed wait. | A longer low-participation run, observed stall/recovery criteria and operator guidance tied to the intended exposure. UI wording does not fix or prove every consensus liveness pattern. |
| Security and failures | Wallet boundary tests reject foreign origins/hosts, absent capabilities/CSRF, duplicate confirmation, cross-wallet reviews and network changes. Lost send replies survive restart and block another send until resolved. Focused model source review produced fixes. | External human security/cryptography review; broader peer/storage/power-loss/corruption and adversarial endurance evidence. A model source review is not a security audit. Native P2P remains operator-private. |
| Platforms and release quality | Debian 13 ARM64 native package; prior Chrome/Safari mining qualification; companion HTTP tests on Windows/Linux; earlier visible in-app Chromium payment; new sandboxed Chromium 151 wallet/mining/payment/recovery pass on Linux. Previous GitHub CI completed both full Linux native jobs and all four portable PoW jobs successfully. | Qualify wallet use with each advertised participant browser, including Safari if advertised. Full macOS/Windows packages, mobile, battery/thermal behavior and sustained mining remain unqualified. The new automated Chromium test is headless; it is not a physically visible Safari run. |

The wallet implementation and limitations are in [LOCAL_WEB_WALLET.md](LOCAL_WEB_WALLET.md).
Its finite qualification receipts are `wallet/QUALIFICATION_20261012.json` and
`wallet/QUALIFICATION_20261013.json`; current runtime hashes, the corrected
stable-state browser check, node starter and 33 HTTPS gateway boundary checks
are recorded in `wallet/QUALIFICATION_FINAL_20261013.json`. Historical receipts
retain their original source hashes. The integrated run is described in
[PARTICIPANT_REHEARSAL_20261013.md](PARTICIPANT_REHEARSAL_20261013.md). All new
currency tests used fresh disposable wallets on an offline regtest chain with
fixed difficulty 20. Browser wallet transactions use native wallet signing;
these tests do not claim browser-side cryptographic signing.

No existing wallet was opened, no real-value transfer occurred, no public
invitation was issued, and the expired deployment epoch was not restarted.
