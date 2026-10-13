# Integrated offline participant rehearsal - October 13, 2026

The finite engineering question was whether one actual browser participant can
create a native wallet, mine a block, observe the exact reward, pay another wallet
and recover that recipient. The final run passed on Debian 13 ARM64 with Chromium
151.0.7922.173. It used the browser's real forms and Start mining button, Worker
and Wasm PoW, the local gateway, and actual native daemon and wallet binaries.
There were no direct browser-driver calls to the wallet API.

## What passed

1. Create fresh Alice and Bob encrypted wallets through the UI, confirm their
   backups, and verify that recovery words clear after confirmation.
2. Generate 64 explicitly counted native fixture blocks for maturity and ring
   decoys. These are not counted as browser-mined blocks.
3. Click Start mining and obtain one canonical browser-mined block at height 65,
   difficulty 20, with native reward `1192055947849` atomic units
   (`11.92055947849 MEEP`). Stop the browser workers after acceptance.
4. Verify that the wallet displays the exact sum of canonical native rewards.
5. Review and cancel a payment; independently verify the native pool is empty.
6. Review and explicitly confirm `1 MEEP` with fee `0.000866 MEEP`. Independently
   verify exactly one native pool transaction and the same fee.
7. Generate 12 native confirmation blocks. Verify the transaction's canonical
   height is 66, the pool is empty, both histories show 12 confirmations, Bob has
   exactly `1 MEEP`, and Alice's balance equals all rewards minus amount and fee.
8. Recover Bob into a new wallet with the same address and balance. Reload locks
   the wallet; a wrong password keeps it locked. Switching wallets clears the old
   recipient and amount. No known seed or password appears in native logs.
9. Finish normal browser shutdown, stop native processes and detached helpers,
   and verify the complete dedicated cgroup has no remaining owned children.
   Only then write the final passing receipt.

Final browser block:
`7316256ba60df940e942af10be9a6a1aeb4c5e306052cf4ddc45e29592698d74`.
Final payment:
`bcc908e9a23a505debd2cec5d6b473fe7a98f059b8d9d13708f47af4b8643c7e`.
The source digests and safe output hashes are in `wallet/QUALIFICATION_20261013.json`.

A separate fresh offline daemon reopened a byte-for-byte copy of the final chain.
All 77 non-genesis native PoW readbacks met their stored targets, the same payment
remained canonical at height 66, and all stored header rewards reconciled with
the amount, fee and displayed balances. The original chain files remained
unchanged and the independent daemon stopped cleanly.

The run took about 80 seconds. Its peak sampled sum of owned-process RSS was
1,601,503,232 bytes against a 1.5 GiB sampled budget. The Pi did not provide an
active cgroup memory controller; this is not a kernel-enforced memory ceiling.
Chromium used its sandbox and a fresh profile. It was headless, with the mining
document reporting visible normally; no visibility or permission override was
installed. This is not a physically visible desktop or Safari test.

## Reproduce in a dedicated disposable Linux unit

Provide the qualified native binaries, Node, an already installed compatible
Chromium and an explicit installed Playwright-core module. The verifier installs
nothing. The directory must be new; old results and failures are retained.

```sh
systemd-run --user --wait --pipe --collect \
  --unit=meepcoin-participant-UNIQUE_RUN_ID \
  --working-directory=/absolute/meepcoin/source \
  --property=CPUQuota=100% --property=TasksMax=192 --property=Nice=10 \
  --property=RuntimeMaxSec=1200 --property=KillMode=control-group \
  --property=TimeoutStopSec=40 \
  /usr/bin/python3 /absolute/meepcoin/source/wallet/verify_participant.py \
  --binaries /absolute/qualified/release/bin \
  --node /absolute/node \
  --run-dir /absolute/new/private/run-directory \
  --browser-binary /absolute/chromium \
  --playwright-module /absolute/playwright-core/index.mjs
```

Use `--native-hash /absolute/meepow-v2-hash` when that CLI is outside `--binaries`.
The controller refuses a shared shell cgroup because cleanup must target only
its own disposable unit. RPC and mining bind to numeric loopback; native peers
are disabled and the daemon is offline. Unit CPU/tasks/deadline limits and the
sampled memory budget bound this finite test. It does not modify existing node
databases, wallets, services, robot/camera workloads or mining configurations.

Only `RESULT.json`, `CLEANUP.json`, `BROWSER_RESULT.json` and the three
`BROWSER_*.png` screenshots are intended as public evidence. Other files include
private session capabilities and disposable encrypted wallets. Never upload the
whole run directory or a wildcard of every JSON file. No browser trace or video
is recorded while recovery words appear.

## Installed Linux launcher check

`wallet/launch.py` independently passed against the installed Debian 13 ARM64
testnet17 package. It verified 3,341 checksum entries, required the installed
manifest's exact local native version/network/genesis, and refused a regtest
node before creating a wallet directory. Normal launch then bootstrapped the
real companion, created a fresh native encrypted wallet and locked it. Both
offline nodes, the companion and its native child stopped cleanly. This test
did not mine the expired v17 deployment, start public services or open an
existing wallet. The launcher is a source add-on; the earlier native archive
does not retroactively contain it.

## What remains

The integrated chain was offline regtest with block major version 16 and fixed
difficulty 20. A new v17 public HTTPS release still needs its own installed
participant journey. The older v17 desktop invitation rehearsal qualified
mining and service lifecycle separately and has expired. These results also
do not qualify full Windows/macOS native packages, Safari wallet use, mobile,
sustained heat/battery behavior, a longer public operating period, permissionless
native P2P or an independent human security/cryptography audit. The six remaining
product areas and their concrete finish lines are in [READINESS_NEXT_SIX.md](READINESS_NEXT_SIX.md).
