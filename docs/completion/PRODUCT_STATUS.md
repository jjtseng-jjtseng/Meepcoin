# MeepCoin deployed invitation checkpoint

The six-step deployed desktop invitation rehearsal is complete. Windows Chrome and
Mac Safari 26.6.2 mined canonical v17 blocks through https://mine.meepcoin.me with
exact native wallet rewards. The final package passed actual unit resource checks,
outage/rotation, persisted expiry, expired restart refusal and cold restore. All
owned services stopped afterward. See [LAUNCH_DECISION.md](LAUNCH_DECISION.md) for
artifact hashes, evidence, scope and the later-session boundary. Mobile endurance,
permissionless native P2P, full Windows/macOS native distributions and mainnet
remain unqualified. The historical private checkpoint below is retained.

# MeepCoin private product checkpoint

This file preserves the earlier private checkpoint. The later opt-in v17 candidate and seven-area qualification are described in [TESTNET17_QUALIFICATION.md](TESTNET17_QUALIFICATION.md), with operations in [TESTNET_OPERATIONS.md](TESTNET_OPERATIONS.md) and the remaining deployment decision in [LAUNCH_DECISION.md](LAUNCH_DECISION.md). Historical remaining-work rows below are not the current candidate disposition.

The core private currency path works: actual Chrome proof of work is accepted by the native daemon, propagates to private peers, pays real native coinbase rewards, matures, and funds an ordinary wallet transfer. This is an experimental private product checkpoint. It is not public-testnet or mainnet readiness.

## Verified in the October continuation

- Real vendored LMDB baseline and four defective controls; all controls rejected for their intended reasons.
- Actual BlockchainLMDB/Blockchain collector, transaction commit/abort/reopen and reader snapshot coherence.
- Qualified cache exception correction, including 12 getter faults, 10 vector-allocation sites, and actual acceptance/reorg/pop/reopen. The original cache and optional post-insertion warming had real reproduced correctness failures. Healthy difficulty arithmetic was preserved.
- Portable ARM64 BLAKE3 dispatch corrected. Actual native public v2 API known-answer tests: 20 vectors, 67 checks, zero failures. The committed Wasm source rebuilt under the exact Emscripten 6.0.3 compiler and reproduced both pinned outputs byte for byte; rebuilt ARM Node vectors passed 20 v2 and 132 legacy cases.
- CLI regtest v1/v16 genesis incompatibility corrected. Production daemon and wallet RPC builds have no test fixture macro.
- Real Chrome mined canonical private blocks. A fresh compiled genesis/network-ID variant exercised daemon-selected targets 60 and 216. A later verified pair used targets 277 and 129 after elapsed time on that chain.
- Actual Chrome idle/reload, immediate Stop, background-tab stop and no automatic restart; focused regressions cover stale start responses, worker generations, late candidate display, shutdown admission and local authorization.
- Three loopback peers agreed. A node restart preserved the chain. Independent offline reopening of all three retained databases reproduced both final browser block IDs, nonces and native proof-of-work hashes, with six exact readbacks meeting the real targets.
- A live three-peer partition produced a two-block losing branch and a four-block winning branch. Reconnection converged on higher cumulative work; orphan wallet rewards disappeared, winning rewards balanced exactly, rescan and restart passed, and all 30 canonical native PoW readbacks agreed. This used fixed difficulty 20 and honest short forks.
- Current-build browser coinbases appeared immature, matured, and funded a one-MEEP transfer. Exact sender accounting includes rewards, amount and fee; recipient credit is exact. Wallet reopen, recipient rescan, daemon restart and disposable seed restoration passed.
- Eight actual native timestamp submissions passed: MAIN and ALT each reject median minus one and clock plus 7,500 seconds, and accept median equality and clock plus 6,900. Every submission had valid native PoW; intended rejection logs and stored accepted-block PoW were independently checked. Fixed difficulty and the 300-second future-limit margin limit this result.
- Pinned-source full ARM64 daemon, wallet RPC and ordinary wallet CLI build passed. A relocated review package passed all checksums, native KAT, rewards/transfer/wallet/node restart, and eleven ARM Node gateway/lifecycle tests.
- Full JavaScript suite after session/shutdown fixes: 1,306 passed, 31 explicitly skipped native-helper tests, zero failures; v2 20-vector and legacy 132-vector checks also passed. The final suite was rerun after package/document changes with the same counts.

## Architecture decision

The first usable product is direct solo mining. The operator configures a public address, and the native coinbase pays it. The mining page and gateway hold no spend keys. This avoids promising a pooled balance or administering payouts. A future pool would need its own durable contribution ledger, orphan/reorg reconciliation, maturity accounting, fee policy and idempotent payouts before launch.

## Remaining work before a public testnet

| Area | Remaining qualification |
|---|---|
| Consensus policy | Prospective honest-launch, churn, stalls, rate changes, hostile timestamp, MAIN/ALT/reorg, clock-skew and recovery criteria; reviewed rule and activation decision |
| PoW | Broader supported-browser/platform equivalence, resource/thermal tests, independent algorithm and optimization review |
| Wallet | Adversarial transactions, long-run fee/reward and decimal boundaries, fork/upgrade handling, broader backup and restore drills |
| Public service | Authenticated TLS sessions, deployment secret handling, per-client quotas, abuse controls, rotation/reconnect and daemon outage behavior |
| Peers | Malformed-peer tests, longer/adversarial partitions and competing forks, version/upgrade behavior, reviewed discovery/seed operations |
| Economics | Boundary arithmetic and long-run tail emission totals, low participation and concentrated hashpower analysis |
| Operations | Supported release builds, monitoring, disk-full/crash recovery, rollback, installation and restore drills |
| Review and launch | Independent consensus/cryptography, wallet, peer/RPC and service review; findings fixed against pinned artifacts; a separate human launch decision |

The relocated Debian 13 ARM64 archive is described in [REVIEW_BUILD.md](REVIEW_BUILD.md). Its source is pinned at 8bfb0b5; the later peer test and checkpoint documentation are additional source changes with no native or gateway runtime changes.

The detailed twelve-area plan remains in the continuation's COMPLETION_PLAN.json. Source-only tests, successful compilation, or cleanup are never substitutes for runtime consensus evidence. The legacy halted campaign and failed environment attempts remain separate preserved records.

The frozen original checkout was preserved. All product work is in the separate codex/completion-20261011 branch. No public network, real-value funds or existing user wallets were used.
