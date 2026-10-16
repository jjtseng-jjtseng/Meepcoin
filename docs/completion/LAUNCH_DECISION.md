# Current checkpoint - October 16, 2026

The latest release and empirical scope are recorded in
[REHEARSAL_RESULTS_20261016.md](REHEARSAL_RESULTS_20261016.md) and
[OWNER_REHEARSAL_20261015.md](OWNER_REHEARSAL_20261015.md). The historical
checkpoints below retain their original identities and limitations. The fresh
network has a fixed 05:39:28 UTC expiry; a broader public launch remains gated
by independent human review. Consult the final closure/review receipt for
terminal status, rather than treating historical success as current service uptime.

---

# Deployed v17 invitation testnet decision

Recorded October 13, 2026 UTC (October 12 local). The six requested deployment steps are complete for a finite desktop invitation experiment. The final deployed rehearsal passed and ended automatically. Its services are stopped; no participant invitations were publicly distributed.

## Decision and operating scope

Qualified for up to eight private invitations and an absolute epoch of at most one hour, deliberate Start, one browser worker, private operator-controlled native peers, and no automatic renewal. Desktop Windows Chrome and Mac Safari 26.6.2 completed native public submissions. Mobile and sustained battery/heat behavior remain unqualified and excluded.

This decision implements the user's instruction to complete the concrete six-step deployment. It rests on operator-run tests and focused model-assisted review, not an external security audit. It does not qualify mainnet, real-value funds, permissionless native P2P, arbitrary hosts/proxies or automatic computer handover.

## Pinned deployed artifact

- Package: `meepcoin-v17-1791847734-debian13-arm64-invitation-final-v2.tar.gz`.
- Archive SHA-256: `aa667793bef2e3a055e6c19a61f0f1f0b0e8f7bce9a0b9fc552b9473fffed2f5`; independently checked on Windows and at root installation.
- Full native daemon/wallet runtime: Debian 13 ARM64, version `0.2.0-testnet17-review (MeepCoin; Monero base 0.18.5.1)-release`.
- Native build-input commit: `9fee7dfc318593f87c63dc3ffd6310850599f358`; build uses `--testnet17-genesis-utc 1791847734`. The default network is unchanged.
- Genesis UTC Unix: `1791847734`; hash `551d45a5767cc6939a58ffe1b8dafc7a807f75add7db10a708cd5d58f4532785`.
- Reviewed watchdog SHA-256: `4fc73898ab8d45bdfb480a00f1e37f424900e0cf243e358f553e38b3068b346a`.
- No wallet, database, invitation, TLS secret or historical Git repository is in the archive. The package's embedded documentation describes the release candidate at packaging time; this decision records its subsequent runtime qualification. The five deployed Python sources were compared byte for byte with the final package before this documentation update.

## Six steps and actual evidence

| Step | Completed result |
|---|---|
| Operating host | Dedicated nologin meepcoin account, separate persistent chain/log/receipt directories, root-owned release/configuration, low CPU/I/O priority, shared one-core and task ceilings, manual start/stop, no boot enablement or restart loop |
| HTTPS | `https://mine.meepcoin.me` through an outbound named Cloudflare tunnel; public CA and hostname validated, loopback origin certificate validated; native RPC/P2P remain loopback-only; wrong Origin/Host and unauthenticated API requests rejected; public native RPC route returns 404 |
| Release | Fresh pinned v17 genesis, full native rebuild, real LMDB controls and native PoW KAT pass, hash-qualified Wasm and dependency reuse, fresh launch database and immutable final archive |
| Deployed rehearsal | Actual browser blocks, independent native proof/target readback, exact coinbase wallet balance with immature rewards locked, real node outage/readiness closure, invitation rotation without deadline extension, actual automatic expiry, expired restart refusal, cold backup and restore |
| Advertised browsers | Windows Chrome and genuinely visible Mac Safari 26.6.2 each mined through public HTTPS on the final artifact; Safari used a real WebDriver click and document.hidden=false; workers stopped and its automation session/driver group were cleaned up |
| Rules/review | Published participation/reset/stop notice and non-secret GitHub issue channel, focused Claude model review, final package/unit hash binding and recorded limited-scope decision |

The final Chrome block at height 4 is `80681b4b0e0ac5cc5364db14e797398ba32ee278b6c80e68677d875b0eccac79`. The final Safari block at height 5 is `b843183e1f4140e1913427968b130f23d48abb1241fd28153cadffedc08f7a24`. Both are canonical v17 blocks and their stored native PoW hashes satisfy the complete 256-bit difficulty target. The exact fresh-wallet total is **2384180675111 atomic units**; unlocked balance is zero. This final session's absolute UTC Unix interval was 1791850830 to 1791851130.

The gateway exited successfully at the persisted deadline, its connector stopped, and directly restarting the expired service CLI was rejected. A cold backup was restored into a new data path and recovered the same canonical tip while the original backup hash stayed unchanged. All owned cgroups were empty afterward. Previously running service names remained running; this is a lifecycle observation, not a robot/camera functional benchmark.

## Resource limit correction

The host boots with its memory cgroup controller disabled. The release honestly uses sampled whole-cgroup RSS, per-process RLIMIT_DATA/AS, file/core limits, OOM priority ordering and systemd CPU/task controls. It has no kernel memory-cgroup ceiling.

Live inspection rejected the first tmpfs configuration because PrivateTmp=yes masked the size-limited mounts. A second probe rejected default root-only mount permissions. The final configuration uses PrivateTmp=no with independent TemporaryFileSystem mounts for /tmp and /var/tmp, each 16 MiB with mode1777; /dev/shm is inaccessible and /run is read-only. The explicit mounts themselves provide isolation. An actual write probe reached ENOSPC above the cap. The final node, gateway, connector and disposable wallet each passed actual mount-size, writable-uid and rejected-path checks as uid999. Failed configurations/probes and earlier Safari hidden-window attempts remain preserved.

## Later participation and remaining work

The completed rehearsal is not an always-on mining service. A later session needs its own fresh launch packet, deliberate start and private invitations tied to participant public testnet reward addresses. Preserve this chain and its evidence; a reset uses new genesis/network identity and new database paths with a notice. Do not bypass the first-start freshness rule or silently extend an expired epoch.

Full Windows/macOS native node and wallet distributions, mobile endurance, broader independent security review, permissionless P2P and mainnet remain unqualified. Low participation can stall blocks and rewards may never mature within a quiet experiment. No profitability, token value or fixed block-time promise is made.

The primary website is https://meepcoin.me. Its HTTPS page and HTTP-to-HTTPS redirect were observed; the optional www HTTPS alias still failed certificate validation and is not advertised. The mining hostname has separate validated HTTPS. Report non-secret incidents through https://github.com/jjtseng-jjtseng/Meepcoin/issues/new/choose; no personal email is published.

## Evidence and operations

The local deployment packet is `deployment-20261012/DEPLOYMENT_FINAL.json`, which hashes the final public RESULT/CLEANUP, actual-unit mounts and file hashes, root installation receipt, package receipt, visible Safari result/cleanup, review and retained tmpfs correction evidence. The first and second rehearsals are separately retained; neither substitutes for the final package's pass. The final summary independently checks rewards, targets, Safari/native hash correspondence, cleanup, mount limits, package SHA and source/package equality.

Use [PI_OPERATIONS.md](PI_OPERATIONS.md) for owned service stop/recovery and [INVITATION_EXPERIMENT.md](INVITATION_EXPERIMENT.md) for participant rules. Keep secrets and private invitation URLs out of public diagnostics. The frozen original checkout and halted legacy campaign remain separate and unchanged.
