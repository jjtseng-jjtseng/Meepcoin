# Fresh two-device public-endpoint rehearsal - October 16, 2026

The signed `0.2.0-rehearsal.5` participant distributions were installed on the
owner's Debian 13 ARM64 Pi and macOS 26 ARM64 Mac. Both local encrypted wallets
used their own local native nodes through individually restricted private P2P
routes. Real Chromium/Chrome mining used `https://mine.meepcoin.me`; native RPC,
wallet RPC, signing keys and recovery words remained on the participant devices.
The immutable qualification epoch is 04:39:28-05:39:28 UTC on October 16, 2026.
This is a finite two-owner-device experiment, not unrestricted public admission.

| Area | Actual completed engineering evidence |
|---|---|
| 1. Identified release | Fresh compile-time v17 genesis `1792125000`, pinned native/Wasm and wallet sources, three signed archives, separate real Pi/Mac installation, safe extraction and every shipped file hash verified |
| 2. Participant journey | Real public browser blocks; native full-width PoW and canonical rewards; canceled payment without relay; Mac-to-Pi 1 MEEP payment with exact fee and 12 confirmations; same address, exact total/unlocked balance and all 27 full history rows after recovery |
| 3. Operating period | One immutable hour, sampled resources every five seconds, real outage/restore, same-database Mac reconnect, individual Mac revocation and rejected same-key re-entry; terminal expiry/backup/restore recorded separately after observation |
| 4. Quiet-chain behavior | 124.467-second unchanged quiet phase, explicit new Start, observed 600-second stall latch in 1.04 seconds, and closed admission preserved across gateway restart; no elapsed block-time or maturity guarantee |
| 5. Failures and security preparation | Actual startup/crash/ownership containment, real ENOSPC, lost-relay reconciliation and copied-LMDB corruption refusal; capability/origin/CSRF/idle-lock boundaries; public RPC paths refused; exact review packet prepared for external human review |
| 6. Release and decision | Detailed plan received non-coding 9.4/10 approval; signed archives and public evidence preserved; final work scores and terminal closure are separate recorded gates; human consensus/cryptography/security review remains required before broader admission |

The native chain reached height 54 (genesis included), tip
`ae55e999e5d6254b9fcf6450121a94be40f8b6f005e368e4ae55f930726c4a85`.
Payment hash: `adf21b434ba88a292ebd292aec331978f5e20606665ab0695bca364887318125`.
Its fee is 86,600,000 atomic units (0.000866 MEEP). One MEEP is
100,000,000,000 atomic units. Final Pi total/unlocked: 31,094,242,110,130;
Mac total: 32,085,867,929,156, unlocked: 21,357,282,546,191.
The Mac's 10,728,585,382,965 immature atomic units match the exact native
coinbase outputs. Recovery compared complete history rows, including duplicates,
without depending on incidental native ordering of equal-timestamp rows.

The original Pi browser aggregate failed twice: native idle-lock preparation
and an order-sensitive recovery assertion. The driver subsequently completed
separate explicit native/UI payment and full-row recovery checks. Do not relabel
the original aggregate as an uninterrupted pass. The original Mac aggregate
passed. Both browser/driver owned groups drained and wallets finished locked.
The first Mac headed hide attempt timed out; the raw-CDP follow-up observed
actual hidden state and cancellation. The successful hide/reload follow-up
interrupted an instantiated worker while Preparing, before a hash-progress
event. Canonical browser blocks separately establish real hashing/submission.

Supported initial participant browsers are Pi Chromium 151 and Mac Chrome 155.
Earlier Safari mining evidence concerns a different epoch; this release does not
claim Safari wallet qualification, mobile endurance, outside-home participant
access, Windows native packaging, Intel Mac, eight-user load, host power-loss
durability, automated host handover or an external human security audit.
The eight-invitation setting is an admission cap; only two devices were exercised.
The memory cgroup controller is disabled on this Pi: sampled RSS and process
limits are used, and no kernel memory-cgroup ceiling is claimed.

See [OWNER_REHEARSAL_20261015.md](OWNER_REHEARSAL_20261015.md) for installation,
publisher authentication, private peer access, encrypted wallet backup/recovery,
operation, safe upgrade/removal and incidents. See
[READINESS_PLAN_20261015.md](READINESS_PLAN_20261015.md) for the detailed six-area
plan. Public GitHub issues are the incident channel; omit wallet files, passwords,
seeds, private keys and capability URLs. Preserve this network after expiry;
a later session needs a new scheduled genesis, signed artifacts and exposure
decision. Human review is a real remaining public-launch requirement.
