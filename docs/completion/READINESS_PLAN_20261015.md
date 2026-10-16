# MeepCoin: six remaining readiness areas

Prepared 2026-10-15. This is a new work package after participant.2, not a replacement for its evidence. Product baseline: `07c22275972ec405a0a5d0b86c5b8c63473747cc`; curated source baseline: `6b07ef3e58a6d4fd9015b4145ea321a2f44cdd90`. Existing participant evidence: `../participant-20261015/HANDOFF.json`.

## Intended result and review gates

Deliver a reproducible, finite desktop testnet release and operator procedure, qualified on the owner's Debian 13 ARM64 Pi and macOS 26 ARM64 Mac. Browser wallet keys remain on the participant device. Public browser mining uses `https://mine.meepcoin.me`; native node/wallet RPC remains loopback and native peers use individual restricted, revocable, pinned SSH routes. Declare only browser/platform combinations actually exercised on the release. Mobile, Windows native packaging, permissionless native peering, mainnet and real money are outside this first scope.

The user requested two independent sub-agent reviews. A non-coding reviewer must score this plan **strictly above 9/10 before implementation**. It may inspect existing sources and evidence read-only. After implementation another reviewer must score every necessary area, with **at least 8/10 per area**, against the criteria below. Neither reviewer may change code, manufacture evidence, or treat a promised future result as a pass. Revise defects and rerun affected checks before asking for another review. Record the review text, scores, source hashes and unresolved issues.

A completed bounded owner-device rehearsal is distinct from an unrestricted public launch. An independent human consensus/cryptography/security audit is an external release gate for broader public enrollment; an AI review cannot satisfy it. Prepare an exact review packet and leave broader launch disabled if that gate is absent. Do not claim everything is ready merely because scoped software work or a model review passes.

## Shared execution and preservation contract

* Work in the isolated product checkout and new dated run directories. Preserve frozen production, protected `.wakatime-project`, `retypes/`, `results/NATURAL_20260927T123517Z/`, historical failed attempts, existing databases, user wallets and live-campaign evidence. Never read or include private credentials in receipts, public source exports or model prompts.
* Pi robot/camera, XMRig/P2Pool and other workloads remain running. Use existing private toolchains and dependencies, low priority, at most one build job per host, explicit CPU/RSS/disk/log budgets, no system package changes, power changes or host reboot. Inspect current availability before starting. Refuse unexpected occupied ports. Mac heavy existing load is a constraint; defer or lower concurrency instead of interrupting it.
* Every owned service/process has a finite deadline, exact run identity, stop action and verified terminal cleanup. No autostart or automatic renewal. No automatic retry of an uncertain block/transaction submission. Save results even on failure. Keep fixture/regtest, synthetic faults and real v17 public traffic distinctly labeled.
* Before public traffic, freeze code and build fresh genesis late. Never bypass first-start freshness or mutate an old network identity. If build/rehearsal misses its freshness window, preserve that attempt and schedule a genuinely new release/network, explaining the failure.
* Collect raw nonsecret receipts on each host, download and independently hash them, bind their version/genesis/source, verify arithmetic with integer atomic units and native canonical data. Report sampled memory as sampled, not a kernel-enforced ceiling. Do not count a compilation, source test or receipt-writing success as a runtime result.
* No need for public email: existing GitHub issue tracker is the participant incident channel. Never send unsolicited messages or request review from another person without authorization.

## 1. Build and identify the next active testnet release

Problem: participant.2 installation is qualified, but its network epoch has expired. The old deployed gateway uses another historical network. They cannot be combined into a current experiment.

Implementation:

1. Inventory exact relevant release/gateway/tunnel settings read-only, without dumping credentials. Check Pi/Mac time, toolchain, resources, approved ports, certificate behavior and current service state. Record source and artifact hashes.
2. Add or complete a parameterized release assembly path using existing builders/packagers. Require a new version, explicit genesis timestamp/network identifier, pinned native and wallet/browser/gateway source, clean source archive and platform manifest. Reuse only verified dependencies, not stale binaries with a new label. Rebuild genesis-dependent native programs on both hosts with one job; verify all three native programs and PoW known-answer tests.

   Build schedule: first measure/rehearse the incremental native build using a clearly non-launch timestamp and fresh output directory or copied verified build cache. Freeze code before scheduling a final genesis no more than 45 minutes ahead, with a conservative measured build/package/install allowance and at least 10 minutes spare. The persisted epoch begins at or after that genesis, after both installs and clock/identity checks; it ends <=3600 seconds later. If either build/package/install misses genesis+30 minutes, do not start the public experiment; preserve the failed schedule and create a separately identified new release with a new timestamp. Never make a future timestamp eligible by changing a clock or weakening timestamp validation.
3. Produce matching Pi and Mac participant archives plus the operator gateway/node package. Bundle qualified libraries, preserve relocatable Mac loader paths/ad-hoc signatures, include licenses and runtime preflight. Signed descriptors bind archive size/hash/platform/genesis. Independently verify publisher key, signature and every installed file before start.
4. Select fresh isolated operator and participant data paths; create no personal wallet. Configure the existing authorized outbound tunnel for the new bounded release. Keep `/json_rpc`, native wallet methods and P2P inaccessible from public HTTP. Exact public origin and private peer identity must match the release.
5. Record an immutable release packet: source commits/archive hashes, binary hashes, Wasm hash/toolchain, genesis time/hash, signer fingerprint, network rules, expiry, supported scope and download locations. Publish draft assets first; public launch artifacts require the recorded scope decision in step 6.

Pass criteria: both signed installations and native identity readbacks agree; no stale database reused; public CA/hostname verification succeeds; public native RPC/P2P probes fail; private node/wallet interfaces bind only loopback; incorrect signature, foreign genesis and expired invitation are refused; all package files and evidence are independently hashed. No secrets in artifacts. Freshness failure remains a failure.

Evidence: release manifests, signed descriptors, install/native identity receipts on both hosts, TLS/public-route checks, private-interface inspection, source/export and artifact hash index. Dependency: all code/fault fixes completed before final fresh build.

## 2. Exercise the actual installed participant journey

Problem: wallet onboarding, old public browser mining, and offline reward/payment rehearsals passed separately. The installed participants need one integrated journey on the new public v17 release.

Implementation:

1. Start individual restricted peer routes with pinned server keys, separate credentials and absolute expiry. Start installed Pi/Mac nodes and companions with private local data. Observe native version/genesis/synchronization rather than assuming readiness from an open port.
2. Use real browser forms on Pi Chromium and Mac Chrome to create disposable encrypted wallets, acknowledge backup, clear displayed words, lock/unlock and reject a wrong password. Keep seeds/passwords exclusively in browser/device memory; public receipts may contain addresses, transaction IDs and amounts only.
3. Visit the actual public HTTPS miner with a private capability; deliberately start one worker. Confirm idle before start, stop on hide/navigation/reload, no auto-resume and bounded nonce batches. Record accepted browser candidates and canonical native block headers; independently recompute native PoW and target satisfaction. Check the miner's reward address and exact integer wallet reward.
4. Mine sufficient **real accepted blocks** to satisfy coinbase maturity and decoy availability. No fixed-difficulty/regtest fixture block is represented as a public-browser block. If the finite window cannot satisfy this, record partial evidence and the precise limiting condition; do not weaken maturity or alter difficulty silently.

   Feasibility gate before committing the final one-hour epoch: measure each browser's real v2 Wasm throughput for 60 seconds, read native coinbase unlock window (currently 10) and ring size (currently 16), and read the current chain's unlocked output count. The mathematical lower bound is 16 eligible outputs plus 10 maturity blocks; the existing wallet sampler may require more (the prior fixture used 64). Reserve up to 64 funding blocks plus 12 post-payment blocks, not an assumed single mining success. Model the pinned integer ASERT trajectory from the proposed genesis at the measured combined rate, report expected time and a conservative 95th-percentile PoW time budget, and require funding/payment/confirmations <=2400 seconds, onboarding <=300 seconds, quiet pauses 300 seconds (120+180), and recovery/cleanup margin >=600 seconds within 3600. Some phases may overlap telemetry, but simultaneous real mining on two browsers is allowed only within one worker per device and the host budget. If the conservative estimate does not fit, do not start a release advertised to complete this journey. Record the exact feasibility blocker and propose a separately reviewed longer finite-epoch policy or a smaller justified sampler requirement; never silently extend an existing epoch, generate fake funding, or promise a passing result. During execution, abort the payment attempt by minute 45 if adequate eligible outputs are absent; preserve public mining and maturity evidence as partial. Use a 10-minute hard ceiling per individual browser mining wait and retain the overall absolute deadline.

   Determine a practical funding target on a labeled fresh isolated regtest rehearsal using the actual wallet transfer/decoy sampler: probe quote readiness at heights 26, 32, 40, 48 and 64, without relaying probe transactions; report failures and the first successful target. Only an actual successful quote justifies a smaller target. The public run must independently obtain a successful quote and maturity readback at that target, with real browser blocks. Default to 64 until the sampler evidence exists. Reserve 12 real post-send blocks to exercise confirmation and recipient unlocked-balance readback; keep canonical credit and spendable credit separate.
5. Quote then cancel a transfer and verify no pool entry. Quote a small testcoin payment, explicitly confirm, reconcile the exact tx ID/pool entry, mine confirmations and verify sender amount+fee and recipient exact credit from independent local native wallets. Never automatically resend an unknown outcome.
6. Restore one participant into a separately named wallet using the locally retained backup; compare address and canonical balance/history. Reject existing destination names. Demonstrate reload locks the original wallet. Explicitly stop both sessions and verify all owned native groups/tunnels/listeners end while databases remain.

Pass criteria: actual public HTTPS blocks accepted from both supported desktop browsers; native PoW matches; canonical reward, maturity and payment amounts/fees agree exactly; cancel has no side effect; restored wallet recovers address and balance; hidden/reload/stop safeguards work; keys never reach operator/public host. Safari is advertised only if the exact journey passes in a genuinely visible window; otherwise retain its earlier mining-only qualification and state the narrower wallet scope.

Evidence: public browser action/candidate receipts, independent canonical headers/PoW, wallet accounting, cancellation/pool/confirmation/restore checks and cleanup. Dependency: step 1 matching fresh release, enough remaining session time.

## 3. Qualify a useful operating period

Problem: a short happy-path run does not establish a finite experiment can be operated reliably.

Implementation:

1. Preserve initial exposure limits: two owner devices during qualification; at most eight independently revocable invitations and one hour per later approved experiment. No paid server needed for this bounded test. Define CPU, task, aggregate sampled RSS, disk headroom, log and tmpfs limits, heartbeat/readiness thresholds and absolute expiry in machine-readable policy.

   Numeric budgets: operator services share <=100% of one CPU; connector <=30%, each restricted SSH service <=20%, native participants use one native concurrency thread, builds use one job and nice 10. Operator total tasks <=128; peer-service tasks <=32 each. Existing 16 MiB service-private tmpfs mounts remain bounded and verified. Native rolling logs <=2 MiB per process (two 1 MiB files), process/controller output <=16 MiB per session, aggregate evidence/log growth <=128 MiB per owned session; exceeding a limit closes admission and stops the owned run. Sample every 5 seconds; a telemetry gap >15 seconds invalidates continuous-coverage evidence. Readiness must close within 5 seconds of observed native RPC loss, requests timeout <=15 seconds, pending sends remain unknown until explicit exact-hash reconciliation. Recovery target <=120 seconds for same-network unexpired restart; no deadline extension or browser auto-resume. A failure to meet a target is a retained failure, not rounded into a pass.

   Tunnel loss makes the public endpoint unavailable even if the local gateway is healthy; the observer records this distinction. Check last canonical progress every 5 seconds; close admission within 5 seconds after the 10-minute stall threshold. For interrupted sends, persist the intended exact hash before dispatch, show unresolved/unknown in the wallet, block new sends, and resolve only from exact-hash native outgoing/pending/failed history plus canonical/pool evidence. An absent hash alone never proves no relay. Unresolved outcomes at deadline require explicit later operator/user reconciliation, not resend.
2. Run one continuous target **30-minute** deployed rehearsal within a one-hour epoch. Include the wallet journey if feasible. Sample timestamps, height/tip, connected peers, RPC/gateway readiness, per-owned-unit CPU/RSS, disk/log size and service state at most every 10 seconds. Fail on memory >1536 MiB operator budget or >2 GiB participant native budget, <1 GiB free storage, runaway logs, unhandled process exit or inconsistent identity.
3. Exercise participant disconnection/reconnect without changing its database; revoke only that participant and verify the other remains connected. Stop/restart only owned gateway/node/tunnel units with the same unexpired network and preserved database. During loss, public readiness/jobs close and uncertain submissions reconcile; restoration does not restart browser workers.
4. Exercise deliberate operator stop, automatic absolute expiry, refusal to restart an expired session, owned-cgroup/process emptiness, and preservation of unrelated initially running services. Take a cold consistent backup and restore into a different path; compare canonical tip and relevant balances.
5. Provide an operator status/stop/backup/restore procedure and executable checks. Keep monitoring bounded to the run; no unattended recurring automation.

Pass criteria: >=30 minutes actual timestamps without budget/identity violation; failure drills produce closed admission, bounded recovery and correct canonical readback; revocation is individual; expiry closes all owned public/private entry points; restart after expiry refused; backup independently reopens at the same tip. Failed drills are retained and fixed, not omitted from the report.

Evidence: telemetry series with coverage/gaps, fault timeline, stop/expiry and backup restore receipts, before/after unrelated service comparison. Limits: this qualifies a one-hour desktop experiment, not days of continuous availability or eight actively mining devices unless those are actually tested.

## 4. Decide quiet-chain usability from evidence

Problem: the ASERT study showed long stalls for low participation and large departures. A permanent 60-second block promise would be false.

Implementation:

1. Retain existing healthy integer difficulty arithmetic and study results. Read the relevant v17 rule/constants and bind the report to them. Do not substitute the model's average for a live availability guarantee.
2. During the live run, include an intentional no-miner interval of at least 120 seconds and a low-participation interval of at least 180 seconds, then resume deliberate mining. Record accepted-block times, target difficulty, local work rate and readiness. Verify no-miner intervals do not create blocks, stale jobs are refused/reconciled, departure does not corrupt accounting, and resumption uses the same canonical chain.
3. Define participant-facing behavior: display no-miner/stalled state and last-block age; avoid promising completion time for payments/maturity. Operational stall threshold is **10 minutes without a canonical block** while mining is intended; stop admission, preserve chain, explain the condition and end the finite experiment if recovery cannot occur inside its deadline. Do not secretly reset/credit balances.
4. Write a concrete decision: acceptable only for a bounded owner/invitation experiment with known stall risk, or rejected pending a separately versioned consensus proposal. For broader enrollment, require human review of liveness evidence and a new decision. If a consensus change is necessary, stop promotion of v17 and specify/build/test a new separately identified network; never relabel v17.

Pass criteria: real quiet/resume observations, exact pinned difficulty policy, UI/rules accurately communicate delay, executable stall rule closes admission, no silent reset or accounting discrepancy. Do not label a 5-minute observation as proof of rare-event or adversarial liveness.

Evidence: live quiet/departure/resume trace, targeted stall-rule test, existing model reference and documented scope decision. Dependency: telemetry from step 3; policy/UI changes occur before fresh final packaging.

## 5. Close failure-handling gaps and prepare security review

Problem: normal cleanup passed, but forced-controller death, storage failures and restoration have not been qualified on the installed packages.

Implementation:

1. Fix participant child ownership so a killed controller cannot leave an unbounded node/wallet/SSH workload. Use an independently bounded guardian and/or OS-supported ownership primitives. Bind process identity to session/run/creation identity; never kill a reused PID or unknown process. Expose an explicit recover/status path for stale session controls, preserving receipts and database. Cover parent death during startup as well as READY. Preserve orderly native shutdown first, bounded escalation last.
2. On **both Pi and Mac**, run isolated actual-native sessions, kill the owned controller with SIGKILL, verify its guardian detects loss, all native/tunnel/listener descendants terminate within a stated bound, stale control is recoverable safely, and the same database reopens with the same genesis/tip. Repeat a meaningful startup-boundary case. Do not power-cycle the host or kill unrelated processes.

   Crash bounds: detect loss of the controller's ownership channel within 2 seconds; attempt orderly descendant shutdown for at most 30 seconds, then bounded escalation/reaping <=10 seconds. Require all owned listener/native/tunnel descendants gone within 45 seconds after SIGKILL; explicit stale-control recovery and same-database identity/tip readiness <=120 seconds. Test both loss before READY and loss after READY. Include a still-running unrelated sentinel and a forged/reused PID receipt as negative controls: recovery must refuse uncertain ownership and preserve those processes. A guardian cannot make a host power cut safe; actual power-loss durability remains separately labeled unqualified.

   Stale recovery prerequisites: private owned directory and regular non-symlink session receipt, matching genesis/release/session nonce and unchanged control-socket inode, guardian terminal receipt proving all owned descendants drained, and no live control listener. Recover removes only that stale socket and appends a recovery receipt. Missing/malformed/nonterminal ownership proof is refused without signaling any PID or deleting files. Prefer a live pipe/child relationship over persisted PID ownership; receipts alone never authorize process termination.
3. Inject disk-full at concrete wallet/journal/release/node boundaries using small isolated capacity limits or targeted write errors. Exercise corrupt/truncated **copied** data and detect/refuse without overwriting originals. Distinguish an injected syscall failure from real filesystem ENOSPC. Include at least one real bounded ENOSPC check where feasible without changing host mounts globally.
4. Verify interrupted send reconciliation across companion restart: an unknown send cannot be repeated automatically, operator/user sees the unresolved state, canonical/pool lookup resolves the exact intent or requires explicit safe handling. Test backup restoration independently, including wrong password and conflicting destination. Keep seeds/passwords local.
5. Review host/origin/CSRF, bootstrap one-time capability, private RPC/P2P, signed downloads, unsafe archives, stale/foreign sessions, revocation, process identity, logs and secret export against the current exact source. Reuse prior evidence where unchanged; rerun changed boundaries. Fix concrete findings and add focused regressions for meaningful failure behavior.
6. Produce a human review packet: exact source/artifact hashes, architecture/trust boundaries, consensus/economics, realistic threat model, test evidence/limitations, known issues, reproduction commands and explicit audit questions. A model's score does not close the human cryptography/security gate for broader launch.

Pass criteria: crash cleanup/restart passes on both platforms; unknown processes preserved; storage/corruption failures fail closed without original-data loss; interrupted sends cannot duplicate; backup restore correct; no open high-severity actionable finding within implemented scope. Report each untested hardware/power-loss aspect explicitly.

Evidence: per-platform crash receipts and descendant identities/ports, storage fault/corrupt-copy/journal reconciliation results, backup hashes/readback, focused tests and review packet. Dependency: fix early before packaging; repeat on final installed release where relevant.

## 6. Record the launch decision and release operation

Problem: usable software needs a truthful participant contract, reproducible launch/stop procedure and an explicit exposure decision.

Implementation:

1. Update participant guide, website/miner notice and operator runbook with the exact tested release, desktop scope, one-worker voluntary mining/stop behavior, testcoin/reset/maturity/stall expectations, private local wallet backup responsibilities and GitHub issue contact. No claim of financial value or guaranteed profitability. Explain 0.125 MEEP tail emission accurately; no false fixed supply cap.
2. Create a machine-readable launch decision bound to exact manifests, evidence and review scores. Each of the six areas has PASS/PARTIAL/BLOCKED and explicit evidence. Scope must not exceed qualified owner/invitation exposure. Missing human audit blocks unrestricted public enrollment, not preparation of its packet.
3. Run the requested final independent sub-agent review of every necessary area. Require >=8/10 each; resolve findings and rerun affected checks. Separate quality score from empirical pass criteria. Never change thresholds or hide failed attempts to obtain a passing grade.
4. Publish approved source/guide/artifacts through existing GitHub accounts with signed release descriptors, verified download hashes and accurate draft/prerelease status. Attach any created PR to this chat. Enable public enrollment or a continuing public service only if its specific release decision is satisfied. Do not leave an expired rehearsal serving usable capabilities.
5. Execute one finite launch/stop rehearsal of the final release within scope. Finish with all owned qualification services stopped, all capabilities expired/revoked, unrelated workloads preserved and a user-readable status describing exactly what can be started next, how, and which external gates remain.

Pass criteria: declared scope matches actual results; no missing required evidence counted as complete; review >=8 each for the scope claimed; published downloads verified; launch/stop/expiry reproducible; public enrollment stays disabled if its broader review gate is missing. Final report includes detailed per-area result and external dependencies, not a generic readiness percentage.

Each final area records two verdicts: engineering implementation/tests and release admission. Two exercised devices do not qualify eight-device load capacity; eight is only an invitation cap until independently exercised. A high model quality score cannot override a failed empirical check or external launch gate.

Evidence: final reviewer report, exact decision JSON, published/draft artifact URLs/hash receipts, updated guides/notice, launch/stop checklist with actual terminal results.

## Work order and finite stopping rules

Plan review -> focused source/fault fixes and tests -> staging orchestration/policy/UI -> freeze sources -> fresh genesis/build/package on both hosts -> signed installations -> integrated deployed mining/payment + 30-minute telemetry and quiet/failure drills -> independent evidence verification -> final review/fixes -> scoped release publication and decision -> clean stop/handoff.

Do not open another compiler/framework investigation: reuse the working Pi/Mac native builds and pinned dependencies. A host failure gets a concrete diagnosis and bounded correction; preserve the failed run. If a truly external prerequisite is unavailable (domain authorization, awake Mac, human audit), complete independent work, record the precise missing gate and do not claim that gate passed. This is a plan to complete all feasible engineering and expose remaining dependencies honestly, not a promise to invent unavailable evidence.
