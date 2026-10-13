# Dedicated Pi invitation deployment

The operator host is jaypi.local (Debian 13 ARM64). The dedicated `meepcoin`
account has no login shell. Code and service configuration are root-owned;
chain data, logs and owner-only invitations are under its separate persistent
directories. Existing robot/camera services and unrelated mining are outside
this deployment.

The public miner hostname is https://mine.meepcoin.me. A named Cloudflare tunnel
connects outward to the edge; no router port forward is required. It forwards
only that hostname to the loopback gateway and validates the origin certificate.
Other hostnames receive 404. Native RPC and P2P remain bound to IPv4 loopback and
are never tunnel routes. The website stays on GitHub Pages at https://meepcoin.me.
The incident channel is the repository's public issue form; no email is required.

## Start, stop and expiry

The installed units are `meepcoin-node.service`, `meepcoin-gateway.service` and
`meepcoin-tunnel.service`. They are disabled at boot and have `Restart=no`.
An operator starts the node, verifies network identity, creates an owner-only
configuration with `pool/private/configure_testnet.mjs`, starts the gateway,
verifies authenticated readiness, then starts the tunnel. Use the concrete
immutable release path for the service's Node entry module.

For an emergency stop, an administrator runs:

```sh
sudo systemctl stop meepcoin-tunnel.service meepcoin-gateway.service meepcoin-node.service
```

Stop the connector first to close public admission. A candidate already sent to
the native node needs canonical reconciliation before retrying. Check each unit's
`ActiveState` and empty `ControlGroup`, then verify the owned ports have closed.
Do not kill unrelated processes by executable name.

The conservative watchdog returns exit 1 for an explicit operator signal, even
when the native child shuts down with exit 0. Consequently systemd can retain a
`failed` state after a deliberate stop. Check the watchdog's `operator_signal_15`
receipt, native child exit code, empty cgroup and closed owned ports to interpret
that state. The final cold restore passed after this exact shutdown behavior.

Every gateway configuration contains an absolute start and end, at most one hour
apart. Its first start must be within one hour of the pinned genesis. The process
also uses a monotonic deadline. Restarting cannot extend that saved epoch; an
expired configuration refuses startup. The tunnel is bound to the gateway and
stops when it expires. A later experiment requires a deliberately reviewed new
packet; there is no automatic epoch renewal or computer handover.

## Resource and secret boundaries

All units share a CPU quota of one core with low scheduling/I/O weight and a
128-task slice ceiling. The connector has an additional 30 percent CPU ceiling.
The watchdog samples the whole unit cgroup, including detached children. The Pi
boots with the memory controller disabled: RSS sampling is not a kernel hard
memory ceiling. Children also have RLIMIT_DATA, address-space, file and core
limits. Node has a bounded old-space heap. OOM scores prefer killing the workload
over its watchdog. Final units additionally bound `/tmp` and `/var/tmp` to 16 MiB
each, make `/dev/shm` inaccessible, and make `/run` read-only.

Tunnel credentials, TLS keys, invitations and disposable wallet files must never
be committed or included in public diagnostics. The Cloudflare account-management
certificate is root-only and inaccessible to the connector. The connector has
only its tunnel-specific credential. The mining gateway holds public reward
addresses, not spend keys. Wallet RPC is a separate bounded, loopback-only
disposable process used for qualification, not a public service.

Keep databases on persistent disk. A cold backup is taken only after owned native
processes stop. Hash the backup, restore into a new path, verify the canonical tip,
then prove the original backup hash stayed unchanged. Preserve failed attempts
and old network directories. Never silently replace a participant chain.

## Supported scope

This deployment supports a finite desktop Chrome and Safari invitation experiment
with test coins and at most eight invitations. Safari 26.6.2 completed a genuinely
visible public native submission on the final package. A hidden Safari document
must remain unable to mine. Mobile and sustained battery/heat behavior are
unqualified. PrivateTmp=no is deliberate: the two size-limited TemporaryFileSystem
mounts supply isolated temporary paths, and PrivateTmp=yes would mask their caps. The public participant
notice is [INVITATION_EXPERIMENT.md](INVITATION_EXPERIMENT.md).

The real deployment receipts and the exposure decision are described in
[LAUNCH_DECISION.md](LAUNCH_DECISION.md). Focused independent model reviews do not
constitute an external security audit or mainnet approval.
