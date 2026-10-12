# Harness compatibility: the removed experimental-genesis hook

## What changed

`cryptonote::generate_genesis_block()` no longer reads `MEEPCOIN_EXPERIMENTAL_GENESIS_TS`.
The genesis timestamp is `MEEPCOIN_GENESIS_TIMESTAMP`, a compile-time constant, and there is
no runtime override of any kind — not an environment variable, not a command-line flag.

## Why it had to go

`generate_genesis_block()` is **shared production code**, not a test helper. It is reached from:

- `Blockchain::init()` (`src/cryptonote_core/blockchain.cpp`), when the daemon initializes an
  empty database, i.e. on every first start of every node;
- `wallet2` (`src/wallet/wallet2.cpp`), when the wallet derives the network's genesis;
- the MeepCoin genesis tools and tests.

With the override in place, two copies of the **same binary** could construct **different genesis
blocks** — different timestamp, different hashing blob, different block id, therefore a different
chain — solely because one of them inherited an environment variable. Nothing about that is
detectable by the other node until the handshake fails, and nothing about it is fixed by the loud
red warning the old code printed. A genesis that depends on the environment is not a genesis.

Replacing it with an ordinary runtime flag would have the identical defect, so it was removed with
no replacement.

## What this breaks, and what was deliberately *not* done

The older Python measurement launchers set `MEEPCOIN_EXPERIMENTAL_GENESIS_TS` so that a throwaway
experiment chain could be started with a genesis age near zero. Those launchers depend on a hook
that no longer exists.

**They are NO-GO until separately redesigned.** They were deliberately **not** edited in this
round, and the old measurement machine was deliberately **not** revived:

- editing each script would imply they are expected to run again in their current form;
- a fresh-genesis capability for isolated experiments is a real need, but it belongs in a
  *separate build* (a compile-time constant chosen at configure time, or a dedicated
  experiment-only target), not in a runtime switch inside shared production code.

That redesign is out of scope here and has not been done. Anyone reaching for those scripts should
expect them to produce the compiled genesis regardless of what they set in the environment.

## What still works

- `meepcoin-genesis`, `meepcoin-genesis16`, `meepcoin-blockhashing` and the focused tests all use
  the compiled constant and are unaffected.
- Nothing about the genesis **values** changed: `MEEPCOIN_GENESIS_TIMESTAMP`, `GENESIS_TX`,
  `GENESIS_NONCE`, the network IDs, ports and address prefixes are byte-identical to the previous
  commit. Only the ability to override the timestamp at runtime was removed.

`meepcoin-runtime-quarantine-test` asserts exactly that: with the variable absent and with it set
to two different valid-looking timestamps, all three networks produce a byte-identical genesis.
