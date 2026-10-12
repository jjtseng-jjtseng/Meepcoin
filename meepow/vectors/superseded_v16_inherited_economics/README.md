# Superseded — version-16 vectors under the INHERITED economics

These are the version-16 block consensus vectors as they stood **before the economics freeze**, when
the daemon still compiled Monero's inherited constants:

| | Value at the time |
|---|---|
| `MONEY_SUPPLY` | 18,446,744,073,709,551,615 (2⁶⁴−1) |
| `COIN` / decimals | 10¹² / 12 |
| Effective emission shift | 20 |
| Genesis reward | 17,592,186,044,415 atomic = 17.592186044415 |
| Tail reward | 300,000,000,000 atomic = 0.3 |
| Devnet genesis hash | `7b98d85f7e19d89aebea0c48515713a22c56cc59d4bc2b6d98bd627fb79229a5` |

They are kept rather than overwritten because they are the record of a validation that actually ran,
and because the PoW values in them remain independently reproducible: **MeepHash-W v2 is frozen and
does not depend on economics.** Every PoW hash in these files can still be recomputed from its
recorded blockhashing blob, and `node/revalidate_v16_vectors.py` did exactly that — 46/46 — after the
hard-fork patch and before the economics change.

## Why they no longer apply to the live chain

Changing `MONEY_SUPPLY` and the emission speed factor changed the genesis coinbase amount, which
changed the genesis block blob, which changed the genesis block hash. Because the epoch seed for
every height ≤ 2112 *is* the genesis hash, every PoW input on the chain changed with it. The chain
these vectors describe no longer exists; its coins were dev/test coins with no monetary value.

Current vectors, under the approved 11-decimal / 25-million / shift-21 economics:

- `../block_vectors_v16_devnet.json`
- `../block_vectors_v16_altchain.json`

See also `../superseded_v1/` for the earlier pre-version-16 set.
