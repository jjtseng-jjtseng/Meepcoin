#!/usr/bin/env python3
"""Directed P2P adjacency: prove the topology instead of trusting a connection count.

Earlier long runs recorded peer counts of h1=2, h2=1, atk=1. That is two undirected links -- a
star centred on h1 -- not the three-edge full mesh the conclusions assumed. A total count cannot
distinguish the two, so this module reads `get_connections` and reconstructs WHICH node is on the
other end of every link.

The awkward part: for an OUTGOING connection `port` is the peer's listening P2P port, but for an
INCOMING connection it is the peer's ephemeral source port and tells you nothing. `peer_id` is
stable per daemon, so:

    1. from every node's OUTGOING connections, learn  peer_id -> listening port
    2. use that map to name the far end of every INCOMING connection

Any link that still cannot be named is reported as unresolved rather than assumed.
"""
import time

# NOTE: `live_median_boundary` is imported LAZILY inside connections(), the only function here
# that contacts a daemon. Importing it at module scope executed its module body, which opens
# ~/.meepcoin-devnet/wallets/walletA.address.txt -- so a bundled checker relocated to another
# machine (or run under a sterile HOME) died with FileNotFoundError before verifying anything,
# purely because sample_verify -> topology -> live_median_boundary. The pure adjacency and
# conformance helpers below touch no wallet, home directory, daemon, repository or network
# resource, and their verdict rules are unchanged.


def connections(port):
    from live_median_boundary import rpc          # lazy: only when a daemon is actually contacted

    r = rpc(port, "get_connections", {}, timeout=15)
    return (r.get("result") or {}).get("connections") or []


def snapshot(nodes):
    """nodes: {name: (rpc_port, p2p_port)} -> directed adjacency plus the raw rows."""
    raw, rpc_errors = {}, []
    for name, (rp, _) in nodes.items():
        try:
            raw[name] = connections(rp)
        except Exception as e:
            raw[name] = [{"error": f"{type(e).__name__}: {e}"}]
            # a node that cannot be asked has NOT proved anything about its links
            rpc_errors.append(name)

    p2p_of = {name: p for name, (_, p) in nodes.items()}
    # peer_id -> node name, learned from outgoing connections only (their port is the real one)
    pid_to_name = {}
    for name, rows in raw.items():
        for c in rows:
            if c.get("error") or c.get("incoming"):
                continue
            try:
                rport = int(c.get("port") or 0)
            except (TypeError, ValueError):
                continue
            for other, pp in p2p_of.items():
                if pp == rport and c.get("peer_id"):
                    pid_to_name[c["peer_id"]] = other

    adj, unresolved = {}, []
    for name, rows in raw.items():
        seen = {}
        for c in rows:
            if c.get("error"):
                continue
            far = None
            if not c.get("incoming"):
                try:
                    rport = int(c.get("port") or 0)
                except (TypeError, ValueError):
                    rport = 0
                far = next((o for o, pp in p2p_of.items() if pp == rport), None)
            if far is None:
                far = pid_to_name.get(c.get("peer_id"))
            rec = {"direction": "in" if c.get("incoming") else "out",
                   "peer_id": c.get("peer_id"), "remote_port": c.get("port"),
                   "state": c.get("state"), "live_time": c.get("live_time"),
                   "connection_id": c.get("connection_id"), "height": c.get("height")}
            if far is None:
                unresolved.append({"node": name, **rec})
            else:
                seen.setdefault(far, []).append(rec)
        adj[name] = seen
    links = set()
    for a, peers in adj.items():
        for b in peers:
            links.add(tuple(sorted((a, b))))
    return {"t": time.time(), "adjacency": adj, "undirected_links": sorted(links),
            "unresolved": unresolved, "peer_id_map": pid_to_name, "rpc_errors": rpc_errors,
            "raw_rows": raw,
            "raw_connection_counts": {n: len([c for c in rows if not c.get("error")])
                                      for n, rows in raw.items()}}


def all_pairs(names):
    out = set()
    for i, a in enumerate(names):
        for b in names[i + 1:]:
            out.add(tuple(sorted((a, b))))
    return out


def required_links(names, topology):
    if topology == "full_mesh":
        return all_pairs(names)
    if topology == "star":
        hub = names[0]
        return {tuple(sorted((hub, o))) for o in names[1:]}
    raise ValueError(topology)


def forbidden_links(names, topology):
    """Links a topology must NOT have.

    Without this, a STAR run could form all three edges and still be labelled STAR: checking only
    that the hub links exist says nothing about the spoke-to-spoke link. FULL_MESH forbids nothing;
    STAR forbids every non-hub pair."""
    if topology == "full_mesh":
        return set()
    if topology == "star":
        return all_pairs(names) - required_links(names, topology)
    raise ValueError(topology)


def conformance(snap, names, topology):
    """Strict verdict. A sample is conformant only when ALL of these hold:

      * every REQUIRED link is confirmed by BOTH endpoints independently in this same sample --
        one endpoint seeing a peer is not enough, because a half-open or one-sided view is exactly
        the failure mode a topology claim must exclude;
      * no FORBIDDEN link is reported by EITHER endpoint (one sighting is enough to condemn it);
      * no node's get_connections call errored;
      * no active connection was left unresolved (an unidentifiable peer could be either endpoint).

    The previous version formed an undirected edge from a single endpoint's view, ignored RPC
    errors and unresolved peers entirely, and let a caller's all([]) pass vacuously on zero
    samples. All three are corrected here and in the caller.
    """
    adj = snap.get("adjacency", {})
    errors = sorted(snap.get("rpc_errors", []))
    unresolved = snap.get("unresolved", [])

    mutual, one_sided = set(), set()
    for a in names:
        for b in names:
            if a >= b:
                continue
            a_sees_b = bool(adj.get(a, {}).get(b))
            b_sees_a = bool(adj.get(b, {}).get(a))
            if a_sees_b and b_sees_a:
                mutual.add((a, b))
            elif a_sees_b or b_sees_a:
                one_sided.add((a, b))

    need = required_links(names, topology)
    forb = forbidden_links(names, topology)
    seen_either = mutual | one_sided
    miss = sorted(need - mutual)                 # must be MUTUALLY confirmed
    extra = sorted(seen_either & forb)           # EITHER endpoint condemns it
    ok = (not miss and not extra and not errors and not unresolved)
    return {"topology": topology, "required": sorted(need), "forbidden": sorted(forb),
            "mutually_confirmed": sorted(mutual), "one_sided_only": sorted(one_sided),
            "missing": miss, "forbidden_present": extra,
            "rpc_errors": errors, "unresolved_count": len(unresolved),
            "unresolved": unresolved[:20],
            "conformant": ok,
            "non_conformance_reasons": (
                ([f"required link not mutually confirmed: {miss}"] if miss else []) +
                ([f"forbidden link present: {extra}"] if extra else []) +
                ([f"get_connections errors on: {errors}"] if errors else []) +
                ([f"{len(unresolved)} unresolved active peer(s)"] if unresolved else []))}


def missing(snap, names, topology):
    """Backwards-compatible pair (missing, required). Prefer conformance() -- this cannot report a
    forbidden edge."""
    c = conformance(snap, names, topology)
    return c["missing"], c["required"]


def wait_for(nodes, topology, timeout=120, poll=2.0):
    """Block until the topology is CONFORMANT: every required link up and no forbidden link
    present. A STAR whose spoke-to-spoke edge has formed is not a STAR and never becomes one by
    waiting, so a forbidden edge fails immediately rather than burning the timeout."""
    names = list(nodes)
    hist = []
    t0 = time.time()
    while time.time() - t0 < timeout:
        snap = snapshot(nodes)
        c = conformance(snap, names, topology)
        hist.append({"t": round(time.time() - t0, 2), "links": snap["undirected_links"],
                     "missing": c["missing"], "forbidden_present": c["forbidden_present"],
                     "counts": snap["raw_connection_counts"]})
        snap["conformance"] = c
        snap["required_links"] = c["required"]
        snap["missing_links"] = c["missing"]
        snap["forbidden_links"] = c["forbidden"]
        snap["forbidden_present"] = c["forbidden_present"]
        if c["forbidden_present"]:
            return False, snap, hist
        if c["conformant"]:
            return True, snap, hist
        time.sleep(poll)
    snap = snapshot(nodes)
    c = conformance(snap, names, topology)
    snap["conformance"] = c
    snap["required_links"] = c["required"]
    snap["missing_links"] = c["missing"]
    snap["forbidden_links"] = c["forbidden"]
    snap["forbidden_present"] = c["forbidden_present"]
    return c["conformant"], snap, hist
