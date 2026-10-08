#!/usr/bin/env python3
"""Round-2 provenance: hash every input and output, not just the manifest and stdout.

run_recorded.sh records commit, branch and command, and hashes whatever files land in the results
directory. That is not enough to reproduce a consensus experiment: it does not pin the daemon
binary, the patched consensus sources the binary was built from, the harness scripts, the snapshot
identity, or the environment variables that decide the genesis block.

Usage from an experiment script:

    prov = Provenance(outdir, harness=[__file__, "node/topology.py", ...], binary=BIN)
    prov.add_snapshot(snapshot_dir, snapshot_json)
    prov.add_run(argv, env_keys)
    ...
    prov.finish(extra_outputs=[report_path])     # writes manifest.json + SHA256SUMS
"""
import hashlib, json, os, shutil, subprocess, sys, time

# Consensus sources whose content decides what the binary enforces. Hashed by content so a rebuilt
# binary with different sources cannot masquerade as the same experiment.
CONSENSUS_SOURCES = [
    "src/cryptonote_core/blockchain.cpp",
    "src/cryptonote_config.h",
    "src/cryptonote_basic/cryptonote_basic_impl.cpp",
    "src/cryptonote_basic/difficulty.cpp",
    "src/cryptonote_basic/miner.cpp",
    "src/cryptonote_core/blockchain.h",
]
# Environment variables that can change consensus or the genesis block.
CONSENSUS_ENV = ["MEEPCOIN_EXPERIMENTAL_GENESIS_TS", "MEEP_DAEMON"]

NODE_TREE = os.path.expanduser("~/meepcoin-node")
REPO = "/mnt/c/Users/tseng/meepcoin"


def sha256_file(path):
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception as e:
        return f"ERROR: {type(e).__name__}: {e}"


def _git(args, cwd):
    try:
        return subprocess.run(["git"] + args, cwd=cwd, capture_output=True,
                              text=True).stdout.strip()
    except Exception:
        return "unknown"


class Provenance:
    def __init__(self, outdir, harness, binary, repo=REPO, node_tree=NODE_TREE,
                 driver_argv=None):
        self.outdir, self.repo, self.node_tree = outdir, repo, node_tree
        os.makedirs(outdir, exist_ok=True)
        dirty = _git(["status", "--porcelain"], repo)
        self.m = {
            "schema": "meepcoin-provenance/2",
            "start_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "repo": {
                "commit": _git(["rev-parse", "HEAD"], repo),
                "branch": _git(["rev-parse", "--abbrev-ref", "HEAD"], repo),
                "clean_tree": dirty == "",
                "uncommitted": [l for l in dirty.splitlines()],
            },
            "frozen_tags": {t: _git(["rev-parse", f"{t}^{{commit}}"], repo) for t in
                            ("v16-economics-freeze", "v2-frozen", "public-testnet-readiness")},
            "driver_argv": list(driver_argv if driver_argv is not None else sys.argv),
            "driver_cwd": os.getcwd(),
            "harness": {},
            "daemon_binary": {},
            "consensus_sources": {},
            "node_tree": {
                "base_commit": _git(["rev-parse", "HEAD"], node_tree),
                "modified": [l for l in _git(["status", "--porcelain"], node_tree).splitlines()],
            },
            "snapshot": None,
            "runs": [],
            "outputs": {},
            "host": {"uname": os.uname().version if hasattr(os, "uname") else sys.platform,
                     "cpus": os.cpu_count()},
        }
        for h in harness:
            p = h if os.path.isabs(h) else os.path.join(repo, h)
            self.m["harness"][os.path.relpath(p, repo) if p.startswith(repo) else p] = {
                "sha256": sha256_file(p), "bytes": os.path.getsize(p) if os.path.exists(p) else None}
        self.m["daemon_binary"] = {"path": binary, "sha256": sha256_file(binary),
                                   "bytes": os.path.getsize(binary) if os.path.exists(binary)
                                   else None,
                                   "mtime": time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                                          time.gmtime(os.path.getmtime(binary)))
                                   if os.path.exists(binary) else None}
        for rel in CONSENSUS_SOURCES:
            p = os.path.join(node_tree, rel)
            if os.path.exists(p):
                self.m["consensus_sources"][rel] = {
                    "sha256": sha256_file(p), "bytes": os.path.getsize(p),
                    "mtime": time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                           time.gmtime(os.path.getmtime(p)))}
        self._write()

    def add_snapshot(self, snap_dir, snap_json_path=None, chain=None):
        entry = {"source_dir": snap_dir, "exists": os.path.isdir(snap_dir)}
        db = os.path.join(snap_dir, "testnet", "lmdb", "data.mdb")
        if os.path.exists(db):
            st = os.stat(db)
            entry["data_mdb"] = {"path": db, "apparent_bytes": st.st_size,
                                 "actual_bytes": st.st_blocks * 512,
                                 "sha256": sha256_file(db),
                                 "mtime": time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                                        time.gmtime(st.st_mtime))}
        if snap_json_path and os.path.exists(snap_json_path):
            entry["metadata_file"] = {"path": snap_json_path,
                                      "sha256": sha256_file(snap_json_path)}
        if chain:
            entry["chain"] = chain
        self.m["snapshot"] = entry
        self._write()

    def add_run(self, label, node_argv, env=None, extra=None):
        """`node_argv` is a mapping {node_name: argv} -- EVERY node, not just the first.

        The previous version stored a single daemon's argv for a whole run, so the exact command
        line of two of the three nodes was simply absent from the record."""
        if isinstance(node_argv, (list, tuple)):        # tolerate the old single-argv form
            node_argv = {"unnamed": list(node_argv)}
        rec = {"label": label, "utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
               "node_argv": {k: list(v) for k, v in node_argv.items()},
               "consensus_env": {k: os.environ.get(k) for k in (env or CONSENSUS_ENV)},
               **(extra or {})}
        self.m["runs"].append(rec)
        self._write()
        return rec

    def update_run(self, label, **fields):
        """Attach end-of-run facts (stop paths, retry counters, timings) to an existing entry."""
        for r in reversed(self.m["runs"]):
            if r.get("label") == label:
                r.update(fields)
                self._write()
                return r
        return None

    def add_output(self, path, kind="raw"):
        if os.path.exists(path):
            self.m["outputs"][path] = {"kind": kind, "sha256": sha256_file(path),
                                       "bytes": os.path.getsize(path)}
        else:
            self.m["outputs"][path] = {"kind": kind, "sha256": "MISSING"}
        self._write()

    def copy_logs(self, node_dirs, subdir="daemon_logs", require_all=True):
        """Copy COMPLETE daemon logs into the evidence directory, hash them, and FAIL CLOSED.

        Must be called only AFTER every daemon process has exited: a log copied while the daemon is
        still writing is truncated, and nothing downstream can detect that. The previous version was
        called before shutdown, silently skipped missing sources, and its caller swallowed every
        exception, so a missing or partial log left no trace.

        Returns a report; `all_present` False means the attempt is invalid."""
        dst = os.path.join(self.outdir, subdir)
        os.makedirs(dst, exist_ok=True)
        report = {"subdir": subdir, "expected": sorted(node_dirs), "copied": {}, "missing": [],
                  "errors": {}}
        for name, d in sorted(node_dirs.items()):
            src = os.path.join(d, "meepcoind.log")
            if not os.path.exists(src):
                report["missing"].append(name)
                continue
            out = os.path.join(dst, f"{name}.log")
            try:
                with open(src, "rb") as a, open(out, "wb") as b:
                    while True:
                        c = a.read(1 << 20)
                        if not c:
                            break
                        b.write(c)
                h = sha256_file(out)
                if isinstance(h, str) and h.startswith("ERROR"):
                    raise RuntimeError(h)
                report["copied"][name] = {"path": out, "bytes": os.path.getsize(out),
                                          "sha256": h, "source": src,
                                          "source_bytes": os.path.getsize(src)}
                self.add_output(out, kind="daemon_log")
            except Exception as e:
                report["errors"][name] = f"{type(e).__name__}: {e}"
        report["all_present"] = (not report["missing"] and not report["errors"] and
                                 len(report["copied"]) == len(node_dirs))
        self.m.setdefault("log_capture", []).append(report)
        self._write()
        if require_all and not report["all_present"]:
            raise RuntimeError("log capture incomplete: missing=%s errors=%s"
                               % (report["missing"], report["errors"]))
        return report

    def copy_inputs(self, paths, dest_subdir="inputs", kind="input"):
        """P1: COPY an input into the bundle instead of pointing a checksum at a live repo path.

        Recording `docs/round2/PREREGISTRATION.md` by absolute path only proves what that file
        contained at hashing time on this machine; a later edit leaves the bundle claiming a
        checksum for a file it does not carry, and a copied bundle cannot check it at all. Copying
        makes the bundle self-describing: the checksum target travels with the evidence."""
        dst = os.path.join(self.outdir, dest_subdir)
        os.makedirs(dst, exist_ok=True)
        copied = self.m.setdefault("copied_inputs", {})
        for p in paths:
            src = p if os.path.isabs(p) else os.path.join(self.repo, p)
            name = os.path.basename(src)
            out = os.path.join(dst, name)
            n = 1
            while os.path.exists(out) and os.path.abspath(out) not in (
                    os.path.abspath(v.get("bundle_path", "")) for v in copied.values()):
                n += 1
                out = os.path.join(dst, f"{n}_{name}")
            if not os.path.exists(src):
                copied[p] = {"bundle_path": None, "source_path": src, "sha256": "MISSING"}
                continue
            shutil.copy2(src, out)
            copied[p] = {"bundle_path": os.path.relpath(out, self.outdir),
                         "source_path": src, "sha256": sha256_file(out),
                         "bytes": os.path.getsize(out),
                         "matches_source": sha256_file(out) == sha256_file(src)}
            self.add_output(out, kind=kind)
        self._write()
        return copied

    def add_node_source_bundle(self, dest_subdir="node_source_state"):
        """Capture the daemon's SOURCE/BUILD state, not just the binary hash.

        The binary hash pins one executable but says nothing about what produced it. The node tree
        is a dirty working copy on top of its base commit, and hashing six hand-picked files does
        not describe it. This records the base commit, the complete diff, and the identity of every
        modified or untracked input that can affect the daemon."""
        dst = os.path.join(self.outdir, dest_subdir)
        os.makedirs(dst, exist_ok=True)
        info = {"node_tree": self.node_tree,
                "base_commit": _git(["rev-parse", "HEAD"], self.node_tree),
                "describe": _git(["describe", "--always", "--dirty"], self.node_tree)}
        entries = [l for l in _git(["status", "--porcelain"], self.node_tree).splitlines()
                   if l.strip()]
        info["status_entries"] = entries
        info["modified_count"] = sum(1 for l in entries if not l.startswith("??"))
        info["untracked_count"] = sum(1 for l in entries if l.startswith("??"))
        try:
            diff = subprocess.run(["git", "diff", "HEAD", "--binary"], cwd=self.node_tree,
                                  capture_output=True, text=True).stdout
        except Exception as e:
            diff = "ERROR capturing diff: %s" % e
        dp = os.path.join(dst, "node_tree.diff")
        with open(dp, "w", encoding="utf-8", newline="\n") as f:
            f.write(diff)
        info["diff"] = {"path": dp, "bytes": os.path.getsize(dp), "sha256": sha256_file(dp)}
        self.add_output(dp, kind="node_source_diff")
        untracked = []
        for l in entries:
            if not l.startswith("??"):
                continue
            rel = l[3:].strip().strip('"')
            src = os.path.join(self.node_tree, rel)
            if os.path.isfile(src):
                untracked.append({"path": rel, "bytes": os.path.getsize(src),
                                  "sha256": sha256_file(src)})
            elif os.path.isdir(src):
                for r, _, fs in os.walk(src):
                    for f in fs:
                        q = os.path.join(r, f)
                        untracked.append({"path": os.path.relpath(q, self.node_tree),
                                          "bytes": os.path.getsize(q), "sha256": sha256_file(q)})
        info["untracked_inputs"] = untracked
        info["untracked_hashed"] = len(untracked)
        def _v(cmd):
            try:
                return subprocess.run(cmd, capture_output=True, text=True).stdout.splitlines()[:1]
            except Exception:
                return []
        info["toolchain"] = {"gcc": _v(["gcc", "--version"]), "cmake": _v(["cmake", "--version"])}
        info["caveat"] = ("The daemon binary hash pins the executable. Source reproducibility is "
                          "claimed only to the extent of base_commit + this diff + these untracked "
                          "input hashes; the original build flags were not captured at build time.")
        self.m["node_source_state"] = info
        self._write()
        return info

    def finish(self, extra_outputs=(), status="COMPLETED"):
        for p in extra_outputs:
            self.add_output(p, kind="report")
        self.m["end_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        self.m["status"] = status
        self._write()
        # P1: SHA256SUMS covers ONLY files inside the bundle, written as BUNDLE-RELATIVE paths,
        # so a copied bundle verifies from its own contents. Everything outside the bundle (daemon
        # binary, snapshot, node source tree, live harness scripts) is an EXTERNAL IDENTITY: it is
        # recorded in the manifest for identification, never as a portable checksum target.
        lines, external = [], {}
        root = os.path.abspath(self.outdir)

        def rel_or_external(path, kind, meta):
            ap = os.path.abspath(path)
            try:
                inside = os.path.commonpath([root, ap]) == root
            except ValueError:
                inside = False
            if inside:
                lines.append(f"{meta['sha256']}  {kind}  {os.path.relpath(ap, root)}")
            else:
                external.setdefault(kind, {})[path] = meta

        for path, meta in self.m["outputs"].items():
            rel_or_external(path, "output", meta)
        for path, meta in self.m["harness"].items():
            p2 = path if os.path.isabs(path) else os.path.join(self.repo, path)
            rel_or_external(p2, "harness", meta)
        b = self.m["daemon_binary"]
        rel_or_external(b["path"], "daemon_binary", b)
        for rel, meta in self.m["consensus_sources"].items():
            rel_or_external(os.path.join(self.node_tree, rel), "consensus_source", meta)
        snap = self.m.get("snapshot") or {}
        if snap.get("data_mdb"):
            rel_or_external(snap["data_mdb"]["path"], "snapshot", snap["data_mdb"])
        if snap.get("metadata_file"):
            rel_or_external(snap["metadata_file"]["path"], "snapshot", snap["metadata_file"])
        # P1: state the durability of the evidence explicitly, instead of leaving a reader to
        # assume that hash-sealed means backed up. It does not.
        self.m["durability"] = {
            "evidence_dir": os.path.abspath(self.outdir),
            "daemon_logs": "COPIED INTO THIS BUNDLE and hash-sealed in SHA256SUMS",
            "offsite_backup": False,
            "statement": (
                "Every artefact needed to re-verify this bundle offline is inside the bundle "
                "directory and covered by SHA256SUMS with bundle-relative paths. The bundle lives "
                "on ONE machine's local filesystem and is NOT replicated off that machine. The "
                "daemon per-attempt data directories are throwaway and are NOT retained; only the "
                "copied logs, raw records, blob archive and summaries survive. If this directory "
                "is deleted the evidence is gone -- the seal proves integrity, not survival."),
            "not_retained": ["per-attempt daemon data directories (LMDB)",
                             "daemon stdout beyond the copied log files"],
        }
        self.m["external_identities"] = external
        self.m["external_identity_note"] = (
            "These paths are OUTSIDE the bundle and are recorded for identification only. They are "
            "deliberately absent from SHA256SUMS so detached bundle integrity does not depend on a "
            "mutable live filesystem. Verify them with bundle_verify --verify-live-inputs on the "
            "originating machine with: python3 inputs/harness/bundle_verify.py <dir> "
            "--verify-live-inputs")
        self._write()
        # The manifest is final at this point and must itself be covered by SHA256SUMS -- the
        # previous version hashed everything except the manifest, so a manifest edit was invisible.
        mpath = os.path.join(self.outdir, "manifest.json")
        lines.append(f"{sha256_file(mpath)}  output  manifest.json")
        spath = os.path.join(self.outdir, "SHA256SUMS")
        with open(spath, "w", encoding="utf-8", newline="\n") as f:
            f.write("\n".join(lines) + "\n")
        # Detached seal binding the two immutable artefacts. Written last and never mutated.
        seal = {"schema": "meepcoin-final-seal/1",
                "sealed_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "evidence_dir": os.path.abspath(self.outdir),
                "manifest_sha256": sha256_file(mpath),
                "sha256sums_sha256": sha256_file(spath),
                "note": (
                    "Verify with the checker CARRIED IN THIS BUNDLE, not one from a live "
                    "repository: python3 inputs/harness/bundle_verify.py <this-dir> --isolated. "
                    "That copy is hash-sealed in SHA256SUMS, so the program and the evidence are "
                    "checked together. On the originating machine, add --verify-live-inputs to "
                    "compare the declared external identities (daemon binary, snapshot, node "
                    "source tree, harness) against the live filesystem. Daemon logs are LOCALLY "
                    "RETAINED and hash-sealed here; they are not backed up off this machine."),
                "bundled_checker": "inputs/harness/bundle_verify.py",
                "bundled_sample_verifier": "inputs/harness/sample_verify.py"}
        with open(os.path.join(self.outdir, "FINAL_SEAL.json"), "w", encoding="utf-8") as f:
            json.dump(seal, f, indent=1)
        self.seal = seal
        return self.m

    def _write(self):
        with open(os.path.join(self.outdir, "manifest.json"), "w", encoding="utf-8") as f:
            json.dump(self.m, f, indent=1)
