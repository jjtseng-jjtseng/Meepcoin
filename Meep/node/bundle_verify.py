#!/usr/bin/env python3
"""Offline bundle/provenance verifier. Takes ONLY a bundle path.

`series_validate.py` judges the science; nothing judged the bundle itself. This does: it checks the
detached seal, the manifest, the checksum inventory, and that every file in the bundle is either
listed or explained. It must not depend on any mutable path outside the bundle.

Usage: python3 node/bundle_verify.py <bundle-dir> [--json=out.json] [--isolated]
                                          [--verify-live-inputs]

  --isolated             verify using ONLY the bundle's own contents; never touches an external
                         path. This is the mode that matters for a relocated bundle.
  --verify-live-inputs   additionally compare every declared external identity (daemon binary,
                         snapshot, node source tree, harness) against the live filesystem:
                         existence, byte count and SHA-256. Meaningful only on the originating
                         machine.
Exit 0 only if the bundle verifies.
"""
import hashlib, json, os, sys

# F: a bundled verifier must NEVER add a file to the sealed bundle it is checking. Running the
# copied series validator used to emit inputs/harness/__pycache__/*.pyc, after which the very
# next isolated bundle verification failed on unlisted files. Suppressing bytecode BEFORE the
# sibling imports below keeps post-seal verification side-effect-free and repeatable in any
# order. `python3 -B` / PYTHONDONTWRITEBYTECODE stay useful as defence in depth, but the code
# must not depend on the caller remembering them.
sys.dont_write_bytecode = True


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for c in iter(lambda: f.read(1 << 20), b""):
            h.update(c)
    return h.hexdigest()


# Files that legitimately exist without appearing in SHA256SUMS.
SELF = {"SHA256SUMS", "FINAL_SEAL.json", "bundle_verify_report.json"}


def verify_live_inputs(bundle):
    """Compare every DECLARED external identity against the live filesystem.

    provenance.py advertised `bundle_verify --verify-live-inputs` for years without the option
    existing. This implements it: on the originating machine each declared external path must
    exist, have the recorded byte count, and hash to the recorded SHA-256. It is meaningful ONLY
    on the machine that produced the bundle, and it is deliberately independent of --isolated,
    which must never touch an external path.
    """
    m = json.load(open(os.path.join(bundle, "manifest.json"), encoding="utf-8"))
    ei = m.get("external_identities") or {}
    out = {"bundle": os.path.abspath(bundle), "checked": 0, "ok": 0, "failures": [], "entries": []}
    for kind, entries in sorted(ei.items()):
        for path, meta in sorted(entries.items()):
            out["checked"] += 1
            row = {"kind": kind, "path": path, "recorded_sha256": meta.get("sha256"),
                   "recorded_bytes": meta.get("bytes")}
            if not os.path.exists(path):
                row["status"] = "MISSING"
                out["failures"].append(f"{kind}: {path} does not exist on this machine")
            else:
                actual_bytes = os.path.getsize(path)
                actual = sha256_file(path)
                row["actual_bytes"], row["actual_sha256"] = actual_bytes, actual
                want_b = meta.get("bytes")
                if want_b is not None and want_b != actual_bytes:
                    row["status"] = "SIZE_MISMATCH"
                    out["failures"].append(
                        f"{kind}: {path} is {actual_bytes} bytes, recorded {want_b}")
                elif meta.get("sha256") != actual:
                    row["status"] = "HASH_MISMATCH"
                    out["failures"].append(
                        f"{kind}: {path} hashes {actual[:16]}, recorded "
                        f"{str(meta.get('sha256'))[:16]}")
                else:
                    row["status"] = "OK"
                    out["ok"] += 1
            out["entries"].append(row)
    out["passed"] = not out["failures"]
    return out


def verify(bundle, isolated=False):
    res = {"bundle": os.path.abspath(bundle), "failures": [], "checks": []}
    fail = res["failures"].append

    def ck(name, ok, detail=""):
        res["checks"].append({"check": name, "ok": bool(ok), "detail": str(detail)[:300]})
        if not ok:
            fail(f"{name}: {detail}")
        return bool(ok)

    mpath = os.path.join(bundle, "manifest.json")
    spath = os.path.join(bundle, "SHA256SUMS")
    fpath = os.path.join(bundle, "FINAL_SEAL.json")
    if not ck("manifest present", os.path.exists(mpath), mpath):
        res["passed"] = False
        return res
    if not ck("SHA256SUMS present", os.path.exists(spath), spath):
        res["passed"] = False
        return res

    # ---- detached seal binds manifest + checksum file ----
    if ck("FINAL_SEAL.json present", os.path.exists(fpath), fpath):
        seal = json.load(open(fpath, encoding="utf-8"))
        res["seal"] = seal
        ck("seal manifest digest matches", seal.get("manifest_sha256") == sha256_file(mpath),
           f"seal={str(seal.get('manifest_sha256'))[:16]} actual={sha256_file(mpath)[:16]}")
        ck("seal SHA256SUMS digest matches", seal.get("sha256sums_sha256") == sha256_file(spath),
           f"seal={str(seal.get('sha256sums_sha256'))[:16]} actual={sha256_file(spath)[:16]}")

    m = json.load(open(mpath, encoding="utf-8"))
    res["manifest_status"] = m.get("status")
    res["series_valid"] = m.get("series_valid")
    ck("manifest has a status", bool(m.get("status")), m.get("status"))
    ck("driver argv recorded", isinstance(m.get("driver_argv"), list) and m["driver_argv"],
       m.get("driver_argv"))
    rc = m.get("resolved_config") or {}
    ck("resolved_config recorded", isinstance(rc, dict) and len(rc) >= 10, len(rc))
    repo = m.get("repo") or {}
    res["repo_commit"] = repo.get("commit")
    res["clean_tree_at_start"] = repo.get("clean_tree")
    for run in m.get("runs", []):
        na = run.get("node_argv") or {}
        ck(f"run {run.get('label')} records all node argv",
           set(na) >= {"h1", "h2", "atk"} or set(na) == set(rc.get("nodes", [])) or len(na) >= 3,
           sorted(na))

    # ---- every checksum entry must verify, and paths must be safe ----
    # P1: entries whose target lies outside the bundle are EXTERNAL IDENTITIES (daemon binary,
    # snapshot, node source tree, live harness). Detached bundle integrity must not depend on them,
    # so isolated mode records them and skips hashing live paths.
    listed, bad, missing, external = set(), [], [], []
    for line in open(spath, encoding="utf-8"):
        parts = [x for x in line.rstrip("\n").split("  ") if x]
        if len(parts) < 2:
            continue
        want, path = parts[0], parts[-1]
        ap = path if os.path.isabs(path) else os.path.join(bundle, path)
        ap = os.path.normpath(ap)
        try:
            inside = (os.path.commonpath([os.path.abspath(bundle), os.path.abspath(ap)]) ==
                      os.path.abspath(bundle))
        except ValueError:
            inside = False
        if inside:
            listed.add(os.path.abspath(ap))
        else:
            external.append(path)
            if isolated:
                # an external identity (daemon binary, snapshot, node source, live harness) is
                # NOT part of detached bundle integrity and must not be hashed from a live path
                continue
        if not os.path.exists(ap):
            missing.append(path)
            continue
        if sha256_file(ap) != want:
            bad.append(path)
    ck("no missing checksum targets", not missing, missing[:5])
    ck("no modified checksum targets", not bad, bad[:5])
    res["checksum_entries"] = len(listed) + len(missing)
    # Entries in SHA256SUMS whose target lies outside the bundle. Since external identities were
    # moved into the manifest this is structurally 0 for a current bundle; it stays here so an
    # OLD bundle written with absolute paths is still reported honestly rather than silently
    # verifying as if it were self-contained.
    res["out_of_bundle_checksum_entries"] = len(external)
    res["legacy_absolute_paths"] = bool(external)
    # The real external identities -- daemon binary, snapshot, node source tree, harness -- are
    # declared in the manifest and deliberately NOT checksum targets. Reporting the SHA256SUMS
    # count as "external identities" said 0 while the manifest declared 20.
    ei = m.get("external_identities") or {}
    res["external_identities"] = {k: len(v) for k, v in ei.items()}
    res["external_identity_entries"] = sum(len(v) for v in ei.values())
    ck("external identities are declared in the manifest", bool(ei), sorted(ei))
    ck("SHA256SUMS contains no absolute out-of-bundle paths", not external, external[:3])
    res["isolated_mode"] = bool(isolated)

    # ---- no unexplained file in the bundle ----
    present, unlisted = set(), []
    for r, _, fs in os.walk(bundle):
        for f in fs:
            q = os.path.abspath(os.path.join(r, f))
            present.add(q)
            if f in SELF or f.endswith(".md"):
                continue
            if q not in listed:
                unlisted.append(os.path.relpath(q, bundle))
    res["files_present"] = len(present)
    res["unlisted"] = unlisted
    ck("no unlisted non-doc files", not unlisted, unlisted[:8])

    # ---- measured series shape ----
    raw_dir = os.path.join(bundle, "raw")
    raws = sorted(f for f in os.listdir(raw_dir)) if os.path.isdir(raw_dir) else []
    res["raw_records"] = len(raws)
    if m.get("SMOKE_RUN"):
        res["smoke"] = True
    else:
        # P1-4: a MEASURED bundle is only PASS if it is scientifically usable, not merely sealed
        ck("exactly nine raw condition records", len(raws) == 9, len(raws))
        ck("manifest status COMPLETED", m.get("status") == "COMPLETED", m.get("status"))
        ck("series_valid is true", m.get("series_valid") is True, m.get("series_valid"))
        ck("series was not aborted", m.get("aborted") in (None, {}), m.get("aborted"))

    # ---- P1: the bundle must carry its inputs, not point at a live repository ----
    ck("durability statement present",
       isinstance(m.get("durability"), dict) and bool(m["durability"].get("statement")),
       (m.get("durability") or {}).get("offsite_backup"))
    ci = m.get("copied_inputs") or {}
    res["copied_inputs"] = len(ci)
    if not m.get("SMOKE_RUN"):
        ck("preregistrations copied into the bundle",
           any("PREREGISTRATION" in k.upper() for k in ci), sorted(ci)[:4])
    missing_copies = [k for k, v in ci.items()
                      if not (v.get("bundle_path") and
                              os.path.exists(os.path.join(bundle, v["bundle_path"])))]
    ck("every copied input is present in the bundle", not missing_copies, missing_copies[:5])

    vpath = os.path.join(bundle, "verifier_results.json")
    if ck("verifier results retained", os.path.exists(vpath), vpath):
        vr = json.load(open(vpath, encoding="utf-8"))
        pv = vr.get("producer_verifier") or {}
        sv = vr.get("sample_verifier") or {}
        res["producer_verifier_pass"] = sum(1 for v in pv.values() if v.get("passed"))
        res["producer_verifier_total"] = len(pv)
        res["sample_verifier_pass"] = sum(1 for v in sv.values() if v.get("passed"))
        res["sample_verifier_total"] = len(sv)
        ck("every producer verifier passed",
           len(pv) > 0 and all(v.get("passed") for v in pv.values()),
           f"{res['producer_verifier_pass']}/{res['producer_verifier_total']}")
        ck("every sample verifier passed",
           len(sv) > 0 and all(v.get("passed") for v in sv.values()),
           f"{res['sample_verifier_pass']}/{res['sample_verifier_total']}")

    res["passed"] = not res["failures"]
    return res


def main(argv):
    paths = [a for a in argv if not a.startswith("--")]
    outp = next((a.split("=", 1)[1] for a in argv if a.startswith("--json=")), None)
    isolated = "--isolated" in argv
    live = "--verify-live-inputs" in argv
    if not paths:
        print(__doc__)
        return 2
    bad = 0
    if live:
        for b in paths:
            lr = verify_live_inputs(b)
            print(f"[{'PASS' if lr['passed'] else 'FAIL'}] live inputs: {lr['ok']}/"
                  f"{lr['checked']} external identities match on this machine")
            for f in lr["failures"][:10]:
                print(f"    ! {f}")
            if not lr["passed"]:
                bad += 1
    for b in paths:
        r = verify(b, isolated=isolated)
        print(f"[{'PASS' if r['passed'] else 'FAIL'}] {b}")
        print(f"    isolated={r.get('isolated_mode')} external_identity="
              f"{r.get('external_identity_entries')}")
        print(f"    checks={len(r['checks'])} files={r.get('files_present')} "
              f"raw={r.get('raw_records')} manifest_status={r.get('manifest_status')} "
              f"series_valid={r.get('series_valid')}")
        for f in r["failures"][:10]:
            print(f"    ! {f}")
        if outp:
            with open(outp, "w", encoding="utf-8") as fh:
                json.dump(r, fh, indent=1, default=str)
        if not r["passed"]:
            bad += 1
    return 0 if bad == 0 else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
