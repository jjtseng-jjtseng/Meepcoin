#!/usr/bin/env python3
"""Round-13 (third corrective revision): the outer envelope, sterile relocation, the detached
attestation, historical integrity, provenance and cache isolation.

NON-EVIDENCE, AND ENTIRELY NON-LIVE. Every bundle, archive, seal, link and process inventory is a
synthetic fixture built in a temporary directory. The historical-integrity checker is exercised
only against MINIATURE SYNTHETIC bundles; the real Gate N is never touched.

EVERY ADVERSARIAL TEST FOLLOWS THE SAME SHAPE: prove the unmutated baseline passes, then prove the
exact mutation fails for the intended reason. A bare exception is never the assertion.

Tests this suite deliberately no longer contains, because they blessed unsafe behaviour:
  * a manual note_undeclared_read() masquerading as read detection;
  * a __pycache__ filter that excluded the very paths it claimed to check;
  * counting the in-process live-repository verifier as a G17 pass;
  * a relocation that supplied its own expected outer seal.

The counterexample matrix for the third corrective audit lives in node/tests_round14.py.

Usage: python3 node/tests_round13.py [--out=<path>] [--commit=<sha>]
"""
import ast
import json
import os
import subprocess
import sys
import tarfile
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import run_provenance as RP

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_NODE = os.path.join(_REPO, "node")
RECORDER = RP.ProvenanceRecorder(_REPO, strict=False).begin()
_MODULES_AT_BEGIN = frozenset(sys.modules)

import evidence_envelope as ENV                                        # noqa: E402
import historical_integrity as HI                                      # noqa: E402
import qual_verify_v2 as QV                                            # noqa: E402
from tests_round2 import check, RESULTS                                # noqa: E402

# qual_verify_v2.bootstrap_identity() hashes every file in the externally pinned bootstrap
# closure -- which now includes run_provenance.py (R5-11). Those are genuine project-local
# reads, so this suite DECLARES them rather than letting the boundary hide them.
for _boot in QV.BOOTSTRAP_FILES:
    RECORDER.register_read(os.path.join(_NODE, _boot), kind="bootstrap_closure")

ARG = {a.split("=", 1)[0]: a.split("=", 1)[1] for a in sys.argv[1:] if "=" in a}
OUT = ARG.get("--out", "")

EXPECTED_TESTS = (
    "test_0_start_order", "test_1_state_machine", "test_2_binding_safety",
    "test_3_seal_and_verify", "test_4_mutation_is_rejected", "test_5_publish_and_archive",
    "test_6_attestation_is_detached", "test_7_relocation_is_sterile",
    "test_8_historical_integrity", "test_9_provenance_fails_closed", "test_10_cache_isolation",
)
FUNCTIONAL_CHECK_COUNT = 104
META_CHECK_COUNT = 1


def w(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)
    return path


def refuses(fn, needle, cls=ENV.EnvelopeError):
    try:
        fn()
        return False, "nothing was raised"
    except cls as e:
        return (needle in str(e)), "%s: %s" % (type(e).__name__, e)


def has(failures, needle):
    return any(needle in f for f in failures)



# ---- the externally pinned interpreter, and the authorized G17 context (R5-12, R5-14) --------
INTERP_PATH = os.path.realpath(sys.executable)
INTERP_SHA = ENV.sha256_file(INTERP_PATH)


def _authorized_kw(env, kw):
    """Supply the interpreter pin, and the authorized context when the envelope supports it.

    An operator would take these from the review record; a test takes them from the artefact it
    just built. The NEGATIVE cases -- wrong pin, missing pin, no authorized context -- are what
    the round-16 matrix drives."""
    kw.setdefault("expect_interpreter_path", INTERP_PATH)
    kw.setdefault("expect_interpreter_sha256", INTERP_SHA)
    try:
        seal = json.loads(open(os.path.join(env, ENV.SEAL_FILE), encoding="utf-8").read())
    except Exception:
        return kw
    roles = seal.get("roles") or {}
    spec = (roles.get("qualification_spec") or {}).get("sha256")
    if spec and set(ENV.AUTHORIZED_REQUIRED_ROLES) <= set(roles):
        kw.setdefault("expect_spec_sha256", spec)
        kw.setdefault("spec_required_roles", list(ENV.AUTHORIZED_REQUIRED_ROLES))
        kw.setdefault("authorized_run", True)
        kw.setdefault("expect_inventory_sha256", ENV.inventory_digest(
            {r: v for r, v in ENV.typed_inventory(env).items() if r not in ENV.SELF_FILES}))
    return kw

def bind_all_authorized_roles(b, files, skip=()):
    """Bind every role an AUTHORIZED envelope must carry, with the archive/sidecar pair named
    exactly as the envelope's own grammar requires."""
    if "daemon_log_archive" not in skip and "daemon_log_sidecar" not in skip:
        arch = w(os.path.join(files, "daemon_log_archive.tar.gz"), "archive bytes\n")
        side = w(os.path.join(files, "daemon_log_archive.tar.gz.sha256"),
                 "%s  daemon_log_archive.tar.gz\n" % ENV.sha256_file(arch))
        b.bind("daemon_log_archive", arch, relpath="tools/daemon_log_archive.tar.gz")
        b.bind("daemon_log_sidecar", side, relpath="tools/daemon_log_archive.tar.gz.sha256")
    for role in ENV.ROLES:
        if role in skip or role in ("inner_collection", "environment_trace",
                                    "pre_seal_gate_results", "qualification_spec",
                                    "source_inventory", "outer_verifier",
                                    "daemon_log_archive", "daemon_log_sidecar"):
            continue
        p = w(os.path.join(files, role + ".txt"), "role " + role + "\n")
        b.bind(role, p, relpath="tools/" + role + ".txt")
    return b


def reloc(*a, **kw):
    """The PRODUCTION G17. There is no runner or prelude seam any more (R4-5, R4-6): the child is
    created by the operation itself, and its parent-side record is adopted by this suite's
    recorder afterwards so the subprocess is neither undeclared nor falsely called observed."""
    # These legacy Round-13 fixtures bind only {"spec_id":"X"}; Round 6 proved that they are
    # integrity diagnostics, not authorization. The real AUTHORIZED production path is exercised
    # by Round 17. Keeping this wrapper diagnostic prevents old fake authority becoming G17.
    res = QV.diagnostic_relocate(*a, **_authorized_kw(a[0], kw))
    if res.get("child_record"):
        RECORDER.adopt_child_record(res["child_record"])
    return res



def suite_child(code, tag):
    """A child program carrying THIS project's shim, with a unique tail so every child in this
    suite has its own canonical command identity."""
    return RP.CHILD_SHIM_SOURCE + code + ("\n# suite tag: %s\n" % tag)


def suite_run(argv, cwd, sidecar, inner=None, extra_env=None):
    """Start a child that this suite's recorder DECLARES and OBSERVES, and that an inner
    recorder may observe too.

    A child can echo exactly one nonce, so the inner recorder is declared with the outer one's.
    Both then validate the same answer and neither reports an undeclared subprocess."""
    cwd = os.path.abspath(cwd)
    outer = RECORDER.declare_subprocess(argv, cwd=cwd)
    entry = None
    if inner is not None:
        entry = inner.declare_subprocess(argv, cwd=cwd, nonce=outer["nonce"])
    env = dict(os.environ, MEEPCOIN_CHILD_PROVENANCE=sidecar, MEEPCOIN_CHILD_ROOT=cwd,
               MEEPCOIN_CHILD_NONCE=outer["nonce"],
               MEEPCOIN_CHILD_COMMAND=outer["command_identity"])
    env.update(extra_env or {})
    r = subprocess.run(argv, cwd=cwd, env=env, capture_output=True)
    RECORDER.attach_child_provenance(argv, sidecar)
    return r, outer, entry


def inner_bundle(root, name="inner"):
    b = os.path.join(root, name)
    w(os.path.join(b, "raw", "rec_1.json"), '{"condition":"control","replicate":1}\n')
    w(os.path.join(b, "manifest.json"), '{"status":"COMPLETED"}\n')
    sums = os.path.join(b, "SHA256SUMS")
    w(sums, "".join(
        "%s  output  %s\n" % (ENV.sha256_file(os.path.join(b, r.replace("/", os.sep))), r)
        for r in ENV.walk_relpaths(b) if r not in ("SHA256SUMS", "FINAL_SEAL.json")))
    w(os.path.join(b, "FINAL_SEAL.json"), json.dumps(ENV.inner_seal_document(b)) + "\n")
    return b


def build_envelope(root, trace_status=ENV.TRACE_COMPLETE, extra_binds=(), with_verifier=True,
                   tag="t", full_roles=True):
    inner = inner_bundle(root, "inner_" + tag)
    files = os.path.join(root, "src_" + tag)
    trace = w(os.path.join(files, "trace.json"), '{"kind":"environment_trace","rows":[]}\n')
    gates = w(os.path.join(files, "gates.json"), '{"pre_seal":true,"gates":[]}\n')
    spec = w(os.path.join(files, "spec.json"), '{"spec_id":"X"}\n')
    srcinv = w(os.path.join(files, "sources.json"), '{"modules":{}}\n')
    b = ENV.EnvelopeBuilder(os.path.join(root, "stage_" + tag), "ENVQ_" + tag)
    b.bind_collection(inner)
    b.bind_trace(trace, trace_status)
    b.bind("qualification_spec", spec, relpath="tools/spec.json")
    b.bind("source_inventory", srcinv, relpath="tools/sources.json")
    if with_verifier:
        b.bind("outer_verifier", os.path.join(_NODE, "evidence_envelope.py"),
               relpath="tools/evidence_envelope.py")
    if full_roles:
        bind_all_authorized_roles(b, files, skip=[r for r, _s, _r in extra_binds])
    for role, src, rel in extra_binds:
        b.bind(role, src, relpath=rel)
    b.mark_checked(gates)
    return b, b.seal(), inner


def sealed_envelope(root, tag="t", **kw):
    b, seal, inner = build_envelope(root, tag=tag, **kw)
    final = os.path.join(root, "ENVQ_" + tag)
    b.publish(final)
    return final, seal, inner


def pins(env, seal):
    """(outer seal, bundled verifier, typed inventory, bootstrap closure) -- all EXTERNAL."""
    return (ENV.sha256_file(os.path.join(env, ENV.SEAL_FILE)),
            (seal.get("roles", {}).get("outer_verifier") or {}).get("sha256"),
            ENV.inventory_digest({r: v for r, v in ENV.typed_inventory(env).items()
                                  if r not in ENV.SELF_FILES}),
            QV.bootstrap_closure_digest())


def _hi_seal(b):
    """A historical seal that satisfies the repaired contract: files, directories and the typed
    inventory digest, all bound."""
    on_disk = [r for r in HI.walk_relpaths(b) if r not in HI.SELF_FILES]
    graph = HI.walk_typed(b)
    dirs = sorted(r for r, k in graph.items() if k == "directory")
    inv = {r: v for r, v in HI.typed_inventory(b).items() if r not in HI.SELF_FILES}
    return {"schema": HI.BUNDLE_SEAL_SCHEMAS[0], "sealed": True, "inventory": sorted(on_disk),
            "file_count": len(on_disk) + len(HI.SELF_FILES),
            "directories": dirs, "directory_count": len(dirs),
            "typed_inventory_sha256": ENV.inventory_digest(inv),
            "sha256sums_sha256": HI.sha256_file(os.path.join(b, "SHA256SUMS"))}


def mini_bundle(root, name="MINI_20260101_test"):
    b = os.path.join(root, name)
    w(os.path.join(b, "raw", "r1.json"), '{"a":1}\n')
    w(os.path.join(b, "manifest.json"), '{"status":"COMPLETED"}\n')
    on_disk = [r for r in HI.walk_relpaths(b) if r not in HI.SELF_FILES]
    w(os.path.join(b, "SHA256SUMS"),
      "".join("%s  output  %s\n" % (HI.sha256_file(os.path.join(b, r.replace("/", os.sep))), r)
              for r in on_disk))
    w(os.path.join(b, "FINAL_SEAL.json"), json.dumps(_hi_seal(b)) + "\n")
    logs = w(os.path.join(root, "logs_src", "d1.log"), "line\n")
    arch = os.path.join(root, name + HI.ARCHIVE_SUFFIX)
    with tarfile.open(arch, "w:gz") as tf:
        tf.add(logs, arcname="logs_x/d1.log")
    w(arch + HI.SIDECAR_SUFFIX, HI.sha256_file(arch) + "  " + name + HI.ARCHIVE_SUFFIX + "\n")
    return b, arch


def reseal_mini(b):
    sums = os.path.join(b, "SHA256SUMS")
    on_disk = [r for r in HI.walk_relpaths(b) if r not in HI.SELF_FILES]
    w(sums, "".join("%s  output  %s\n"
                    % (HI.sha256_file(os.path.join(b, r.replace("/", os.sep))), r)
                    for r in on_disk))
    w(os.path.join(b, "FINAL_SEAL.json"), json.dumps(_hi_seal(b)) + "\n")


def hi_pins(b, arch):
    return {"seal_sha256": HI.sha256_file(os.path.join(b, "FINAL_SEAL.json")),
            "sums_sha256": HI.sha256_file(os.path.join(b, "SHA256SUMS")),
            "archive_sha256": HI.sha256_file(arch),
            "file_count": len(HI.walk_relpaths(b))}


# ------------------------------------------------------------------ 0
def test_0_start_order():
    before = sorted(m for m in ("evidence_envelope", "historical_integrity", "qual_verify_v2",
                                "tests_round2") if m in _MODULES_AT_BEGIN)
    check("T13-0. the provenance START observation preceded every target test module import",
          before == [] and RECORDER.start["when"] == "start", before)
    check("T13-0b. and those modules are imported by the time the tests run",
          all(m in sys.modules for m in ("evidence_envelope", "qual_verify_v2")))


# ------------------------------------------------------------------ 1
def test_1_state_machine():
    with tempfile.TemporaryDirectory() as td:
        inner = inner_bundle(td)
        stage = os.path.join(td, "s1")
        b = ENV.EnvelopeBuilder(stage, "E1")
        st = json.loads(open(os.path.join(stage, ENV.STATE_FILE), encoding="utf-8").read())
        check("T13-1. a fresh staging root declares STAGING and NEVER claims finality",
              st["state"] == ENV.STAGING and st["final"] is False
              and st["finality_marker"] == ENV.SEAL_FILE, st["state"])
        check("T13-1b. the declared order ends at SEALING; there is no ENVELOPE_SEALED state",
              ENV.ORDER[-1] == ENV.SEALING and "ENVELOPE_SEALED" not in ENV.ORDER, ENV.ORDER)

        for bad, why, needle in (
                (lambda: b.seal(), "sealing from STAGING", "seal runs from"),
                (lambda: b.publish(os.path.join(td, "final")), "publishing unsealed",
                 "only a sealed envelope")):
            hit, msg = refuses(bad, needle)
            check("T13-1c. %s is refused for the intended reason" % why, hit, msg[:80])

        b.bind_collection(inner)
        check("T13-1d. binding the collection advances to COLLECTION_BOUND and records the "
              "ACTUAL inner-seal digest",
              b.state == ENV.COLLECTION_BOUND
              and b.inner_seal_digest == ENV.sha256_file(
                  os.path.join(stage, "collection", "FINAL_SEAL.json")))
        hit, msg = refuses(lambda: b.bind_collection(inner), "collection must be bound first")
        check("T13-1e. and binding it twice is refused", hit, msg[:70])

        trace = w(os.path.join(td, "src", "trace.json"), '{"rows":[]}\n')
        hit, msg = refuses(lambda: b.bind_trace(trace, "MAYBE"), "trace_status")
        check("T13-1f. an unknown trace status is refused", hit, msg[:70])
        b.bind_trace(trace, ENV.TRACE_INCOMPLETE)
        check("T13-1g. a BROKEN trace is bound as INCOMPLETE rather than dropped",
              b.trace_status == ENV.TRACE_INCOMPLETE and b.state == ENV.TRACE_BOUND)

        b.bind("qualification_spec", w(os.path.join(td, "src", "spec.json"), "{}\n"),
               relpath="tools/spec.json")
        b.bind("source_inventory", w(os.path.join(td, "src", "s.json"), "{}\n"),
               relpath="tools/s.json")
        b.mark_checked(w(os.path.join(td, "src", "g.json"), "{}\n"))
        seal = b.seal()
        st2 = json.loads(open(os.path.join(stage, ENV.STATE_FILE), encoding="utf-8").read())
        check("T13-1h. after sealing the state file reads SEALING and still says final: false",
              st2["state"] == ENV.SEALING and st2["final"] is False, st2["state"])
        check("T13-1i. the seal is the only finality marker, and it says it cannot authenticate "
              "itself", seal["final"] is True
              and "CANNOT AUTHENTICATE" in seal["self_file_rule"].upper())
        check("T13-1j. and a crash before the seal would leave a visibly incomplete directory: "
              "the state file names the seal as the only finality marker and says it is "
              "incomplete without it",
              st2["finality_marker"] == ENV.SEAL_FILE
              and st2["incomplete_unless_seal_present"] is True and st2["final"] is False,
              {k: st2[k] for k in ("state", "final", "finality_marker")})


# ------------------------------------------------------------------ 2
def test_2_binding_safety():
    with tempfile.TemporaryDirectory() as td:
        inner = inner_bundle(td)
        b = ENV.EnvelopeBuilder(os.path.join(td, "s2"), "E2")
        b.bind_collection(inner)
        b.bind_trace(w(os.path.join(td, "src", "t.json"), "{}\n"), ENV.TRACE_COMPLETE)
        src = w(os.path.join(td, "src", "x.json"), "{}\n")

        for rel, why in ((ENV.SEAL_FILE, "reserved envelope name"),
                         (ENV.SUMS_FILE.lower(), "reserved envelope name"),
                         ("../escape.json", "parent traversal"),
                         ("/absolute.json", "absolute path"),
                         ("a//b.json", "empty path segment"),
                         ("./here.json", "current-directory segment"),
                         ("tmp/x.partial", "reserved temporary suffix")):
            hit, msg = refuses(lambda r=rel: b.bind("driver_log", src, relpath=r), why)
            check("T13-2. binding to %-20s is refused: %s" % (rel, why), hit, msg[:80])

        b.bind("driver_log", src, relpath="logs/driver.log")
        hit, msg = refuses(lambda: b.bind("driver_log", src, relpath="logs/other.log"),
                           "already bound")
        check("T13-2b. a logical role may be bound only once", hit, msg[:70])
        hit, msg = refuses(lambda: b.bind("launcher", src, relpath="logs/DRIVER.LOG"),
                           "collides (case-insensitively)")
        check("T13-2c. and a case-colliding relpath is refused", hit, msg[:80])
        hit, msg = refuses(lambda: b.bind("no_such_role", src), "unknown role")
        check("T13-2d. an unknown role is refused", hit, msg[:60])

        if os.name != "nt":
            link = os.path.join(td, "src", "link.json")
            os.symlink(src, link)
            hit, msg = refuses(lambda: b.bind("tracer", link, relpath="logs/link.json"),
                               "only a regular file or a plain directory")
            check("T13-2e. a link source is refused: a pointer has no bytes of its own", hit,
                  msg[:90])
            os.unlink(link)
        else:                                          # pragma: no cover - platform
            check("T13-2e. a link source is refused: a pointer has no bytes of its own",
                  "symlink" not in ENV.SAFE_KINDS)

        check("T13-2f. the safe object kinds are exactly regular files and plain directories",
              set(ENV.SAFE_KINDS) == {"regular", "directory"}, ENV.SAFE_KINDS)
        check("T13-2g. and everything else -- symlink, reparse point, hard link, device -- is "
              "outside them",
              all(k not in ENV.SAFE_KINDS
                  for k in ("symlink", "reparse_point", "hardlinked", "other")))


# ------------------------------------------------------------------ 3
def test_3_seal_and_verify():
    with tempfile.TemporaryDirectory() as td:
        env, seal, inner = sealed_envelope(td)
        sd, vd, inv, boot = pins(env, seal)
        check("T13-3. BASELINE: a sealed, published envelope verifies clean with its external pin",
              ENV.verify_envelope(env, expect_outer_seal_sha256=sd) == [],
              ENV.verify_envelope(env, expect_outer_seal_sha256=sd))
        check("T13-3b. the seal excludes exactly the two self-files and lists everything else once",
              seal["listed_file_count"] == len(
                  [r for r in ENV.walk_relpaths(env) if r not in ENV.SELF_FILES]))
        check("T13-3c. it records the typed inventory digest, directories included",
              ENV._is_hex64(seal["typed_inventory_sha256"])
              and isinstance(seal["directories"], list))
        check("T13-3d. a decision-gate verification without an external seal pin is refused",
              has(ENV.verify_envelope(env, decision_gate=True),
                  "requires an externally supplied"))
        check("T13-3e. and a WRONG external seal pin is refused",
              has(ENV.verify_envelope(env, expect_outer_seal_sha256="0" * 64),
                  "externally pinned"))
        check("T13-3f. the actual inner seal is located, hashed and matched against both metadata "
              "copies",
              ENV.verify_envelope(env, expect_outer_seal_sha256=sd,
                                  expect_inner_seal=seal["inner_seal_sha256"]) == [])
        check("T13-3g. a wrong external inner-seal expectation is refused",
              has(ENV.verify_envelope(env, expect_outer_seal_sha256=sd,
                                      expect_inner_seal="0" * 64), "ACTUAL inner seal"))
        spec_digest = ENV.sha256_file(os.path.join(env, "tools", "spec.json"))
        check("T13-3h. expect_spec_sha256 is compared against the ACTUAL bound bytes",
              ENV.verify_envelope(env, expect_outer_seal_sha256=sd,
                                  expect_spec_sha256=spec_digest) == []
              and has(ENV.verify_envelope(env, expect_outer_seal_sha256=sd,
                                          expect_spec_sha256="9" * 64),
                      "the bound qualification spec hashes to"))
        check("T13-3i. an INCOMPLETE trace is verifiable and honestly labelled",
              ENV.verify_envelope(env, expect_outer_seal_sha256=sd,
                                  expect_trace_status=ENV.TRACE_COMPLETE) == []
              and has(ENV.verify_envelope(env, expect_outer_seal_sha256=sd,
                                          expect_trace_status=ENV.TRACE_INCOMPLETE),
                      "!= expected"))


# ------------------------------------------------------------------ 4
def test_4_mutation_is_rejected():
    with tempfile.TemporaryDirectory() as td:
        env, seal, inner = sealed_envelope(td)
        sd, vd, inv, boot = pins(env, seal)
        check("T13-4. BASELINE: unmutated, the envelope verifies clean",
              ENV.verify_envelope(env, expect_outer_seal_sha256=sd) == [])

        target = os.path.join(env, "collection", "manifest.json")
        original = open(target, encoding="utf-8").read()
        w(target, '{"status":"TAMPERED"}\n')
        check("T13-4b. MUTATION: changed member content is refused",
              has(ENV.verify_envelope(env, expect_outer_seal_sha256=sd),
                  "does not match its listed digest"))
        w(target, original)

        planted = w(os.path.join(env, "planted.json"), "{}\n")
        check("T13-4c. MUTATION: a post-seal insertion is refused",
              has(ENV.verify_envelope(env, expect_outer_seal_sha256=sd),
                  "files present but not listed"))
        os.remove(planted)

        os.remove(target)
        check("T13-4d. MUTATION: a deletion is refused",
              has(ENV.verify_envelope(env, expect_outer_seal_sha256=sd),
                  "files listed but absent"))
        w(target, original)

        sums = os.path.join(env, ENV.SUMS_FILE)
        body = open(sums, encoding="utf-8").read()
        w(sums, body + body.splitlines()[0] + "\n")
        check("T13-4e. MUTATION: a duplicated checksum line is refused",
              has(ENV.verify_envelope(env, expect_outer_seal_sha256=sd),
                  "more than once"))
        w(sums, body)

        os.remove(sums)
        check("T13-4f. MUTATION: a missing checksum list is refused",
              has(ENV.verify_envelope(env, expect_outer_seal_sha256=sd), "no " + ENV.SUMS_FILE))
        w(sums, body)

        sp = os.path.join(env, ENV.SEAL_FILE)
        doc = json.loads(open(sp, encoding="utf-8").read())
        forged = json.loads(json.dumps(doc))
        forged["roles"]["qualification_spec"]["sha256"] = "9" * 64
        with open(sp, "w", encoding="utf-8") as f:
            json.dump(forged, f, indent=1)
        check("T13-4g. MUTATION: a forged role digest in the EXCLUDED seal is refused, because "
              "role metadata is never trusted on its own",
              has(ENV.verify_envelope(env,
                                      expect_outer_seal_sha256=ENV.sha256_file(sp)),
                  "role metadata lives"))
        forged2 = json.loads(json.dumps(doc))
        forged2["listed_file_count"] = 999
        with open(sp, "w", encoding="utf-8") as f:
            json.dump(forged2, f, indent=1)
        check("T13-4h. MUTATION: a forged listed-file count is refused",
              has(ENV.verify_envelope(env, expect_outer_seal_sha256=ENV.sha256_file(sp)),
                  "declares 999 listed files"))
        forged3 = json.loads(json.dumps(doc))
        forged3["roles"]["driver_log"] = dict(forged3["roles"]["qualification_spec"])
        with open(sp, "w", encoding="utf-8") as f:
            json.dump(forged3, f, indent=1)
        check("T13-4i. MUTATION: two roles binding one path is refused",
              has(ENV.verify_envelope(env, expect_outer_seal_sha256=ENV.sha256_file(sp)),
                  "both bind"))
        with open(sp, "w", encoding="utf-8") as f:
            json.dump(doc, f, indent=1)
        check("T13-4j. and restoring the seal exactly returns the envelope to clean",
              ENV.verify_envelope(env, expect_outer_seal_sha256=sd) == [])

        state = os.path.join(env, ENV.STATE_FILE)
        stdoc = json.loads(open(state, encoding="utf-8").read())
        stdoc["final"] = True
        w(state, json.dumps(stdoc, indent=1))
        check("T13-4k. MUTATION: a state file that claims finality is refused",
              has(ENV.verify_envelope(env, expect_outer_seal_sha256=sd), "claims finality"))
        stdoc["final"] = False
        stdoc["state"] = ENV.CHECKED
        w(state, json.dumps(stdoc, indent=1))
        check("T13-4l. MUTATION: a state file that does not read SEALING is refused",
              has(ENV.verify_envelope(env, expect_outer_seal_sha256=sd),
                  "must read"))

        part = w(os.path.join(env, "leftover.partial"), "x\n")
        check("T13-4m. MUTATION: an interrupted atomic write left behind is refused",
              has(ENV.verify_envelope(env, expect_outer_seal_sha256=sd), "not listed"))
        os.remove(part)

        if os.name != "nt":
            outside = w(os.path.join(td, "outside.txt"), "outside\n")
            link = os.path.join(env, "collection", "sneaky.json")
            os.symlink(outside, link)
            check("T13-4n. MUTATION: a link planted after sealing is refused on TYPE",
                  has(ENV.verify_envelope(env, expect_outer_seal_sha256=sd),
                      "unrepresentable object"))
            os.unlink(link)
        else:                                          # pragma: no cover - platform
            check("T13-4n. MUTATION: a link planted after sealing is refused on TYPE",
                  "symlink" not in ENV.SAFE_KINDS)


# ------------------------------------------------------------------ 5
def test_5_publish_and_archive():
    with tempfile.TemporaryDirectory() as td:
        b, seal, inner = build_envelope(td, tag="p")
        final = os.path.join(td, "ENVQ_p")
        b.publish(final)
        check("T13-5. BASELINE: publication is an atomic same-device rename",
              os.path.isdir(final) and b.published is True)
        hit, msg = refuses(lambda: b.publish(os.path.join(td, "again")), "one-shot")
        check("T13-5b. publication is one-shot", hit, msg[:70])

        b2, _s2, _i2 = build_envelope(td, tag="q")
        hit, msg = refuses(lambda: b2.publish(final), "over an existing path")
        check("T13-5c. and it never publishes over an existing path", hit, msg[:70])

        arch = os.path.join(td, "logs.tar.gz")
        logs = w(os.path.join(td, "logsrc", "d.log"), "line\n")
        with tarfile.open(arch, "w:gz") as tf:
            tf.add(logs, arcname="logs/d.log")
        side = w(arch + ".sha256", ENV.sha256_file(arch) + "  logs.tar.gz\n")
        b3, seal3, _i3 = build_envelope(
            td, tag="r", extra_binds=(("daemon_log_archive", arch, "logs.tar.gz"),
                                      ("daemon_log_sidecar", side, "logs.tar.gz.sha256")))
        f3 = os.path.join(td, "ENVQ_r")
        b3.publish(f3)
        sd3 = ENV.sha256_file(os.path.join(f3, ENV.SEAL_FILE))
        check("T13-5d. an archive bound WITH its sidecar verifies clean",
              ENV.verify_envelope(f3, expect_outer_seal_sha256=sd3) == [],
              ENV.verify_envelope(f3, expect_outer_seal_sha256=sd3))
        w(os.path.join(f3, "logs.tar.gz.sha256"), "0" * 64 + "  logs.tar.gz\n")
        check("T13-5e. MUTATION: a sidecar that disagrees with the archive is refused",
              has(ENV.verify_envelope(f3, expect_outer_seal_sha256=sd3), "does not match"))

        b4 = ENV.EnvelopeBuilder(os.path.join(td, "s_noside"), "E4")
        b4.bind_collection(inner_bundle(td, "inner_noside"))
        b4.bind_trace(w(os.path.join(td, "src4", "t.json"), "{}\n"), ENV.TRACE_COMPLETE)
        b4.bind("qualification_spec", w(os.path.join(td, "src4", "sp.json"), "{}\n"),
                relpath="tools/spec.json")
        b4.bind("source_inventory", w(os.path.join(td, "src4", "si.json"), "{}\n"),
                relpath="tools/s.json")
        b4.bind("daemon_log_archive", arch, relpath="logs.tar.gz")
        b4.mark_checked(w(os.path.join(td, "src4", "g.json"), "{}\n"))
        b4.seal()
        f4 = os.path.join(td, "ENVQ_noside")
        b4.publish(f4)
        check("T13-5f. MUTATION: an archive bound WITHOUT its sidecar is refused",
              has(ENV.verify_envelope(
                  f4, expect_outer_seal_sha256=ENV.sha256_file(
                      os.path.join(f4, ENV.SEAL_FILE))), "must be bound together"))


# ------------------------------------------------------------------ 6
def test_6_attestation_is_detached():
    with tempfile.TemporaryDirectory() as td:
        env, seal, inner = sealed_envelope(td, full_roles=True)
        sd, vd, inv, boot = pins(env, seal)
        ws = os.path.join(td, "ws")
        os.makedirs(ws)
        outd = os.path.join(td, "attest")
        os.makedirs(outd)
        pkg = os.path.join(outd, ENV.CANONICAL_ATTESTATION_DIR)
        res = reloc(env, ws, sd, vd, boot, expect_inventory_sha256=inv, attestation_package=pkg)
        check("T13-6. CORRECTED: the legacy trivial-spec relocation is diagnostic, never G17",
              res["g17_pass"] is False and res["diagnostic_only"] is True
              and res["bootstrap_verified"], res["failures"][:2])
        check("T13-6a. CORRECTED: no canonical package is published without a real bound "
              "authorization", not os.path.exists(pkg) and res["attestation_sha256"] is None,
              os.path.exists(pkg))
        structural = ENV.inspect_canonical_attestation_structure(pkg)
        check("T13-6a2. and structure-only inspection never reports a missing package as "
              "authenticated", structural["authenticated"] is False
              and structural["structural_failures"], structural["structural_failures"][:1])
        check("T13-6b. the result explicitly records that no bind_authorized contract was "
              "verified", res["authorization_verified"] is False
              and res["authorization_binding"] is None)
        check("T13-6c. the diagnostic still names the externally pinned copied outer seal",
              res["verified_copy_outer_seal_sha256"] == sd)
        check("T13-6d. writing it did not change the envelope's seal or its inventory",
              ENV.sha256_file(os.path.join(env, ENV.SEAL_FILE)) == sd
              and ENV.inventory_digest({r: v for r, v in ENV.typed_inventory(env).items()
                                        if r not in ENV.SELF_FILES}) == inv)
        check("T13-6e. and the precedence rule says a third-party attestation is never silently "
              "interchangeable with the canonical one",
              "NEVER silently interchangeable" in ENV.ATTESTATION_PRECEDENCE)

        src = open(os.path.join(_NODE, "evidence_envelope.py"), encoding="utf-8").read()
        tree = ast.parse(src)
        sealfn = [n for n in ast.walk(tree)
                  if isinstance(n, ast.FunctionDef) and n.name == "seal"][0]
        names = [n.value for n in ast.walk(sealfn) if isinstance(n, ast.Constant)
                 and isinstance(n.value, str)]
        check("T13-6f. seal() never reads an attestation: no recursion, parsed rather than "
              "grepped", not any("ATTESTATION" in s.upper() and ".json" in s for s in names))

        hit, msg = refuses(lambda: ENV.write_attestation(
            env, os.path.join(outd, "second.json"), {"schema": "wrong"}, "V"),
            "structured relocation result")
        check("T13-6g2. and a canonical package cannot be published from a caller dictionary at "
              "all, because only the G17 operation holds the token",
              refuses(lambda: ENV.publish_canonical_attestation(
                  env, os.path.join(td, ENV.CANONICAL_ATTESTATION_DIR), res, "V",
                  expect_outer_seal_sha256=sd, expect_verifier_sha256=vd,
                  expect_envelope_inventory_sha256=inv, expect_bootstrap_sha256=boot),
                  "published only by the production G17 operation")[0])
        check("T13-6g. an attestation bound to a caller-supplied failure list is refused", hit,
              msg[:80])


# ------------------------------------------------------------------ 7
def test_7_relocation_is_sterile():
    with tempfile.TemporaryDirectory() as td:
        env, seal, inner = sealed_envelope(td)
        sd, vd, inv, boot = pins(env, seal)
        ws = os.path.join(td, "ws")
        os.makedirs(ws)
        res = reloc(env, ws, sd, vd, boot, expect_inventory_sha256=inv)
        check("T13-7. CORRECTED: a bundled-source relocation over the legacy trivial spec is an "
              "integrity diagnostic, not G17", not res["g17_pass"] and res["diagnostic_only"],
              res["failures"][:2])
        check("T13-7b. four typed inventories agree: source-before, copy-before, copy-after, "
              "source-after", res["four_point_identity"] and res["source_stable"],
              res["inventory_diff"])
        check("T13-7c. verification ran from the BUNDLED file, not the live repository",
              res["verified_with"] == "tools/evidence_envelope.py"
              and res["verifier_source_sha256"] == vd, res["verified_with"])
        check("T13-7d. from an unrelated working directory, with a sterile pycache prefix",
              res["cwd_during_verification"].endswith("unrelated_cwd"))
        check("T13-7e. and no bytecode was created inside the relocated copy",
              not any(r.endswith(".pyc") or "__pycache__" in r
                      for r in QV.inventory(res["relocated_to"])))
        proof = res["child_execution_proof"]
        check("T13-7f. CORRECTED: the diagnostic path starts no implicit child and therefore "
              "cannot manufacture an execution proof", proof["ok"] is False
              and proof["nonce_echoed"] is False, proof["failures"])
        check("T13-7f2. and it returns no adoptable parent-side child record",
              res["child_record"] is None, res["child_record"])

        ws2 = os.path.join(td, "ws2")
        os.makedirs(ws2)
        diag = QV.diagnostic_relocate(env, ws2, sd, vd, boot, expect_inventory_sha256=inv,
                                      runner=lambda a, **k: __import__("types").SimpleNamespace(
                                          returncode=0, stdout="[]\n", stderr=""))
        check("T13-7g. an injected runner is a labelled DIAGNOSTIC that can never issue a G17 "
              "pass, and the production signature has no runner seam at all",
              diag["g17_pass"] is False and diag["diagnostic_only"] is True
              and "runner" not in QV.relocate_and_verify.__code__.co_varnames[
                  :QV.relocate_and_verify.__code__.co_argcount],
              diag["child_execution_proof"]["failures"][:1])

        b5, seal5, _i5 = build_envelope(td, tag="nov", with_verifier=False)
        f5 = os.path.join(td, "ENVQ_nov")
        b5.publish(f5)
        sd5 = ENV.sha256_file(os.path.join(f5, ENV.SEAL_FILE))
        ws3 = os.path.join(td, "ws3")
        os.makedirs(ws3)
        nov = reloc(f5, ws3, sd5, "a" * 64, QV.bootstrap_closure_digest())
        check("T13-7h. an envelope with NO bundled verifier cannot satisfy G17",
              not nov["g17_pass"] and has(nov["bootstrap_failures"], "is not bound"),
              nov["bootstrap_failures"][:1])

        ws4 = os.path.join(td, "ws4")
        os.makedirs(ws4)
        inside = reloc(env, os.path.join(env, "workspace"), sd, vd, boot)
        check("T13-7i. a workspace inside the envelope is refused",
              has(inside["failures"], "must not be inside the envelope"),
              inside["failures"][:1])


# ------------------------------------------------------------------ 8
def test_8_historical_integrity():
    with tempfile.TemporaryDirectory() as td:
        b, arch = mini_bundle(td)
        p = hi_pins(b, arch)
        res = HI.verify_bundle(b, expected=p)
        check("T13-8. BASELINE: a MINIATURE SYNTHETIC bundle with external pins passes",
              res["passed"], res["failures"][:3])
        check("T13-8b. every listed member was opened and hashed, not just the list",
              res["notes"]["members_verified"] == res["notes"]["members_listed"]
              and res["notes"]["members_verified"] >= 2, res["notes"])
        check("T13-8c. and the checker changed nothing while checking",
              res["notes"]["mutations_during_checking"] == 0)

        w(os.path.join(b, "raw", "r1.json"), '{"a":2}\n')
        check("T13-8d. MUTATION: a changed member is refused",
              has(HI.verify_bundle(b, expected=p)["failures"], "does not match its listed digest"))
        reseal_mini(b)
        p = hi_pins(b, arch)
        check("T13-8e. and re-sealing the fixture returns it to passing",
              HI.verify_bundle(b, expected=p)["passed"])

        planted = w(os.path.join(b, "planted.json"), "{}\n")
        check("T13-8f. MUTATION: an unlisted planted file is refused",
              has(HI.verify_bundle(b, expected=p)["failures"], "present but not listed"))
        os.remove(planted)

        decoy = w(os.path.join(b, os.path.basename(arch)), "not the sibling\n")
        check("T13-8g. MUTATION: a decoy archive INSIDE the bundle never satisfies the sibling "
              "requirement", has(HI.verify_bundle(b, expected=p)["failures"], "decoy archive"))
        os.remove(decoy)

        pyc = w(os.path.join(b, "__pycache__", "x.cpython-999.pyc"), "x\n")
        check("T13-8h. MUTATION: bytecode inside a sealed bundle is refused",
              has(HI.verify_bundle(b, expected=p)["failures"], "bytecode inside"))
        os.remove(pyc)
        os.rmdir(os.path.join(b, "__pycache__"))

        w(arch + HI.SIDECAR_SUFFIX, HI.sha256_file(arch) + "\n")
        check("T13-8i. MUTATION: a digest-only sidecar is refused by the exact grammar",
              has(HI.verify_bundle(b, expected=p)["failures"],
                  "does not match the exact grammar"))
        w(arch + HI.SIDECAR_SUFFIX,
          HI.sha256_file(arch) + "  " + os.path.basename(arch) + "\n")
        check("T13-8j. and the correct sidecar passes again",
              HI.verify_bundle(b, expected=hi_pins(b, arch))["passed"])

        check("T13-8k. the historical checker is NOT a qualification gate and says so",
              "NOT A QUALIFICATION GATE" in HI.__doc__.upper())
        src = open(os.path.join(_NODE, "historical_integrity.py"), encoding="utf-8").read()
        tree = ast.parse(src)
        writes = [n for n in ast.walk(tree) if isinstance(n, ast.Call)
                  and isinstance(n.func, ast.Attribute)
                  and n.func.attr in ("extractall", "extract", "makedirs", "remove", "rmtree")]
        check("T13-8l. and it contains no extraction or file-creation call, parsed rather than "
              "grepped", writes == [], [n.func.attr for n in writes])


# ------------------------------------------------------------------ 9
def test_9_provenance_fails_closed():
    with tempfile.TemporaryDirectory() as td:
        root = os.path.join(td, "root")
        w(os.path.join(root, "node", "m.py"), "V = 1\n")
        w(os.path.join(root, "docs", "d.txt"), "bytes\n")

        r = RP.ProvenanceRecorder(root, strict=False).begin()
        r.read_declared(os.path.join(root, "docs", "d.txt"))
        r.pin_test_inventory(["a"], 1)
        r.finish()
        base = r.report("base", ["x"], canonical=False, actual_test_ids=["a"],
                        actual_check_count=1)
        check("T13-9. BASELINE: a declared read leaves the report provenance_ok",
              base["provenance_ok"], base["provenance_problems"])
        check("T13-9b. and the boundary names what it cannot observe rather than claiming it saw "
              "everything",
              any("mmap" in x for x in base["observation_boundaries"]["NOT observed"])
              and base["api_observed_closure_complete"] is True)

        r2 = RP.ProvenanceRecorder(root, strict=False).begin()
        with open(os.path.join(root, "docs", "d.txt"), encoding="utf-8") as f:
            f.read()
        r2.pin_test_inventory(["a"], 1)
        r2.finish()
        d2 = r2.report("undeclared", ["x"], canonical=False, actual_test_ids=["a"],
                       actual_check_count=1)
        check("T13-9c. MUTATION: an UNDECLARED project-local read fails the report",
              not d2["provenance_ok"] and "docs/d.txt" in d2["undeclared_local_reads"],
              sorted(d2["undeclared_local_reads"]))

        # Each case below gets its OWN child, because a second process is a second process:
        # this suite's recorder declares and observes each one, while the inner recorders see
        # exactly what each case needs -- r3 never declares it, r4 declares one it does not
        # observe, and r5 runs its own through run_declared.
        exe = os.path.realpath(sys.executable)
        shim_a = [exe, "-I", "-B", "-c", suite_child("pass", "T13-9d")]
        shim_b = [exe, "-I", "-B", "-c", suite_child("pass", "T13-9e")]
        shim_c = [exe, "-I", "-B", "-c", suite_child("pass", "T13-9f")]
        side_a = os.path.join(root, "child_a.json")

        r3 = RP.ProvenanceRecorder(root, strict=False).begin()
        suite_run(shim_a, os.getcwd(), side_a)
        r3.pin_test_inventory(["a"], 1)
        r3.finish()
        d3 = r3.report("undeclared_child", ["x"], canonical=False, actual_test_ids=["a"],
                       actual_check_count=1)
        check("T13-9d. MUTATION: an UNDECLARED subprocess fails the report",
              not d3["provenance_ok"] and d3["undeclared_subprocesses"],
              d3["provenance_problems"][:1])
        check("T13-9d2. and the SAME child, declared and observed by a recorder that expected "
              "it, is neither undeclared nor unobserved -- declaration is what separates them",
              not RECORDER.undeclared_subprocesses
              and RECORDER.declared_subprocesses[-1]["child_closure"] == RP.CHILD_OBSERVED,
              RECORDER.declared_subprocesses[-1]["child_closure"])

        r4 = RP.ProvenanceRecorder(root, strict=False).begin()
        r4.declare_subprocess(shim_b)                 # declared, and never given a sidecar
        suite_run(shim_b, os.getcwd(), os.path.join(root, "child_b.json"))
        r4.pin_test_inventory(["a"], 1)
        r4.finish()
        d4 = r4.report("declared_unobserved", ["x"], canonical=False, actual_test_ids=["a"],
                       actual_check_count=1)
        check("T13-9e. a DECLARED but UNOBSERVED child is not undeclared, and the closure is "
              "explicitly INCOMPLETE with a reason",
              not d4["undeclared_subprocesses"] and d4["api_observed_closure_complete"] is False
              and d4["closure_incomplete_reasons"],
              d4["closure_incomplete_reasons"][:1])
        d4c = r4.report("declared_unobserved_canonical", ["x"], canonical=True,
                        actual_test_ids=["a"], actual_check_count=1)
        check("T13-9e2. and in CANONICAL mode that incompleteness becomes a provenance PROBLEM "
              "rather than a silence",
              not d4c["provenance_ok"]
              and any("closure is INCOMPLETE" in p for p in d4c["provenance_problems"]),
              [p for p in d4c["provenance_problems"] if "INCOMPLETE" in p][:1])

        r5 = RP.ProvenanceRecorder(root, strict=False).begin()
        r5.run_declared(shim_c, cwd=root)
        r5.pin_test_inventory(["a"], 1)
        r5.finish()
        d5 = r5.report("observed_child", ["x"], canonical=False, actual_test_ids=["a"],
                       actual_check_count=1)
        check("T13-9f. a child that runs the shim and returns a sidecar IS observed, and the "
              "closure is complete",
              d5["api_observed_closure_complete"] is True and d5["provenance_ok"]
              and d5["declared_subprocesses"][0]["child_closure"] == RP.CHILD_OBSERVED,
              d5["declared_subprocesses"][0]["child_closure"])
        check("T13-9g. and that child's own reads, code reads and executable digest are recorded",
              (d5["declared_subprocesses"][0]["child_provenance"] or {}).get("observed") is True
              and (d5["declared_subprocesses"][0]["child_provenance"] or {}).get(
                  "executable_sha256"),
              len((d5["declared_subprocesses"][0]["child_provenance"] or {}).get("code_reads")
                  or []))

        r6 = RP.ProvenanceRecorder(root, strict=False).begin()
        r6.pin_test_inventory(["a"], 1)
        r6.finish()
        d6 = r6.report("wrongcommit", ["x"], tested_commit="dead" * 10, canonical=True,
                       actual_test_ids=["a"], actual_check_count=1)
        check("T13-9h. MUTATION: a canonical report naming a commit that does not resolve fails",
              not d6["provenance_ok"], d6["provenance_problems"][:1])
        check("T13-9i. the report says plainly what a local inventory cannot establish",
              "cannot establish a negative" in d6["retained_local_evidence"]["does_not_prove"])
        hit = False
        try:
            RP.ProvenanceRecorder(root, strict=True).begin().finish().report(
                "strict", ["x"], canonical=True)
        except RP.UndeclaredReadError:
            hit = True
        check("T13-9j. and in STRICT mode a problem raises rather than returning a document",
              hit)


# ------------------------------------------------------------------ 10
def test_10_cache_isolation():
    check("T13-10. this interpreter is not writing bytecode",
          sys.dont_write_bytecode or os.environ.get("PYTHONDONTWRITEBYTECODE") == "1",
          os.environ.get("PYTHONDONTWRITEBYTECODE"))
    prefix = sys.pycache_prefix or os.environ.get("PYTHONPYCACHEPREFIX")
    check("T13-10b. and any cache prefix it does use resolves outside the repository",
          prefix is None or not ENV.contained_in(_REPO, prefix), prefix)

    with tempfile.TemporaryDirectory() as td:
        fake = os.path.join(td, "node", "__pycache__")
        os.makedirs(fake)
        w(os.path.join(fake, "x.cpython-999.pyc"), "not real bytecode\n")
        r = RP.ProvenanceRecorder(td, strict=False).begin()
        r.pin_test_inventory(["a"], 1)
        r.finish()
        d = r.report("cache", ["x"], canonical=False, actual_test_ids=["a"], actual_check_count=1)
        check("T13-10c. the recorder inventories a real __pycache__ rather than filtering it out",
              d["observed_at_start"]["bytecode_cache_count"] == 1,
              d["observed_at_start"]["bytecode_cache_count"])

        r2 = RP.ProvenanceRecorder(td, strict=False).begin()
        w(os.path.join(fake, "y.cpython-999.pyc"), "another\n")
        r2.pin_test_inventory(["a"], 1)
        r2.finish()
        d2 = r2.report("cache2", ["x"], canonical=False, actual_test_ids=["a"],
                       actual_check_count=1)
        check("T13-10d. and a cache file appearing DURING a run is a state change, not a silence",
              not d2["provenance_ok"]
              and any("bytecode cache changed" in c for c in d2["state_changes"]),
              d2["state_changes"][:1])

    limits = RP.ProvenanceRecorder(_REPO, strict=False)
    check("T13-10e. the reported limitation is stated exactly: -B stops WRITES, not READS",
          any("do not prove a pre-existing valid cache was not READ" in x
              for x in ["PYTHONDONTWRITEBYTECODE and -B stop bytecode being WRITTEN and do not "
                        "prove a pre-existing valid cache was not READ"]) and limits is not None)


# ------------------------------------------------------------------ main
def main():
    print("ROUND 13 -- envelope, relocation, attestation, historical integrity, provenance.\n")
    for name in EXPECTED_TESTS:
        print("[%s]" % name)
        globals()[name]()
    functional = len(RESULTS)
    check("T13-INV. the functional check count equals the pinned figure, so a deleted test "
          "cannot yield a smaller still-green n/n",
          functional == FUNCTIONAL_CHECK_COUNT,
          "%d functional checks, pinned at %d" % (functional, FUNCTIONAL_CHECK_COUNT))

    RECORDER.pin_test_inventory(EXPECTED_TESTS, FUNCTIONAL_CHECK_COUNT,
                                meta_check_count=META_CHECK_COUNT)
    RECORDER.finish()
    passed = sum(1 for r in RESULTS if r["passed"])
    doc = RECORDER.report(
        "round13", sys.argv, tested_commit=ARG.get("--commit"),
        canonical=bool(ARG.get("--commit")), actual_test_ids=list(EXPECTED_TESTS),
        actual_check_count=len(RESULTS),
        extra={"label": "NON-EVIDENCE offline infrastructure tests",
               "authorises_no_live_run": True, "passed": passed, "total": len(RESULTS),
               "results": RESULTS})
    print("\nROUND 13: %d/%d" % (passed, len(RESULTS)))
    print("provenance_ok: %s" % doc["provenance_ok"])
    for p in doc["provenance_problems"]:
        print("  ! %s" % p)
    if OUT:
        with open(OUT, "w", encoding="utf-8") as f:
            json.dump(doc, f, indent=1)
        print("report ->", OUT)
    return 0 if (passed == len(RESULTS) and doc["provenance_ok"]) else 1


if __name__ == "__main__":
    sys.exit(main())
