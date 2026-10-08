#!/usr/bin/env python3
"""Run provenance that fails closed: what was observed, when, and what it cannot observe.

PROSPECTIVE INFRASTRUCTURE. NON-EVIDENCE.

WHAT THE FIRST CORRECTIVE AUDIT REPRODUCED, AND WHAT CHANGED

  reads were invisible     an ordinary open() of a project-local document produced
                           provenance_ok=true. Reads are now intercepted at the Python file API.
  transient imports lost   origins are persisted when the import is REQUESTED.
  any commit accepted      tested_commit must resolve AND equal both the start and the end HEAD.
  drift invisible          state is fingerprinted by size, digest and type.
  bytecode filter          exact before/after cache inventories are compared.

WHAT THE THIRD CORRECTIVE AUDIT REPRODUCED (R3-5 and R3-10), AND WHAT CHANGED

  R3-5  three reads were invisible at once. (a) builtins.open() of a project-local .py that was
        NEVER imported was ignored by an explicit `if rel.endswith(".py"): return` -- the comment
        said "covered by the import closure", which assumed the very completeness the closure was
        supposed to prove; the file appeared in no closure and in no read list. (b) io.open() was
        never intercepted at all: `builtins.open is io.open` is True, but rebinding
        builtins.open leaves io.open pointing at the original function. (c) runpy.run_path()
        executed a local module that appeared nowhere. The report said provenance_ok=true.

        Now: suffix is never a reason to ignore a read; io.open and _io.open are wrapped
        alongside builtins.open; and _io.open_code -- which is what importlib's FileLoader,
        runpy.run_path and every explicit file loader actually use to fetch source -- is wrapped,
        so imported, exec'd and runpy'd local code all land in an APPEND-ONLY executed-source
        ledger that `del sys.modules[...]` cannot erase.

  R3-10 pin_test_inventory(ids, expected_count=99) followed by report(actual_test_ids=None) gave
        provenance_ok=true: the comparison was guarded by `and actual_test_ids is not None`, and
        expected_count was stored and never compared to anything. A pinned inventory now REQUIRES
        the exact actual id set and the exact actual check count, and the functional/meta split is
        declared so the two totals cannot drift by one while both look correct.

THE SUPPORTED EXECUTION MODEL, AND WHAT FALLS OUTSIDE IT

Observed: project-local reads through builtins.open / io.open / _io.open / os.open / pathlib;
local source fetched through _io.open_code, which covers imports, runpy.run_path and explicit file
loaders; subprocess creation; git HEAD, dirty-path content fingerprints and the bytecode cache.

NOT observed: reads through mmap after the file object closes; reads inside native extension code;
non-Python readers invoked by shell tools; and the internals of a child process UNLESS that child
runs the shim in CHILD_SHIM_SOURCE and returns its own provenance sidecar.

A canonical report therefore requires every subprocess to be declared AND to return an observed
child sidecar. A declared-but-unobserved child sets closure_complete=false with a reason, and in
canonical or strict mode that is a provenance PROBLEM. Truthful non-green is preferred to a
provenance_ok=true that quietly excludes a class it could not see.
"""
import builtins
import copy
import hashlib
import secrets
import importlib.abc
import io as _io_mod
import _io
import json
import os
import pathlib
import stat
import subprocess
import sys
import threading
import time

sys.dont_write_bytecode = True

# Captured before a recorder can wrap subprocess.Popen.  `run_observed` deliberately owns the
# process object it creates; a caller cannot replace this with a result-returning function and
# then ask the provenance layer to certify that a process ran.  This is still a cooperative
# Python API boundary, not a defence against hostile code in this interpreter (which could reach
# or mutate module globals).
_REAL_POPEN = subprocess.Popen

SCHEMA = "meepcoin-run-provenance/3"
CHILD_SIDECAR_SCHEMA = "meepcoin-child-provenance/4"
CHILD_RECORD_SCHEMA = "meepcoin-child-record/3"
CHILD_SIDECAR_KEYS = frozenset((
    "schema", "nonce", "command_identity", "argv", "cwd", "root", "pid",
    "executable", "executable_sha256", "reads", "code_reads", "metadata",
    "grandchildren", "exit", "observed",
))
# R5-7 reproduced a sidecar that named a project DOCUMENT as its executable, with that
# document's correct digest, `root` as an object, `cwd` and `exit` null and `argv` empty --
# for a child that was never started -- and was accepted as an observation. Every field below
# is now compared with a fact the PARENT observed, not with another field of the same sidecar.
CHILD_RECORD_KEYS = frozenset((
    "schema", "record_token", "argv", "command_identity", "command_display", "executable",
    "executable_sha256", "cwd", "root", "env_policy", "env_keys", "nonce", "sidecar_path",
    "started_utc", "returned_utc", "process_started", "process_returned", "exit",
    "pid", "timed_out", "process_proof_ok",
    "stdout_bytes", "stderr_bytes", "stdout_sha256", "stderr_sha256", "output_encoding",
    "declared_inputs", "inputs_after", "declared_outputs", "sidecar_sha256",
    "sidecar_failures", "sidecar_path_classes", "execution_proof_ok",
))
CHILD_RECORD_REQUIRED = frozenset((
    "schema", "record_token", "argv", "command_identity", "executable", "executable_sha256",
    "cwd", "root", "env_policy", "env_keys", "nonce", "started_utc", "returned_utc",
    "process_started", "process_returned",
    "pid", "exit", "timed_out", "process_proof_ok", "stdout_bytes", "stderr_bytes",
    "stdout_sha256", "stderr_sha256", "declared_inputs", "inputs_after",
    "sidecar_sha256", "sidecar_failures", "sidecar_path_classes", "execution_proof_ok",
))
READ_ITEM_KEYS = frozenset(("path", "how", "sha256"))
METADATA_ITEM_KEYS = frozenset(("path", "how", "kind", "entries", "entry_count", "size"))
GRANDCHILD_ITEM_KEYS = frozenset(("argv", "command_identity"))
READ_HOW = frozenset(("builtins.open", "io.open", "os.open"))
CODE_READ_HOW = frozenset(("open_code",))
METADATA_HOW = frozenset(("os.listdir", "os.scandir", "pathlib.Path.iterdir",
                          "pathlib.Path.stat"))
CHILD_OBSERVED = "api-observed (validated sidecar)"
CHILD_PROOF_ONLY = "parent-bound (execution proof, child reads NOT observed)"
CHILD_NOT_OBSERVED = "NOT OBSERVED"
# What this module actually is. It is not an operating-system tracer and does not claim to be.
OBSERVATION_MODEL = "python-api-observed"
ENV_POLICY_SCHEMA = "meepcoin-child-environment-policy/1"
ENV_POLICY_KEYS = frozenset(("schema", "kind", "allowed_keys", "environment_sha256"))
CHILD_RESERVED_ENV_KEYS = frozenset((
    "MEEPCOIN_CHILD_PROVENANCE", "MEEPCOIN_CHILD_ROOT", "MEEPCOIN_CHILD_NONCE",
    "MEEPCOIN_CHILD_COMMAND",
))

# The provenance tooling must not observe ITSELF.
_INTERNAL_DEPTH = 0


def environment_policy(env=None):
    """Return the exact, value-bound policy for caller-controlled child environment entries.

    The four MEEPCOIN_CHILD_* values are generated or overwritten by run_observed and are therefore
    excluded from the caller portion.  Values are not exposed in the record; their canonical
    key/value mapping is bound by SHA-256.  A caller-supplied policy must equal this derived object
    exactly or the process is not started.
    """
    source = dict(os.environ if env is None else env)
    if not all(isinstance(k, str) and isinstance(v, str) for k, v in source.items()):
        raise LaunchObserverError("the child environment must map strings to strings")
    caller = {k: v for k, v in source.items() if k not in CHILD_RESERVED_ENV_KEYS}
    payload = json.dumps(sorted(caller.items()), ensure_ascii=False,
                         separators=(",", ":")).encode("utf-8")
    return {
        "schema": ENV_POLICY_SCHEMA,
        "kind": "exact-caller-environment",
        "allowed_keys": sorted(caller),
        "environment_sha256": hashlib.sha256(payload).hexdigest(),
    }


class _internal:
    """Suppress self-observation for the duration of a block."""

    def __enter__(self):
        global _INTERNAL_DEPTH
        _INTERNAL_DEPTH += 1
        return self

    def __exit__(self, *exc):
        global _INTERNAL_DEPTH
        _INTERNAL_DEPTH -= 1
        return False


# Reserved keys `extra` may never overwrite: the verdict must not be editable by its own payload.
RESERVED_REPORT_KEYS = frozenset((
    "schema", "suite", "non_evidence", "live", "canonical", "tested_commit", "command",
    "interpreter", "observed_at_start",
    "observed_at_end", "state_changed_during_run", "state_changes", "import_closure",
    "import_closure_unmatched_at_tested_commit", "registered_reads", "undeclared_local_reads",
    "declared_subprocesses", "undeclared_subprocesses", "observation_boundaries", "limitations",
    "provenance_ok", "provenance_problems", "test_inventory", "retained_local_evidence", "utc",
    "executed_source_ledger", "api_observed_closure_complete", "observation_model",
    "closure_incomplete_reasons", "metadata_observations",
    "path_identity_problems", "code_self_reads", "actual_test_ids", "actual_check_count",
    "child_metadata_observations", "undeclared_child_local_reads", "diagnostic_children",
    "invalid_diagnostic_return",
    "finish_boundary_clean", "finish_boundary_failures",
    "child_code_reads_outside_tested_commit",
))

# The child-side shim. It is a SOURCE STRING on purpose: a child runs with an empty PYTHONPATH in
# a sterile environment and cannot import this module. Prepend it to a child's -c program (or pass
# it as a prelude) and set MEEPCOIN_CHILD_PROVENANCE to the sidecar path.
CHILD_SHIM_SOURCE = (
    "import atexit as _at, builtins as _b, hashlib as _hh, io as _iom, _io as _ioc, json as _js, "
    "os as _os, pathlib as _pl, subprocess as _sp, sys as _sy\n"
    "_pp = _os.environ.get('MEEPCOIN_CHILD_PROVENANCE')\n"
    "if _pp:\n"
    "    _root = _os.environ.get('MEEPCOIN_CHILD_ROOT') or ''\n"
    "    _nonce = _os.environ.get('MEEPCOIN_CHILD_NONCE') or ''\n"
    "    _cid = _os.environ.get('MEEPCOIN_CHILD_COMMAND') or ''\n"
    "    _rd, _cd, _md, _ch = {}, {}, {}, []\n"
    "    _oo, _io_o, _c_o, _oc, _po, _oso = (_b.open, _iom.open, _ioc.open, _ioc.open_code,\n"
    "                                        _sp.Popen, _os.open)\n"
    "    _old_ld, _old_sd, _old_it, _old_st = (_os.listdir, _os.scandir,\n"
    "                                          _pl.Path.iterdir, _pl.Path.stat)\n"
    "    def _dg(p):\n"
    "        try:\n"
    "            h = _hh.sha256()\n"
    "            f = _ioc.FileIO(p, 'r')\n"
    "            try:\n"
    "                while True:\n"
    "                    b = f.read(1 << 20)\n"
    "                    if not b:\n"
    "                        break\n"
    "                    h.update(b)\n"
    "            finally:\n"
    "                f.close()\n"
    "            return h.hexdigest()\n"
    "        except OSError:\n"
    "            return None\n"
    "    def _abs(p):\n"
    "        try:\n"
    "            return _os.path.realpath(_os.path.abspath(_os.fspath(p)))\n"
    "        except TypeError:\n"
    "            return None\n"
    "    def _note(d, p, how):\n"
    "        a = _abs(p)\n"
    "        if a is None:\n"
    "            return\n"
    "        d.setdefault(a, {'path': a, 'how': how, 'sha256': _dg(a)})\n"
    "    def _meta(p, how):\n"
    "        a = _abs(p)\n"
    "        if a is None:\n"
    "            return\n"
    "        e = _md.get(a)\n"
    "        if e is None:\n"
    "            e = _md[a] = {'path': a, 'how': [], 'kind': None, 'entries': None,\n"
    "                          'entry_count': None, 'size': None}\n"
    "        if how not in e['how']:\n"
    "            e['how'].append(how)\n"
    "        try:\n"
    "            if _os.path.isdir(a):\n"
    "                names = sorted(_old_ld(a))\n"
    "                e['kind'] = 'directory'\n"
    "                e['entries'] = names[:200]\n"
    "                e['entry_count'] = len(names)\n"
    "            else:\n"
    "                e['kind'] = 'file'\n"
    "                e['size'] = _os.stat(a).st_size\n"
    "        except OSError:\n"
    "            e['kind'] = e['kind'] or 'unreadable'\n"
    "    def _w(f, m='r', *a, **k):\n"
    "        q = _oo(f, m, *a, **k)\n"
    "        if 'r' in m or '+' in m:\n"
    "            _note(_rd, f, 'builtins.open')\n"
    "        return q\n"
    "    def _wi(f, m='r', *a, **k):\n"
    "        q = _io_o(f, m, *a, **k)\n"
    "        if 'r' in m or '+' in m:\n"
    "            _note(_rd, f, 'io.open')\n"
    "        return q\n"
    "    def _wo(p, fl, *a, **k):\n"
    "        q = _oso(p, fl, *a, **k)\n"
    "        if (fl & _os.O_ACCMODE) != _os.O_WRONLY:\n"
    "            _note(_rd, p, 'os.open')\n"
    "        return q\n"
    "    def _wc(p, *a, **k):\n"
    "        q = _oc(p, *a, **k)\n"
    "        _note(_cd, p, 'open_code')\n"
    "        return q\n"
    "    def _wld(p='.', *a, **k):\n"
    "        _meta(p, 'os.listdir')\n"
    "        return _old_ld(p, *a, **k)\n"
    "    def _wsd(p='.', *a, **k):\n"
    "        _meta(p, 'os.scandir')\n"
    "        return _old_sd(p, *a, **k)\n"
    "    def _wit(s, *a, **k):\n"
    "        _meta(s, 'pathlib.Path.iterdir')\n"
    "        return _old_it(s, *a, **k)\n"
    "    def _wst(s, *a, **k):\n"
    "        _meta(s, 'pathlib.Path.stat')\n"
    "        return _old_st(s, *a, **k)\n"
    "    class _WP(_po):\n"
    "        def __init__(s, args, *a, **k):\n"
    "            _av = [str(x) for x in (args if isinstance(args, (list, tuple)) else [args])]\n"
    "            _ci = _hh.sha256(_js.dumps(_av, ensure_ascii=True, "
    "separators=(',', ':')).encode('utf-8')).hexdigest()\n"
    "            _ch.append({'argv': _av, 'command_identity': _ci})\n"
    "            _po.__init__(s, args, *a, **k)\n"
    "    _b.open, _iom.open, _ioc.open, _ioc.open_code = _w, _wi, _wi, _wc\n"
    "    _os.open, _sp.Popen = _wo, _WP\n"
    "    _os.listdir, _os.scandir = _wld, _wsd\n"
    "    _pl.Path.iterdir, _pl.Path.stat = _wit, _wst\n"
    "    def _flush():\n"
    "        d = {'schema': 'meepcoin-child-provenance/4', 'nonce': _nonce,\n"
    "             'command_identity': _cid, 'pid': _os.getpid(),\n"
    "             'argv': list(_sy.argv), 'cwd': _abs(_os.getcwd()),\n"
    "             'root': (_abs(_root) if _root else ''),\n"
    "             'executable': _abs(_sy.executable),\n"
    "             'executable_sha256': _dg(_abs(_sy.executable)),\n"
    "             'reads': sorted(_rd.values(), key=lambda x: x['path']),\n"
    "             'code_reads': sorted(_cd.values(), key=lambda x: x['path']),\n"
    "             'metadata': sorted(_md.values(), key=lambda x: x['path']),\n"
    "             'grandchildren': _ch, 'exit': 0, 'observed': True}\n"
    "        try:\n"
    "            f = _oo(_pp, 'w', encoding='utf-8')\n"
    "            try:\n"
    "                _js.dump(d, f)\n"
    "            finally:\n"
    "                f.close()\n"
    "        except OSError:\n"
    "            pass\n"
    "    _at.register(_flush)\n"
)


def command_identity(argv):
    """The CANONICAL, unambiguous identity of a full argument vector.

    R5-6: a space-joined string erases argument boundaries, so ["same program", "argument"] and
    ["same", "program argument"] hashed identically. The vector is encoded as canonical JSON --
    an explicit array, explicit UTF-8, no insignificant whitespace -- before it is hashed, so
    the boundaries are part of the message."""
    payload = json.dumps([str(a) for a in argv], ensure_ascii=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def argv_display(argv, limit=200):
    """HUMAN-READABLE ONLY. Never an identity; never compared."""
    return " ".join(str(a) for a in argv)[:limit]


def argv_key(argv):
    """The identity used to match a declaration to an observation."""
    return "cmd:%s" % command_identity(argv)


CHILD_UNBOUND = "sidecar present, but NO parent-observed process start (not an observation)"

# Records produced by run_observed after its saved Popen returned and the frozen sidecar was
# validated. A dictionary that merely carries CHILD_RECORD_SCHEMA is a caller's claim.
_ADOPTABLE = {}
# Recorders that are active when run_observed creates a process are part of the same
# cooperative observation boundary.  The process-owning API bypasses the replaceable
# subprocess.Popen name deliberately, so one globally consumed capability is propagated to
# those already-active recorders when it is adopted.  A later recorder cannot replay it.
_ACTIVE_RECORDERS = []
# Serialises recorder begin/finish, the capture-to-Popen reservation, and capability adoption.
# Without this lock finish() could close its observation window between selection as an eligible
# recorder and registration of the real process returned by Popen.
_RECORDER_STATE_LOCK = threading.RLock()


class LaunchObserverError(RuntimeError):
    pass


class _LaunchObserver(object):
    """Legacy split observer retained only so stale callers fail intelligibly.

    Its methods cannot create an adoptable record.  A caller-driven `starting()` / `completed()`
    sequence proves only that those methods were called, not that an operating-system process
    existed.  Production code must use run_observed(), which owns one real Popen object from
    construction through return."""

    __slots__ = ("token", "argv", "identity", "display", "executable", "executable_sha256",
                 "cwd", "root", "nonce", "sidecar_path", "declared_inputs", "started_utc",
                 "returned_utc", "record", "adopted_by", "_started", "_done")

    def __init__(self, argv, executable, cwd, root, declared_inputs, sidecar_path):
        argv = [str(a) for a in argv]
        if not argv:
            raise LaunchObserverError("a launch needs a non-empty argument vector")
        exe = os.path.realpath(str(executable or argv[0]))
        if file_kind(exe) != "regular":
            raise LaunchObserverError(
                "the executable %r resolves to %r, which is %s, not a regular file; the parent "
                "hashes the exact file it is about to run"
                % (executable or argv[0], exe, file_kind(exe)))
        self.token = secrets.token_hex(16)
        self.argv = argv
        self.identity = command_identity(argv)
        self.display = argv_display(argv)
        self.executable = os.path.abspath(exe)
        self.executable_sha256 = sha256_file(exe)
        self.cwd = os.path.abspath(cwd or os.getcwd())
        self.root = os.path.abspath(root) if root else None
        self.nonce = secrets.token_hex(16)
        self.sidecar_path = sidecar_path
        self.declared_inputs = dict(declared_inputs or {})
        self.started_utc = None
        self.returned_utc = None
        self.record = None
        self.adopted_by = set()
        self._started = False
        self._done = False

    def child_env(self, base=None):
        """The MEEPCOIN_CHILD_* challenge this launch answers to."""
        env = dict(base if base is not None else os.environ)
        if self.sidecar_path:
            env["MEEPCOIN_CHILD_PROVENANCE"] = self.sidecar_path
        env["MEEPCOIN_CHILD_ROOT"] = str(self.root or "")
        env["MEEPCOIN_CHILD_NONCE"] = self.nonce
        env["MEEPCOIN_CHILD_COMMAND"] = self.identity
        return env

    def bind_argv(self, argv):
        """Fix the FINAL argument vector before the process starts.

        An operation whose child program embeds this observer's own nonce cannot know the
        vector when the observer is created. The nonce, the executable and the digest stay the
        observer's; only the vector is completed here, and only before it starts."""
        if self._started or self._done:
            raise LaunchObserverError("the argument vector is fixed once the process has started")
        argv = [str(a) for a in argv]
        if not argv:
            raise LaunchObserverError("a launch needs a non-empty argument vector")
        if os.path.normcase(os.path.realpath(argv[0]))                 != os.path.normcase(os.path.realpath(self.executable)):
            raise LaunchObserverError(
                "argv[0] %r is not the executable this observer hashed (%r)"
                % (argv[0], self.executable))
        self.argv = argv
        self.identity = command_identity(argv)
        self.display = argv_display(argv)
        return list(argv)

    def starting(self):
        """Called IMMEDIATELY before process creation."""
        self._started = True
        self.started_utc = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        return self

    def completed(self, returncode, stdout_bytes=b"", stderr_bytes=b"", env_keys=None,
                  env_policy=None, inputs_after=None, declared_outputs=None):
        """Called after the process returned. stdout/stderr are RAW BYTES."""
        if not self._started:
            raise LaunchObserverError("completed() before starting(): this observer never saw a "
                                      "process start, so it cannot record one")
        if self._done:
            raise LaunchObserverError("this launch has already been completed")
        for name, blob in (("stdout", stdout_bytes), ("stderr", stderr_bytes)):
            if not isinstance(blob, (bytes, bytearray)):
                raise LaunchObserverError(
                    "%s must be raw bytes; a decoded string cannot establish what the child "
                    "actually wrote (R5-5)" % name)
        self._done = True
        self.returned_utc = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        out, err = bytes(stdout_bytes), bytes(stderr_bytes)
        self.record = {
            "schema": CHILD_RECORD_SCHEMA,
            "record_token": self.token,
            "argv": list(self.argv),
            "command_identity": self.identity,
            "command_display": self.display,
            "executable": self.executable,
            "executable_sha256": self.executable_sha256,
            "cwd": self.cwd,
            "root": self.root,
            "env_policy": env_policy,
            "env_keys": sorted(env_keys or []),
            "nonce": self.nonce,
            "sidecar_path": self.sidecar_path,
            "started_utc": self.started_utc,
            "returned_utc": self.returned_utc,
            "process_started": True,
            "process_returned": True,
            "exit": int(returncode),
            "stdout_bytes": len(out), "stderr_bytes": len(err),
            "stdout_sha256": hashlib.sha256(out).hexdigest(),
            "stderr_sha256": hashlib.sha256(err).hexdigest(),
            "output_encoding": "raw bytes; counts and digests are over the exact byte stream",
            "declared_inputs": dict(self.declared_inputs),
            "inputs_after": dict(inputs_after or {}),
            "declared_outputs": dict(declared_outputs or {}),
            "execution_proof_ok": False,
        }
        return self.record


def begin_launch(argv, executable=None, cwd=None, root=None, declared_inputs=None,
                 sidecar_path=None):
    """Unsupported legacy split lifecycle; it can no longer claim process observation."""
    raise LaunchObserverError(
        "begin_launch() is unsupported: caller-driven starting()/completed() calls cannot prove "
        "a process ran. Use run_observed(), which creates and waits for the real process itself")


def _record_digest(record):
    payload = json.dumps(record, sort_keys=True, ensure_ascii=True,
                         separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _lexical_path_identity(path):
    return os.path.abspath(os.path.normpath(path)).replace("\\", "/").casefold()


def _path_identity(path):
    """Portable collision key for evidence paths, deliberately case-folded.

    Case-sensitive filesystems can contain two paths that differ only in case, but such an
    evidence set cannot be represented safely after relocation to a case-insensitive host.
    """
    return os.path.realpath(os.path.abspath(path)).replace("\\", "/").casefold()


def _contained(root, path):
    if not root:
        return False
    try:
        return _path_identity(os.path.commonpath((os.path.realpath(root),
                                                  os.path.realpath(path)))) \
            == _path_identity(os.path.realpath(root))
    except (OSError, TypeError, ValueError):
        return False


def _canonical_absolute(path, label, require_kind=None):
    if not isinstance(path, str) or not path or not os.path.isabs(path):
        raise LaunchObserverError("%s %r is not an absolute path" % (label, path))
    if "\x00" in path:
        raise LaunchObserverError("%s contains a NUL byte" % label)
    try:
        normalized = os.path.normpath(path)
        lexical = os.path.abspath(normalized)
        resolved = os.path.realpath(lexical)
    except (OSError, TypeError, ValueError) as e:
        raise LaunchObserverError("%s %r cannot be resolved: %s: %s"
                                  % (label, path, type(e).__name__, e))
    if os.path.normcase(path) != os.path.normcase(normalized):
        raise LaunchObserverError("%s %r is not in canonical lexical form; use %r"
                                  % (label, path, normalized))
    if _lexical_path_identity(lexical) != _lexical_path_identity(resolved):
        raise LaunchObserverError("%s %r is an alias for %r" % (label, lexical, resolved))
    if require_kind is not None and file_kind(resolved) != require_kind:
        raise LaunchObserverError("%s %r is %s, not %s"
                                  % (label, resolved, file_kind(resolved), require_kind))
    return resolved


def _normalise_expected_inputs(expected_inputs):
    if not isinstance(expected_inputs, dict):
        raise LaunchObserverError(
            "expected_inputs must be an object mapping canonical absolute paths to externally "
            "supplied lowercase sha256 digests")
    out, seen = {}, {}
    for raw, digest in expected_inputs.items():
        path = _canonical_absolute(raw, "launch input", "regular")
        if not _is_lower_hex64(digest):
            raise LaunchObserverError("launch input %r has no lowercase 64-hex expected digest"
                                      % path)
        key = _path_identity(path)
        if key in seen:
            raise LaunchObserverError("launch inputs %r and %r collide after path normalization"
                                      % (seen[key], path))
        seen[key] = path
        out[path] = digest
    return out


def _strict_json_bytes(blob):
    def object_(pairs):
        out = {}
        for key, value in pairs:
            if key in out:
                raise ValueError("duplicate JSON object key %r" % key)
            out[key] = value
        return out
    return json.loads(blob.decode("utf-8"), object_pairs_hook=object_)


def _sidecar_path_classes(entry, doc):
    classes = []
    root = entry.get("root")
    bound = {_path_identity(p) for p in (entry.get("declared_inputs") or {})
             if isinstance(p, str) and os.path.isabs(p)}
    for channel in ("reads", "code_reads", "metadata"):
        for item in (doc.get(channel) or []) if isinstance(doc, dict) else []:
            path = item.get("path") if isinstance(item, dict) else None
            if not isinstance(path, str) or not os.path.isabs(path):
                scope = "invalid"
            elif _contained(root, path):
                scope = "root"
            elif _path_identity(path) in bound:
                scope = "bound_input"
            else:
                scope = "external"
            classes.append({"channel": channel, "path": path, "scope": scope})
    return classes


class ObservedCompletedProcess(object):
    """CompletedProcess-compatible result of one process owned by run_observed.

    `stdout` and `stderr` are always the exact byte streams.  Text views are derived with strict
    UTF-8 and are None when decoding is impossible.
    """

    __slots__ = ("args", "returncode", "stdout", "stderr", "stdout_text", "stderr_text",
                 "record", "sidecar_failures", "sidecar_document")

    def __init__(self, args, returncode, stdout, stderr, record, sidecar_failures,
                 sidecar_document):
        self.args = list(args)
        self.returncode = returncode
        self.stdout = bytes(stdout)
        self.stderr = bytes(stderr)
        self.stdout_text = self._decode(self.stdout)
        self.stderr_text = self._decode(self.stderr)
        self.record = record
        self.sidecar_failures = list(sidecar_failures)
        self.sidecar_document = copy.deepcopy(sidecar_document)

    @staticmethod
    def _decode(blob):
        try:
            return blob.decode("utf-8")
        except UnicodeDecodeError:
            return None

    def check_returncode(self):
        if self.returncode:
            raise subprocess.CalledProcessError(self.returncode, self.args,
                                                output=self.stdout, stderr=self.stderr)


class _ObservedCapability(object):
    """Private frozen facts that make exactly one returned record adoptable."""

    __slots__ = ("record", "record_sha256", "sidecar_document", "sidecar_failures",
                 "eligible_recorders", "adopted", "token", "argv", "identity", "display",
                 "executable", "executable_sha256", "cwd", "root", "nonce",
                 "sidecar_path", "declared_inputs")

    def __init__(self, record, sidecar_document, sidecar_failures, eligible_recorders):
        self.record = record
        self.record_sha256 = _record_digest(record)
        self.sidecar_document = copy.deepcopy(sidecar_document)
        self.sidecar_failures = list(sidecar_failures)
        self.eligible_recorders = tuple(eligible_recorders)
        self.adopted = False
        self.token = record["record_token"]
        self.argv = list(record["argv"])
        self.identity = record["command_identity"]
        self.display = record["command_display"]
        self.executable = record["executable"]
        self.executable_sha256 = record["executable_sha256"]
        self.cwd = record["cwd"]
        self.root = record["root"]
        self.nonce = record["nonce"]
        self.sidecar_path = record["sidecar_path"]
        self.declared_inputs = dict(record["declared_inputs"])


def run_observed(argv, *, executable, expect_executable_sha256, cwd, root,
                 expected_inputs, sidecar_path, env=None, timeout=None, env_policy=None,
                 declared_outputs=()):
    """Create, communicate with, and wait for ONE real process, then freeze its provenance.

    No caller supplies a process, process factory, PID, return code, output, timestamp, or
    after-image.  The executable and every launch input have independently supplied digests and
    are checked immediately before this function's own saved Popen call and again after return.

    This enforces a cooperative Python API boundary.  It is not an OS tracer, executable-signing
    system, TPM measurement, or proof against hostile code in this interpreter.
    """
    if not isinstance(argv, (list, tuple)) or not argv \
            or not all(isinstance(a, str) for a in argv):
        raise LaunchObserverError("argv must be a non-empty list of strings")
    argv = list(argv)
    exe = _canonical_absolute(executable, "executable", "regular")
    argv_exe = _canonical_absolute(argv[0], "argv[0]", "regular")
    if _path_identity(argv_exe) != _path_identity(exe):
        raise LaunchObserverError("argv[0] %r is not the executable %r" % (argv[0], exe))
    if not _is_lower_hex64(expect_executable_sha256):
        raise LaunchObserverError("expect_executable_sha256 is not lowercase 64-hex")
    cwd_abs = _canonical_absolute(cwd, "cwd", "directory")
    root_abs = None if root is None else _canonical_absolute(root, "root", "directory")
    expected = _normalise_expected_inputs(expected_inputs)
    if sidecar_path is not None:
        sidecar = _canonical_absolute(sidecar_path, "sidecar path")
        parent = os.path.dirname(sidecar)
        if file_kind(parent) != "directory":
            raise LaunchObserverError("sidecar parent %r is not a directory" % parent)
        if os.path.lexists(sidecar):
            raise LaunchObserverError("refusing a pre-existing child sidecar %r" % sidecar)
    else:
        sidecar = None
    outputs = []
    for raw in declared_outputs or ():
        if not isinstance(raw, str) or not os.path.isabs(raw):
            raise LaunchObserverError("declared output %r is not an absolute path" % (raw,))
        outputs.append(os.path.realpath(os.path.abspath(raw)))

    child_env = dict(os.environ if env is None else env)
    observed_env_policy = environment_policy(child_env)
    if env_policy is not None and (not isinstance(env_policy, dict)
                                   or env_policy != observed_env_policy):
        raise LaunchObserverError(
            "the supplied environment policy does not exactly describe the child environment: "
            "expected %r" % observed_env_policy)
    bound_env_policy = observed_env_policy
    token, nonce = secrets.token_hex(16), secrets.token_hex(16)
    identity = command_identity(argv)
    if sidecar:
        child_env["MEEPCOIN_CHILD_PROVENANCE"] = sidecar
    else:
        child_env.pop("MEEPCOIN_CHILD_PROVENANCE", None)
    child_env["MEEPCOIN_CHILD_ROOT"] = str(root_abs or "")
    child_env["MEEPCOIN_CHILD_NONCE"] = nonce
    child_env["MEEPCOIN_CHILD_COMMAND"] = identity

    # The final byte checks and the process creation are adjacent inside this operation.  No
    # caller code, callback, clock or provider runs between them.
    got_exe = sha256_file(exe)
    if got_exe != expect_executable_sha256:
        raise LaunchObserverError("executable %r hashes to %s, not the expected %s"
                                  % (exe, str(got_exe)[:16], expect_executable_sha256[:16]))
    before = {}
    for path, want in expected.items():
        got = sha256_file(path)
        if file_kind(path) != "regular" or got != want:
            raise LaunchObserverError("launch input %r hashes to %s, not the expected %s"
                                      % (path, str(got)[:16], want[:16]))
        before[path] = got

    # Freeze the already-active cooperative observers at the same boundary as the real launch.
    # A recorder begun only after the process returned did not observe that run and is not added
    # to this set merely because it later receives the record object.
    with _RECORDER_STATE_LOCK:
        eligible_recorders = tuple(r for r in _ACTIVE_RECORDERS if r._active)
        try:
            process = _REAL_POPEN(argv, cwd=cwd_abs, env=child_env,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        except BaseException as e:
            raise LaunchObserverError("Popen failed before a process was observed: %s: %s"
                                      % (type(e).__name__, e))
        started_utc = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        pid = process.pid
        if not _is_int(pid) or pid <= 0:             # pragma: no cover - Popen contract
            try:
                process.kill()
                process.wait()
            finally:
                raise LaunchObserverError("Popen returned no positive integer PID")

        # Register the real Popen result BEFORE communicate, hashing, parsing or record
        # construction, while finish() is excluded by the same lifecycle lock.
        try:
            with _internal():
                for recorder in eligible_recorders:
                    recorder._register_started_observation(
                        token=token, argv=argv, identity=identity, display=argv_display(argv),
                        cwd=cwd_abs, root=root_abs, executable=exe,
                        executable_sha256=expect_executable_sha256,
                        env_keys=sorted(child_env), env_policy=bound_env_policy,
                        nonce=nonce, sidecar_path=sidecar, declared_inputs=expected,
                        started_utc=started_utc, pid=pid)
        except BaseException as e:
            try:
                if process.poll() is None:
                    process.kill()
                process.wait()
            finally:
                failure = "%s: %s" % (type(e).__name__, e)
                with _internal():
                    for recorder in eligible_recorders:
                        if any(d.get("record_token") == token
                               for d in recorder.declared_subprocesses):
                            recorder._mark_observation_aborted(token, process, failure)
            raise

    timed_out = False
    try:
        try:
            stdout_bytes, stderr_bytes = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            process.kill()
            stdout_bytes, stderr_bytes = process.communicate()
        returned_utc = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        out, err = bytes(stdout_bytes or b""), bytes(stderr_bytes or b"")
        returncode = process.returncode
        after = {path: sha256_file(path) if file_kind(path) == "regular" else None
                 for path in expected}
        drift = sorted(path for path, want in expected.items() if after.get(path) != want)
        exe_after = sha256_file(exe) if file_kind(exe) == "regular" else None
        process_proof_ok = bool(not timed_out and _is_int(returncode) and returncode == 0
                                and exe_after == expect_executable_sha256 and not drift)

        sidecar_doc, sidecar_sha, side_fails = None, None, []
        if not sidecar:
            side_fails.append(
                "this launch declared no sidecar path, so child closure is not observed")
        elif file_kind(sidecar) != "regular":
            side_fails.append("no regular provenance sidecar was written at %r" % sidecar)
        else:
            try:
                with _io.FileIO(sidecar, "r") as f:
                    sidecar_bytes = f.read()
                sidecar_sha = hashlib.sha256(sidecar_bytes).hexdigest()
                sidecar_doc = _strict_json_bytes(sidecar_bytes)
            except Exception as e:
                side_fails.append("unreadable sidecar: %s: %s" % (type(e).__name__, e))

        provisional = {
            "argv": argv, "command_identity": identity, "cwd": cwd_abs, "root": root_abs,
            "executable": exe, "executable_sha256": expect_executable_sha256,
            "nonce": nonce, "exit": returncode, "pid": pid,
            "process_started": True, "process_returned": True,
            "declared_inputs": dict(expected),
        }
        if sidecar_doc is not None:
            side_fails.extend(sidecar_failures(provisional, sidecar_doc, sidecar,
                                               expected_inputs=expected))
        if exe_after != expect_executable_sha256:
            side_fails.append("the parent-observed executable changed while the child ran")
        if drift:
            side_fails.append("launch input(s) changed while the child ran: %s" % drift)
        classes = _sidecar_path_classes(provisional, sidecar_doc or {})
        execution_ok = bool(process_proof_ok and sidecar_doc is not None and not side_fails)
        declared_out = {path: sha256_file(path) if file_kind(path) == "regular" else None
                        for path in outputs}
        record = {
            "schema": CHILD_RECORD_SCHEMA, "record_token": token, "argv": argv,
            "command_identity": identity, "command_display": argv_display(argv),
            "executable": exe, "executable_sha256": expect_executable_sha256,
            "cwd": cwd_abs, "root": root_abs, "env_policy": bound_env_policy,
            "env_keys": sorted(child_env), "nonce": nonce, "sidecar_path": sidecar,
            "started_utc": started_utc, "returned_utc": returned_utc,
            "process_started": True, "process_returned": True, "pid": pid,
            "exit": returncode, "timed_out": timed_out,
            "process_proof_ok": process_proof_ok,
            "stdout_bytes": len(out), "stderr_bytes": len(err),
            "stdout_sha256": hashlib.sha256(out).hexdigest(),
            "stderr_sha256": hashlib.sha256(err).hexdigest(),
            "output_encoding": "raw bytes; counts and digests are over the exact byte stream",
            "declared_inputs": dict(expected), "inputs_after": after,
            "declared_outputs": declared_out, "sidecar_sha256": sidecar_sha,
            "sidecar_failures": list(side_fails), "sidecar_path_classes": classes,
            "execution_proof_ok": execution_ok,
        }
        shape_fails = validate_child_record(record)
        if shape_fails:                              # pragma: no cover - internal invariant
            raise LaunchObserverError(
                "run_observed built an invalid child record: %s" % shape_fails)
        capability = _ObservedCapability(record, sidecar_doc, side_fails, eligible_recorders)
        _ADOPTABLE[token] = capability
        # A real child must not disappear merely because the caller drops the returned
        # capability.  Successful finalization replaces the started entry with an adoption-
        # pending entry; only globally single-use adoption can close it.
        with _RECORDER_STATE_LOCK, _internal():
            for recorder in capability.eligible_recorders:
                recorder._register_pending_observation(capability)
        return ObservedCompletedProcess(
            argv, returncode, out, err, record, side_fails, sidecar_doc)
    except BaseException as e:
        cleanup_error = None
        try:
            if process.poll() is None:
                process.kill()
            process.wait()
        except BaseException as ce:                  # preserve the original failure
            cleanup_error = "%s: %s" % (type(ce).__name__, ce)
        failure = "%s: %s" % (type(e).__name__, e)
        if cleanup_error:
            failure += "; cleanup also failed: " + cleanup_error
        _ADOPTABLE.pop(token, None)
        with _RECORDER_STATE_LOCK, _internal():
            for recorder in eligible_recorders:
                recorder._mark_observation_aborted(token, process, failure,
                                                   timed_out=timed_out)
        raise


def validate_child_record(record):
    """Shape/type/range check of a child record. Returns a list of failures.

    This is the SECOND gate. The first is that the record must have been produced by a
    completed run_observed call in this process; a dictionary carrying the schema name is not a
    record."""
    f = []
    if not isinstance(record, dict):
        return ["a child record must be an object, not %s" % type(record).__name__]
    if record.get("schema") != CHILD_RECORD_SCHEMA:
        f.append("child record schema %r != %r" % (record.get("schema"), CHILD_RECORD_SCHEMA))
    missing = sorted(CHILD_RECORD_REQUIRED - set(record))
    unknown = sorted(set(record) - CHILD_RECORD_KEYS)
    if missing:
        f.append("child record is missing %s" % missing)
    if unknown:
        f.append("child record carries unknown field(s) %s" % unknown)
    argv = record.get("argv")
    if not isinstance(argv, list) or not argv or not all(isinstance(a, str) for a in argv):
        f.append("child record argv is not a non-empty list of strings")
    elif record.get("command_identity") != command_identity(argv):
        f.append("child record command_identity does not match its own argv")
    exe = record.get("executable")
    if not isinstance(exe, str) or not os.path.isabs(exe):
        f.append("child record executable %r is not an absolute path" % (exe,))
    if not _is_lower_hex64(record.get("executable_sha256")):
        f.append("child record executable_sha256 is not a lowercase 64-hex digest")
    for k in ("cwd",):
        v = record.get(k)
        if not isinstance(v, str) or not os.path.isabs(v):
            f.append("child record %s %r is not an absolute path" % (k, v))
    if record.get("root") is not None and (not isinstance(record["root"], str)
                                           or not os.path.isabs(record["root"])):
        f.append("child record root %r is neither absent nor an absolute path"
                 % (record.get("root"),))
    policy = record.get("env_policy")
    if not isinstance(policy, dict) or set(policy) != ENV_POLICY_KEYS:
        f.append("child record env_policy does not have the exact environment-policy schema")
    else:
        if policy.get("schema") != ENV_POLICY_SCHEMA \
                or policy.get("kind") != "exact-caller-environment":
            f.append("child record env_policy carries the wrong schema or kind")
        allowed = policy.get("allowed_keys")
        if not isinstance(allowed, list) or not all(isinstance(k, str) for k in allowed) \
                or allowed != sorted(set(allowed)):
            f.append("child record env_policy.allowed_keys is not a sorted unique string list")
        if not _is_lower_hex64(policy.get("environment_sha256")):
            f.append("child record env_policy.environment_sha256 is not lowercase 64-hex")
    env_keys = record.get("env_keys")
    if not isinstance(env_keys, list) or not all(isinstance(k, str) for k in env_keys) \
            or env_keys != sorted(set(env_keys)):
        f.append("child record env_keys is not a sorted unique string list")
    elif isinstance(policy, dict) and isinstance(policy.get("allowed_keys"), list):
        caller_keys = sorted(k for k in env_keys if k not in CHILD_RESERVED_ENV_KEYS)
        if caller_keys != policy["allowed_keys"]:
            f.append("child record environment policy does not match its observed env_keys")
        required_reserved = {"MEEPCOIN_CHILD_ROOT", "MEEPCOIN_CHILD_NONCE",
                             "MEEPCOIN_CHILD_COMMAND"}
        if record.get("sidecar_path") is not None:
            required_reserved.add("MEEPCOIN_CHILD_PROVENANCE")
        actual_reserved = set(env_keys) & CHILD_RESERVED_ENV_KEYS
        if actual_reserved != required_reserved:
            f.append("child record env_keys does not contain exactly the parent-owned reserved "
                     "environment keys")
    if not _is_lower_hex(record.get("nonce"), 32):
        f.append("child record nonce is not a 32-character lowercase hex challenge")
    if record.get("process_started") is not True or record.get("process_returned") is not True:
        f.append("child record does not assert a parent-observed process start and return")
    if not _is_int(record.get("pid")) or record.get("pid", 0) <= 0:
        f.append("child record pid %r is not a positive parent-observed integer"
                 % (record.get("pid"),))
    if not _is_int(record.get("exit")):
        f.append("child record exit %r is not an integer" % (record.get("exit"),))
    for k in ("timed_out", "process_proof_ok", "execution_proof_ok"):
        if not isinstance(record.get(k), bool):
            f.append("child record %s %r is not a boolean" % (k, record.get(k)))
    for k in ("stdout_bytes", "stderr_bytes"):
        v = record.get(k)
        if not _is_int(v) or v < 0:
            f.append("child record %s %r is not a non-negative integer" % (k, v))
    for k in ("stdout_sha256", "stderr_sha256"):
        if not _is_lower_hex64(record.get(k)):
            f.append("child record %s is not a lowercase 64-hex digest" % k)
    for k in ("declared_inputs", "inputs_after", "declared_outputs"):
        if k in record and not isinstance(record[k], dict):
            f.append("child record %s is not an object" % k)
    declared = record.get("declared_inputs")
    after = record.get("inputs_after")
    if isinstance(declared, dict):
        for path, digest in declared.items():
            if not isinstance(path, str) or not os.path.isabs(path):
                f.append("child record declared input %r is not an absolute path" % (path,))
            if not _is_lower_hex64(digest):
                f.append("child record declared input %r has an invalid digest" % (path,))
    if isinstance(after, dict):
        if isinstance(declared, dict) and set(after) != set(declared):
            f.append("child record inputs_after does not name exactly its declared inputs")
        for path, digest in after.items():
            if digest is not None and not _is_lower_hex64(digest):
                f.append("child record after-image for %r has an invalid digest" % (path,))
    side_sha = record.get("sidecar_sha256")
    if side_sha is not None and not _is_lower_hex64(side_sha):
        f.append("child record sidecar_sha256 is neither absent nor lowercase 64-hex")
    if not isinstance(record.get("sidecar_failures"), list) or not all(
            isinstance(x, str) for x in (record.get("sidecar_failures") or [])):
        f.append("child record sidecar_failures is not a list of strings")
    classes = record.get("sidecar_path_classes")
    if not isinstance(classes, list):
        f.append("child record sidecar_path_classes is not a list")
    else:
        for item in classes:
            if not isinstance(item, dict) or set(item) != {"channel", "path", "scope"} \
                    or item.get("channel") not in ("reads", "code_reads", "metadata") \
                    or item.get("scope") not in ("root", "bound_input", "external", "invalid"):
                f.append("child record carries a malformed sidecar path classification")
                break
    if record.get("execution_proof_ok") is True and (
            record.get("process_proof_ok") is not True or record.get("sidecar_failures")):
        f.append("execution_proof_ok contradicts the process or sidecar proof")
    return f


def _is_int(v):
    return isinstance(v, int) and not isinstance(v, bool)


def _is_lower_hex(s, n):
    return isinstance(s, str) and len(s) == n and all(c in "0123456789abcdef" for c in s)


def _is_lower_hex64(s):
    return _is_lower_hex(s, 64)


def _git(repo, *args):
    with _internal():
        try:
            r = subprocess.run(["git", "-C", repo] + list(args), capture_output=True, text=True)
            return r.stdout.strip() if r.returncode == 0 else None
        except Exception:
            return None


def sha256_file(path):
    try:
        h = hashlib.sha256()
        with _io.FileIO(path, "r") as f:
            while True:
                chunk = f.read(1 << 20)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    except (OSError, TypeError, ValueError):
        return None


def file_kind(path):
    """regular / directory / symlink / reparse_point / other / absent. A Windows junction is a
    reparse point and is NOT a symlink to os.path.islink; see evidence_envelope for the case that
    produced this."""
    try:
        st = os.lstat(path)
    except (OSError, TypeError, ValueError):
        return "absent"
    if stat.S_ISLNK(st.st_mode):
        return "symlink"
    tag = getattr(st, "st_reparse_tag", 0) or 0
    if tag or (getattr(st, "st_file_attributes", 0) or 0) & getattr(
            stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400):
        return "reparse_point"
    if stat.S_ISDIR(st.st_mode):
        return "directory"
    if stat.S_ISREG(st.st_mode):
        return "regular"
    return "other"


class _ChildResult(object):
    """What run_declared returns: RAW bytes, plus a strict decoding that may be None.

    R5-5: `text=True` plus len(str) reported a character count as a byte count and hashed a
    decoding rather than the stream. Here the bytes are the fact and the text is derived."""

    __slots__ = ("returncode", "stdout", "stderr", "stdout_text", "stderr_text")

    def __init__(self, returncode, stdout, stderr):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        self.stdout_text = self._decode(stdout)
        self.stderr_text = self._decode(stderr)

    @staticmethod
    def _decode(blob):
        try:
            return blob.decode("utf-8")
        except UnicodeDecodeError:
            return None


class UndeclaredReadError(RuntimeError):
    """A project-local input was read or executed without being declared. Fatal for the report."""


# ------------------------------------------------------------------ import observation
class ImportObserver(importlib.abc.MetaPathFinder):
    """Records local modules as they are REQUESTED, and persists their origin."""

    def __init__(self, local_dir):
        self.local_dir = os.path.abspath(local_dir)
        self.requested = []
        self.seen = {}                                # module name -> absolute path

    def _record(self, name):
        cand = os.path.join(self.local_dir, name.replace(".", os.sep) + ".py")
        pkg = os.path.join(self.local_dir, name.replace(".", os.sep), "__init__.py")
        for c in (cand, pkg):
            if os.path.isfile(c):
                self.seen[name] = os.path.abspath(c)
                return

    def find_spec(self, fullname, path=None, target=None):
        self.requested.append(fullname)
        self._record(fullname)
        return None

    def __enter__(self):
        self._sweep()
        sys.meta_path.insert(0, self)
        return self

    def __exit__(self, *exc):
        self._sweep()
        try:
            sys.meta_path.remove(self)
        except ValueError:                            # pragma: no cover - defensive
            pass
        return False

    def _sweep(self):
        """Also catch modules imported before the observer existed, or by another finder."""
        for name, mod in list(sys.modules.items()):
            f = getattr(mod, "__file__", None)
            if not f:
                continue
            f = os.path.abspath(f)
            if f.endswith(".py") and (os.path.dirname(f) == self.local_dir
                                      or f.startswith(self.local_dir + os.sep)):
                self.seen[name] = f

    def local_modules(self):
        self._sweep()
        return dict(sorted(self.seen.items()))

    def note_exec(self, path):
        """A local file executed dynamically (exec/runpy) rather than imported."""
        p = os.path.abspath(path)
        self.seen["<exec>:" + os.path.basename(p)] = p


# ------------------------------------------------------------------ read observation
class _ReadWatch:
    """Intercepts project-local reads at the Python file API.

    `builtins.open is io.open` is True, and rebinding one leaves the other pointing at the
    original function -- which is exactly how R3-5's io.open() read went unseen. All three names
    are wrapped, and so is _io.open_code, which is what importlib's FileLoader, runpy.run_path and
    explicit file loaders use to fetch source."""

    def __init__(self, recorder):
        self.rec = recorder
        self._saved = {}

    def _watch(self, path, how):
        try:
            p = os.path.abspath(os.fspath(path))
        except TypeError:
            return
        self.rec._observe_read(p, how)

    def _watch_meta(self, path, how):
        try:
            p = os.path.abspath(os.fspath(path))
        except TypeError:
            return
        self.rec._observe_metadata(p, how)

    def _watch_code(self, path, how):
        try:
            p = os.path.abspath(os.fspath(path))
        except TypeError:
            return
        self.rec._observe_code(p, how)

    def __enter__(self):
        r = self
        self._saved["open"] = builtins.open
        self._saved["io_open"] = _io_mod.open
        self._saved["c_open"] = _io.open
        self._saved["os_open"] = os.open
        self._saved["p_open"] = pathlib.Path.open
        self._saved["p_rt"] = pathlib.Path.read_text
        self._saved["p_rb"] = pathlib.Path.read_bytes
        self._saved["io_open_code"] = _io_mod.open_code
        self._saved["c_open_code"] = _io.open_code
        self._saved["popen"] = subprocess.Popen
        self._saved["listdir"] = os.listdir
        self._saved["scandir"] = os.scandir
        self._saved["p_iterdir"] = pathlib.Path.iterdir
        self._saved["p_stat"] = pathlib.Path.stat

        def open_(file, mode="r", *a, **kw):
            if "r" in mode or "+" in mode:
                r._watch(file, "builtins.open")
            return r._saved["open"](file, mode, *a, **kw)

        def io_open(file, mode="r", *a, **kw):
            if "r" in mode or "+" in mode:
                r._watch(file, "io.open")
            return r._saved["io_open"](file, mode, *a, **kw)

        def os_open(path, flags, *a, **kw):
            # A descriptor is READABLE unless its access mode is O_WRONLY. R4-16 reproduced
            # os.open(path, O_RDWR | O_APPEND) slipping past, because O_APPEND was treated as a
            # write-only marker; O_APPEND says where writes go, not whether reads are possible.
            if (flags & os.O_ACCMODE) != os.O_WRONLY:
                r._watch(path, "os.open")
            return r._saved["os_open"](path, flags, *a, **kw)

        def p_open(self_, mode="r", *a, **kw):
            if "r" in mode or "+" in mode:
                r._watch(self_, "pathlib.Path.open")
            return r._saved["p_open"](self_, mode, *a, **kw)

        def p_rt(self_, *a, **kw):
            r._watch(self_, "pathlib.Path.read_text")
            return r._saved["p_rt"](self_, *a, **kw)

        def p_rb(self_, *a, **kw):
            r._watch(self_, "pathlib.Path.read_bytes")
            return r._saved["p_rb"](self_, *a, **kw)

        def open_code(path, *a, **kw):
            r._watch_code(path, "open_code")
            return r._saved["c_open_code"](path, *a, **kw)

        def listdir(path=None, *a, **kw):
            r._watch_meta(path if path is not None else ".", "os.listdir")
            return r._saved["listdir"](path, *a, **kw)

        def scandir(path=".", *a, **kw):
            r._watch_meta(path, "os.scandir")
            return r._saved["scandir"](path, *a, **kw)

        def p_iterdir(self_, *a, **kw):
            r._watch_meta(self_, "pathlib.Path.iterdir")
            return r._saved["p_iterdir"](self_, *a, **kw)

        def p_stat(self_, *a, **kw):
            r._watch_meta(self_, "pathlib.Path.stat")
            return r._saved["p_stat"](self_, *a, **kw)

        class WatchedPopen(r._saved["popen"]):
            # Recorders NEST: this class may subclass another recorder's WatchedPopen. Each
            # recorder must keep its OWN entry for the same process, so the observations are
            # kept in a per-instance map keyed by recorder rather than in one attribute that
            # the next __init__ would overwrite.
            def __init__(self, args, *a, **kw):
                candidate = r.rec._prepare_subprocess(args, kw)
                super().__init__(args, *a, **kw)
                entry = r.rec._observe_subprocess_started(candidate, self.pid)
                self.__dict__.setdefault("_meepcoin_entries", {})[id(r.rec)] = entry

            def wait(self, *a, **kw):
                rc = super().wait(*a, **kw)
                seen = self.__dict__.get("_meepcoin_entries") or {}
                r.rec._observe_subprocess_return(seen.get(id(r.rec)), rc)
                return rc

            def communicate(self, *a, **kw):
                value = super().communicate(*a, **kw)
                seen = self.__dict__.get("_meepcoin_entries") or {}
                r.rec._observe_subprocess_return(seen.get(id(r.rec)), self.returncode)
                return value

        builtins.open = open_
        _io_mod.open = io_open
        _io.open = io_open
        os.open = os_open
        pathlib.Path.open = p_open
        pathlib.Path.read_text = p_rt
        pathlib.Path.read_bytes = p_rb
        _io_mod.open_code = open_code
        _io.open_code = open_code
        os.listdir = listdir
        os.scandir = scandir
        pathlib.Path.iterdir = p_iterdir
        pathlib.Path.stat = p_stat
        subprocess.Popen = WatchedPopen
        return self

    def __exit__(self, *exc):
        builtins.open = self._saved["open"]
        _io_mod.open = self._saved["io_open"]
        _io.open = self._saved["c_open"]
        os.open = self._saved["os_open"]
        pathlib.Path.open = self._saved["p_open"]
        pathlib.Path.read_text = self._saved["p_rt"]
        pathlib.Path.read_bytes = self._saved["p_rb"]
        _io_mod.open_code = self._saved["io_open_code"]
        _io.open_code = self._saved["c_open_code"]
        os.listdir = self._saved["listdir"]
        os.scandir = self._saved["scandir"]
        pathlib.Path.iterdir = self._saved["p_iterdir"]
        pathlib.Path.stat = self._saved["p_stat"]
        subprocess.Popen = self._saved["popen"]
        return False


# ------------------------------------------------------------------ the recorder
def sidecar_failures(entry, doc, sidecar_path, used_nonces=None, used_sidecars=None,
                     expected_inputs=None):
    """Strictly validate one frozen child sidecar against facts measured by its parent."""
    f = []
    used_nonces = set() if used_nonces is None else used_nonces
    used_sidecars = set() if used_sidecars is None else used_sidecars
    if not isinstance(doc, dict):
        return ["the sidecar is %s, not an object" % type(doc).__name__]

    def strict_path(path, label):
        if not isinstance(path, str) or not path or not os.path.isabs(path):
            f.append("%s %r is not a canonical absolute path" % (label, path))
            return None
        if "\x00" in path:
            f.append("%s contains a NUL byte" % label)
            return None
        try:
            normalized = os.path.normpath(path)
            lexical, resolved = os.path.abspath(normalized), os.path.realpath(normalized)
        except (OSError, TypeError, ValueError) as e:
            f.append("%s %r cannot be resolved: %s: %s"
                     % (label, path, type(e).__name__, e))
            return None
        if os.path.normcase(path) != os.path.normcase(normalized):
            f.append("%s %r is not in canonical lexical form; use %r"
                     % (label, path, normalized))
            return None
        if _lexical_path_identity(lexical) != _lexical_path_identity(resolved):
            f.append("%s %r is not canonical; it resolves to %r" % (label, path, resolved))
            return None
        return resolved

    if not entry.get("process_started") or not entry.get("process_returned"):
        f.append("no parent-observed process start and return: a JSON file is not execution")
    if doc.get("schema") != CHILD_SIDECAR_SCHEMA:
        f.append("sidecar schema %r != %r" % (doc.get("schema"), CHILD_SIDECAR_SCHEMA))
    missing = sorted(CHILD_SIDECAR_KEYS - set(doc))
    unknown = sorted(set(doc) - CHILD_SIDECAR_KEYS)
    if missing:
        f.append("sidecar is missing %s" % missing)
    if unknown:
        f.append("sidecar carries unknown field(s) %s" % unknown)

    want_nonce = entry.get("nonce")
    if not _is_lower_hex(want_nonce, 32):
        f.append("this child was declared without a usable nonce")
    elif doc.get("nonce") != want_nonce:
        f.append("the sidecar does not echo this child's nonce")
    elif want_nonce in used_nonces:
        f.append("this nonce has already been used by another child")
    validated_sidecar_path = strict_path(sidecar_path, "the sidecar path")
    side_id = (_path_identity(validated_sidecar_path)
               if validated_sidecar_path is not None else None)
    if side_id is not None and side_id in used_sidecars:
        f.append("this sidecar file has already been claimed by another child")

    if doc.get("command_identity") != entry.get("command_identity"):
        f.append("the sidecar echoes command identity %r, not this launch's %r"
                 % (str(doc.get("command_identity"))[:16],
                    str(entry.get("command_identity"))[:16]))
    got_argv = doc.get("argv")
    if not isinstance(got_argv, list) or not got_argv \
            or not all(isinstance(x, str) for x in got_argv):
        f.append("the sidecar's argv is not a non-empty list of strings: %r" % (got_argv,))
    else:
        parent = [str(a) for a in (entry.get("argv") or [])]
        if got_argv[0] != "-c" and got_argv[0] not in parent \
                and os.path.basename(got_argv[0]) not in [os.path.basename(a) for a in parent]:
            f.append("the sidecar's argv[0] %r matches no declared argument" % got_argv[0])

    for field, want in (("cwd", entry.get("cwd")), ("root", entry.get("root"))):
        got = doc.get(field)
        if want is None:
            if got not in (None, ""):
                f.append("the sidecar reports %s %r for a launch that declared none"
                         % (field, got))
            continue
        got_path = strict_path(got, "the sidecar's %s" % field)
        if got_path is not None and _path_identity(got_path) != _path_identity(want):
            f.append("the sidecar reports %s %r, not the parent's %r" % (field, got, want))

    exe = strict_path(doc.get("executable"), "the sidecar executable")
    want_exe = entry.get("executable")
    if exe is not None and file_kind(exe) != "regular":
        f.append("the sidecar names executable %r, which is not a regular file" % exe)
    elif exe is not None and want_exe and _path_identity(exe) != _path_identity(want_exe):
        f.append("the sidecar names executable %r, not the file the parent launched (%r)"
                 % (exe, want_exe))
    if not _is_lower_hex64(doc.get("executable_sha256")):
        f.append("the sidecar's executable_sha256 is not a lowercase 64-hex digest")
    elif doc["executable_sha256"] != entry.get("executable_sha256"):
        f.append("the sidecar claims executable digest %s; the parent hashed %s"
                 % (doc["executable_sha256"][:16],
                    str(entry.get("executable_sha256"))[:16]))

    if not _is_int(doc.get("exit")):
        f.append("the sidecar's exit %r is not an integer" % (doc.get("exit"),))
    elif entry.get("exit") is not None and doc["exit"] != entry["exit"]:
        f.append("the sidecar reports exit %r, the parent saw %r"
                 % (doc.get("exit"), entry["exit"]))
    if not _is_int(doc.get("pid")) or (doc.get("pid") or 0) <= 0:
        f.append("the sidecar's pid %r is not a positive integer" % (doc.get("pid"),))
    elif not _is_int(entry.get("pid")) or doc["pid"] != entry["pid"]:
        f.append("the sidecar reports pid %r, the parent observed pid %r"
                 % (doc.get("pid"), entry.get("pid")))

    for field in ("reads", "code_reads", "metadata", "grandchildren"):
        if not isinstance(doc.get(field), list):
            f.append("sidecar %s is not a list" % field)

    bound_map = dict(entry.get("declared_inputs") or {})
    if expected_inputs is not None:
        bound_map.update(expected_inputs)
    bound = {_path_identity(p): d for p, d in bound_map.items()
             if isinstance(p, str) and os.path.isabs(p)}
    root = entry.get("root")

    for field, allowed_how in (("reads", READ_HOW), ("code_reads", CODE_READ_HOW)):
        seen = set()
        for item in (doc.get(field) or []):
            if not isinstance(item, dict) or set(item) != READ_ITEM_KEYS:
                f.append("sidecar %s entry must contain exactly %s"
                         % (field, sorted(READ_ITEM_KEYS)))
                continue
            path = strict_path(item.get("path"), "sidecar %s path" % field)
            if not isinstance(item.get("how"), str) or item.get("how") not in allowed_how:
                f.append("sidecar %s carries unknown observation API %r"
                         % (field, item.get("how")))
            if not _is_lower_hex64(item.get("sha256")):
                f.append("sidecar %s carries a malformed or non-lowercase digest" % field)
            if path is None:
                continue
            key = _path_identity(path)
            if key in seen:
                f.append("sidecar %s lists %r twice, or under colliding case" % (field, path))
            seen.add(key)
            if _contained(root, path) or key in bound:
                now = sha256_file(path) if file_kind(path) == "regular" else None
                if now is None:
                    f.append("sidecar %s local/bound path %r is deleted, unreadable, or not a "
                             "regular file" % (field, path))
                elif item.get("sha256") != now:
                    f.append("sidecar %s says %r hashes to %s; the parent re-derived %s"
                             % (field, path, str(item.get("sha256"))[:16], now[:16]))

    seen_meta = set()
    for item in (doc.get("metadata") or []):
        if not isinstance(item, dict) or set(item) != METADATA_ITEM_KEYS:
            f.append("sidecar metadata entry must contain exactly %s"
                     % sorted(METADATA_ITEM_KEYS))
            continue
        path = strict_path(item.get("path"), "sidecar metadata path")
        how = item.get("how")
        if not isinstance(how, list) or not how or not all(
                isinstance(x, str) and x in METADATA_HOW for x in how) or len(set(how)) != len(how):
            f.append("sidecar metadata how must be a non-empty unique list of known APIs")
        kind = item.get("kind")
        entries, count, size = item.get("entries"), item.get("entry_count"), item.get("size")
        if kind == "directory":
            if not isinstance(entries, list) or not all(isinstance(x, str) for x in entries) \
                    or entries != sorted(entries) or len(entries) > 200:
                f.append("sidecar directory metadata has an invalid entries prefix")
            if not _is_int(count) or count < 0 or (isinstance(entries, list) and (
                    count < len(entries) or (count <= 200 and count != len(entries))
                    or (count > 200 and len(entries) != 200))):
                f.append("sidecar directory metadata has an inconsistent entry_count")
            if size is not None:
                f.append("sidecar directory metadata must carry size=null")
        elif kind == "file":
            if entries is not None or count is not None or not _is_int(size) or size < 0:
                f.append("sidecar file metadata must carry null entries/count and a nonnegative "
                         "integer size")
        elif kind == "unreadable":
            if entries is not None or count is not None or size is not None:
                f.append("sidecar unreadable metadata must carry null entries/count/size")
        else:
            f.append("sidecar metadata kind %r is invalid" % kind)
        if path is None:
            continue
        key = _path_identity(path)
        if key in seen_meta:
            f.append("sidecar metadata lists %r twice, or under colliding case" % path)
        seen_meta.add(key)
        if _contained(root, path) or key in bound:
            actual_kind = file_kind(path)
            if actual_kind == "directory":
                try:
                    names = sorted(os.listdir(path))
                except OSError:
                    names = None
                if kind != "directory" or names is None or entries != names[:200] \
                        or count != len(names):
                    f.append("sidecar metadata for directory %r disagrees with the parent's "
                             "re-derived entries" % path)
            elif actual_kind == "regular":
                actual_size = os.path.getsize(path)
                if kind != "file" or size != actual_size:
                    f.append("sidecar metadata for file %r disagrees with the parent's size %r"
                             % (path, actual_size))
            else:
                f.append("sidecar metadata local/bound path %r is now %s and cannot be verified"
                         % (path, actual_kind))

    for g in (doc.get("grandchildren") or []):
        if not isinstance(g, dict) or set(g) != GRANDCHILD_ITEM_KEYS:
            f.append("sidecar grandchild entry must contain exactly %s"
                     % sorted(GRANDCHILD_ITEM_KEYS))
            continue
        gav = g.get("argv")
        if not isinstance(gav, list) or not gav or not all(isinstance(x, str) for x in gav):
            f.append("sidecar grandchild argv is not a non-empty list of strings")
        elif g.get("command_identity") != command_identity(gav):
            f.append("sidecar grandchild command_identity does not match its argv")
        f.append("the child started an unobserved grandchild; child closure is incomplete")

    if doc.get("observed") is not True:
        f.append("the sidecar does not declare itself an observation")
    if not f:
        used_nonces.add(want_nonce)
        used_sidecars.add(side_id)
    return f


def validate_launch_sidecar(record, sidecar_path=None, used_nonces=None, used_sidecars=None,
                            expected_inputs=None):
    """Diagnostic re-validation of a sidecar path against a completed record.

    Production consumers use the immutable document/failure snapshot returned by run_observed;
    reopening a mutable path later is not an authentication boundary.
    """
    if not isinstance(record, dict):
        return ["a child record must be an object"]
    path = sidecar_path or record.get("sidecar_path")
    if not path:
        return ["this launch declared no sidecar path, so nothing can be validated"]
    if not os.path.isfile(path):
        return ["no provenance sidecar was written at %r" % path]
    try:
        with _io.FileIO(path, "r") as stream:
            doc = _strict_json_bytes(stream.read())
    except Exception as e:
        return ["unreadable sidecar: %s: %s" % (type(e).__name__, e)]
    entry = {
        "argv": list(record.get("argv") or []),
        "command_identity": record.get("command_identity"),
        "cwd": record.get("cwd"), "root": record.get("root"),
        "executable": record.get("executable"),
        "executable_sha256": record.get("executable_sha256"),
        "nonce": record.get("nonce"), "exit": record.get("exit"),
        "pid": record.get("pid"), "declared_inputs": record.get("declared_inputs") or {},
        "process_started": record.get("process_started"),
        "process_returned": record.get("process_returned"),
    }
    return sidecar_failures(entry, doc, path, used_nonces, used_sidecars,
                            expected_inputs=expected_inputs)


class ProvenanceRecorder:
    def __init__(self, repo, local_dir=None, strict=True, doc_dirs=("docs",),
                 strict_reads=None):
        self.repo = os.path.abspath(repo)
        self.local_dir = os.path.abspath(local_dir or os.path.join(self.repo, "node"))
        self.strict = bool(strict if strict_reads is None else strict_reads)
        self.doc_dirs = tuple(os.path.join(self.repo, d) for d in doc_dirs)
        self.start = None
        self.end = None
        self.observer = ImportObserver(self.local_dir)
        self.watch = _ReadWatch(self)
        self.registered = {}
        self.undeclared = {}
        # A DATA read of a file that is already in the executed-source ledger. It is neither
        # undeclared nor ignored: the file is in the closure, hashed at execution and re-hashed at
        # the end, and the read is reported here so it is visible rather than exempt. This is
        # membership in an OBSERVED ledger, not the suffix rule R3-5 walked through.
        self.code_self_reads = {}
        # APPEND-ONLY. Nothing removes from this, so evicting a module cannot erase its execution.
        self.executed = {}
        self.path_problems = []
        # DECISION-RELEVANT METADATA. R4-17 selected a project-local file by iterating a directory
        # and reading sizes, and nothing appeared anywhere while the report claimed completeness.
        # Enumeration and stat of project-local paths are now INSIDE the observed boundary.
        self.metadata = {}
        self.used_nonces = set()
        self.used_sidecars = set()
        self.declared_subprocesses = []
        self.undeclared_subprocesses = []
        self._active = False
        self._in_hook = False
        self.test_inventory = None
        self.finish_boundary_failures = []
        self.finished_with_incomplete_diagnostic = False

    # ---- path identity ----
    def _identity(self, p):
        """(abspath, realpath, problem_or_None). Aliasing and unresolvable identities are noted."""
        ap = os.path.abspath(p)
        try:
            rp = os.path.realpath(ap)
        except OSError:                               # pragma: no cover - defensive
            return ap, None, "%r cannot be resolved" % ap
        if os.path.normcase(rp) != os.path.normcase(ap):
            return ap, rp, ("%r is an alias for %r; a path that is not its own realpath cannot "
                            "be compared by name" % (ap, rp))
        if os.path.normcase(os.path.abspath(ap)) != os.path.normcase(ap):  # pragma: no cover
            return ap, rp, "%r does not normalise to itself" % ap
        return ap, rp, None

    def _project_local(self, p):
        # The project directories THEMSELVES count, not only their contents: enumerating
        # `<repo>/docs` is a project-local observation (R4-17).
        if p == self.local_dir or p in self.doc_dirs:
            return True
        if p.startswith(self.local_dir + os.sep) or os.path.dirname(p) == self.local_dir:
            return True
        return any(p.startswith(d + os.sep) for d in self.doc_dirs)

    # ---- interception callbacks ----
    def _observe_read(self, path, how):
        """A DATA read. Suffix is never a reason to ignore one: R3-5 read an unimported local .py
        through builtins.open and the `.py` exemption made it invisible."""
        if not self._active or self._in_hook or _INTERNAL_DEPTH:
            return
        ap, rp, problem = self._identity(path)
        target = rp or ap
        if not (self._project_local(ap) or self._project_local(target)):
            return
        if file_kind(target) == "directory":
            # A directory descriptor is not a file read. Directory access is ENUMERATION, and it
            # is observed on the metadata channel, where an entry/type/size identity is recorded.
            self._observe_metadata(target, how)
            return
        rel = os.path.relpath(target, self.repo).replace(os.sep, "/")
        self._in_hook = True
        try:
            if problem:
                self.path_problems.append({"path": ap, "resolved": rp, "problem": problem,
                                           "how": how})
            if rel in self.registered:
                return
            if not target.startswith(self.repo + os.sep):
                self.path_problems.append(
                    {"path": ap, "resolved": rp, "how": how,
                     "problem": "%r resolves OUTSIDE the repository (%r); a reparse point or "
                                "symlink escape is not a project-local read" % (ap, target)})
                return
            digest = sha256_file(target)
            entry = {"path": rel, "how": how, "sha256": digest}
            if rel in self.executed:
                # Already in the executed-source ledger: it is IN the closure, was hashed when it
                # ran and is re-hashed at the end. Recorded, never silently dropped.
                self.code_self_reads.setdefault(rel, entry)
                return
            if digest is None:
                entry["problem"] = ("the file could not be hashed after it was opened -- it may "
                                    "have been deleted or replaced")
                self.path_problems.append(dict(entry, problem=entry["problem"]))
            self.undeclared.setdefault(rel, entry)
        finally:
            self._in_hook = False

    def _observe_code(self, path, how):
        """SOURCE fetched for execution: an import, runpy.run_path, or an explicit file loader.

        Append-only. `del sys.modules[name]` afterwards cannot remove what is written here."""
        if not self._active or self._in_hook or _INTERNAL_DEPTH:
            return
        ap, rp, problem = self._identity(path)
        target = rp or ap
        if not (self._project_local(ap) or self._project_local(target)):
            return
        rel = os.path.relpath(target, self.repo).replace(os.sep, "/")
        self._in_hook = True
        try:
            if problem:
                self.path_problems.append({"path": ap, "resolved": rp, "problem": problem,
                                           "how": how})
            self.executed.setdefault(rel, {
                "path": rel, "how": how,
                "sha256_at_execution": sha256_file(target),
                "first_seen_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            })
        finally:
            self._in_hook = False

    def _observe_metadata(self, path, how):
        """Directory enumeration and stat of a PROJECT-LOCAL path. Not a read: a metadata
        observation, recorded with a stable entry/type/size identity."""
        if not self._active or self._in_hook or _INTERNAL_DEPTH:
            return
        if not self._project_local(path):
            return
        rel = os.path.relpath(path, self.repo).replace(os.sep, "/")
        self._in_hook = True
        try:
            entry = self.metadata.get(rel)
            if entry is None:
                entry = {"path": rel, "how": sorted({how}), "kind": file_kind(path)}
                if entry["kind"] == "directory":
                    try:
                        names = sorted(self.watch._saved["listdir"](path))
                    except OSError:                   # pragma: no cover - defensive
                        names = None
                    entry["entries"] = names
                    entry["entry_count"] = None if names is None else len(names)
                elif entry["kind"] == "regular":
                    entry["size"] = os.path.getsize(path)
                self.metadata[rel] = entry
            elif how not in entry["how"]:
                entry["how"] = sorted(set(entry["how"]) | {how})
        finally:
            self._in_hook = False

    def _prepare_subprocess(self, args, popen_kwargs=None):
        """Match a Popen attempt, without falsely calling it a process start.

        The WatchedPopen wrapper calls _observe_subprocess_started only after the underlying
        Popen constructor has returned a real object with a real PID.
        """
        if not self._active or self._in_hook or _INTERNAL_DEPTH:
            return None
        argv = list(args) if isinstance(args, (list, tuple)) else [str(args)]
        key = argv_key(argv)
        self._in_hook = True
        try:
            for d in self.declared_subprocesses:
                if d["argv_key"] != key:
                    continue
                if d.get("process_started"):
                    continue                        # a second start of the same command
                exe = os.path.realpath(str(argv[0])) if argv else None
                if exe and file_kind(exe) == "regular":
                    d["executable"] = exe
                    d["executable_sha256"] = sha256_file(exe)
                cwd = (popen_kwargs or {}).get("cwd")
                d["cwd"] = os.path.abspath(cwd) if cwd else os.path.abspath(os.getcwd())
                env = (popen_kwargs or {}).get("env") or {}
                d["env_keys"] = sorted(env)
                d["root"] = env.get("MEEPCOIN_CHILD_ROOT") or d.get("root")
                return {"declared": d}
            return {"undeclared": {
                "argv_key": key, "command_display": argv_display(argv),
                "project_local_arguments": [str(a) for a in argv if isinstance(a, str)
                                             and self._project_local(os.path.abspath(a))]}}
        finally:
            self._in_hook = False

    def _observe_subprocess_started(self, candidate, pid):
        """Commit a matched start only after Popen returned a positive PID."""
        if candidate is None or self._in_hook or _INTERNAL_DEPTH:
            return None
        self._in_hook = True
        try:
            if "undeclared" in candidate:
                self.undeclared_subprocesses.append(candidate["undeclared"])
                return None
            entry = candidate.get("declared")
            if entry is None:
                return None
            entry["process_started"] = True
            entry["started_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            entry["pid"] = int(pid)
            entry["observed_by"] = ("the recorder's subprocess.Popen interception after the "
                                    "constructor returned a real PID")
            return entry
        finally:
            self._in_hook = False

    def _observe_subprocess_return(self, entry, returncode):
        """Called when the observed child returns. The exit is the PARENT's, not the child's."""
        if entry is None or entry.get("process_returned") or self._in_hook or _INTERNAL_DEPTH:
            return
        self._in_hook = True
        try:
            entry["process_returned"] = True
            entry["returned_utc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            entry["exit"] = int(returncode)
            entry["output_encoding"] = ("this child's pipes belong to the caller, so the parent "
                                        "recorded no stdout/stderr bytes for it")
        finally:
            self._in_hook = False

    # ---- state observation ----
    def _fingerprint(self, rel):
        full = os.path.join(self.repo, rel.replace("/", os.sep))
        return {"path": rel, "kind": file_kind(full),
                "size": os.path.getsize(full) if os.path.isfile(full) else None,
                "sha256": sha256_file(full) if os.path.isfile(full) else None}

    def _observe(self, when):
      with _internal():
        status = _git(self.repo, "status", "--porcelain", "--untracked-files=all")
        head = _git(self.repo, "rev-parse", "HEAD")
        dirty = [ln for ln in (status or "").splitlines()]
        fp = {}
        for ln in dirty:
            rel = ln[3:].strip().strip('"')
            if "->" in rel:
                rel = rel.split("->")[-1].strip()
            fp[rel] = self._fingerprint(rel)
        cache = {}
        for dirpath, _d, files in os.walk(self.local_dir):
            if os.path.basename(dirpath) == "__pycache__":
                for fn in sorted(files):
                    full = os.path.join(dirpath, fn)
                    rel = os.path.relpath(full, self.repo).replace(os.sep, "/")
                    cache[rel] = {"size": os.path.getsize(full), "sha256": sha256_file(full)}
        return {
            "when": when,
            "utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "branch": _git(self.repo, "rev-parse", "--abbrev-ref", "HEAD"),
            "head": head,
            "git_available": status is not None and head is not None,
            "dirty_paths": dirty,
            "dirty_count": len(dirty),
            "dirty_fingerprints": fp,
            "bytecode_cache": cache,
            "bytecode_cache_count": len(cache),
        }

    def begin(self):
        """MUST be called before any test body or imported test module runs."""
        with _RECORDER_STATE_LOCK:
            if self._active:
                raise RuntimeError("this provenance recorder is already active")
            if self.start is not None or self.end is not None:
                raise RuntimeError("a provenance recorder is single-use; create a new recorder "
                                   "instead of beginning it again")
            self.start = self._observe("start")
            self.observer.__enter__()
            try:
                self.watch.__enter__()
            except BaseException:
                self.observer.__exit__(*sys.exc_info())
                raise
            self._active = True
            _ACTIVE_RECORDERS.append(self)
            return self

    def finish(self, allow_incomplete_diagnostic=False):
        """Close this single-use recorder, refusing ordinary closure over pending children.

        The narrow diagnostic option does not forgive anything: it records an irreversible
        finish-boundary failure, so even a later finalization/adoption cannot produce a green
        report.  It exists only so an explicitly noncanonical negative-control report can be
        emitted instead of leaking hooks.
        """
        with _RECORDER_STATE_LOCK:
            if not self._active or self.end is not None:
                raise RuntimeError("finish() requires one active, not-yet-finished recorder")
            if not _ACTIVE_RECORDERS or _ACTIVE_RECORDERS[-1] is not self:
                raise RuntimeError("active provenance recorders must finish in LIFO order so an "
                                   "outer recorder cannot remove an inner recorder's hooks")
            outstanding = [d.get("record_token") or d.get("argv_key")
                           for d in self.declared_subprocesses
                           if d.get("observation_pending") or d.get("adoption_pending")]
            if outstanding and not allow_incomplete_diagnostic:
                raise RuntimeError("finish() refused with in-flight or unadopted real child "
                                   "observations: %s" % outstanding[:4])
            if outstanding:
                self.finished_with_incomplete_diagnostic = True
                self.finish_boundary_failures.append(
                    "the observation window was explicitly closed for a noncanonical diagnostic "
                    "with in-flight or unadopted real child token(s): %s" % outstanding[:4])
            self._active = False
            _ACTIVE_RECORDERS.pop()
            self.watch.__exit__(None, None, None)
            self.observer.__exit__(None, None, None)
            self.end = self._observe("end")
            return self

    # ---- declarations ----
    def register_read(self, path, kind="input"):
        full = os.path.abspath(path)
        rel = os.path.relpath(os.path.realpath(full), self.repo).replace(os.sep, "/")
        self.registered[rel] = {"path": rel, "kind": kind, "sha256": sha256_file(full),
                                "exists": os.path.exists(full),
                                "size": os.path.getsize(full) if os.path.isfile(full) else None}
        self.undeclared.pop(rel, None)
        return full

    def read_declared(self, path, kind="input", mode="r", encoding="utf-8"):
        full = self.register_read(path, kind)
        self._in_hook = True
        try:
            if "b" in mode:
                with self.watch._saved.get("open", open)(full, mode) as f:
                    return f.read()
            with self.watch._saved.get("open", open)(full, mode, encoding=encoding) as f:
                return f.read()
        finally:
            self._in_hook = False

    def run_declared(self, argv, inputs=(), observe_child=True, child_root=None,
                     outputs=(), **kw):
        """Convenience wrapper around the process-owning run_observed API.

        This recorder derives pins for its declared test inputs at entry.  Production
        authorization paths must call run_observed directly with independently retained pins.
        """
        for bad in ("text", "encoding", "errors", "universal_newlines"):
            if bad in kw:
                raise ValueError(
                    "run_declared always captures RAW BYTES; %r would make the recorded sizes "
                    "and digests facts about a decoding, not about the child" % bad)
        argv = [str(a) for a in argv]
        if not argv:
            raise ValueError("run_declared needs a non-empty argv")
        cwd = os.path.realpath(os.path.abspath(kw.pop("cwd", None) or os.getcwd()))
        env = kw.pop("env", None)
        timeout = kw.pop("timeout", None)
        if kw:
            raise ValueError("run_declared does not accept process options %s; the process-"
                             "owning API fixes its launch policy" % sorted(kw))
        declared = {}
        with _internal():
            for p in list(inputs) + [a for a in argv if isinstance(a, str) and os.path.isfile(a)]:
                ap = os.path.realpath(os.path.abspath(p))
                if file_kind(ap) == "regular":
                    declared[ap] = sha256_file(ap)
        sidecar = None
        owned = False
        if observe_child:
            child_env = dict(os.environ if env is None else env)
            sidecar = child_env.get("MEEPCOIN_CHILD_PROVENANCE")
            if not sidecar:
                with _internal():
                    import tempfile as _tf
                    sidecar = os.path.join(
                        _tf.gettempdir(), "child_provenance_%d_%d.json"
                        % (len(self.declared_subprocesses), int(time.time() * 1000) % 100000))
                owned = True
        else:
            child_env = dict(os.environ if env is None else env)
        root = os.path.realpath(os.path.abspath(child_root or self.repo))
        self._in_hook = True
        try:
            with _internal():
                result = run_observed(
                    argv, executable=os.path.realpath(argv[0]),
                    expect_executable_sha256=sha256_file(os.path.realpath(argv[0])),
                    cwd=cwd, root=root, expected_inputs=declared, sidecar_path=sidecar,
                    env=child_env, timeout=timeout,
                    declared_outputs=[os.path.realpath(os.path.abspath(p)) for p in outputs])
        finally:
            self._in_hook = False
        with _internal():
            self.adopt_child_record(result.record)
            if owned and sidecar and os.path.isfile(sidecar):
                try:
                    os.remove(sidecar)
                except OSError:                     # pragma: no cover
                    pass
        return result

    # ---- the shared parent-observed entry ----
    def _entry_from_observer(self, obs, env_keys=None):
        return {
            "argv_key": "cmd:%s" % obs.identity, "argv": list(obs.argv),
            "command_identity": obs.identity, "command_display": obs.display,
            "cwd": obs.cwd, "root": obs.root,
            "executable": obs.executable, "executable_sha256": obs.executable_sha256,
            "env_keys": sorted(env_keys or []),
            "nonce": obs.nonce, "sidecar_path": obs.sidecar_path,
            "declared_inputs": dict(obs.declared_inputs), "inputs_after": {},
            "declared_outputs": {},
            "process_started": False, "process_returned": False,
            "started_utc": None, "returned_utc": None,
            "pid": None, "exit": None, "timed_out": None,
            "process_proof_ok": False, "execution_proof_ok": False,
            "stdout_bytes": None, "stderr_bytes": None,
            "stdout_sha256": None, "stderr_sha256": None,
            "sidecar_sha256": None, "sidecar_failures": [], "sidecar_path_classes": [],
            "child_provenance": None, "child_closure": CHILD_NOT_OBSERVED,
        }

    def _register_started_observation(self, *, token, argv, identity, display, cwd, root,
                                      executable, executable_sha256, env_keys, env_policy,
                                      nonce, sidecar_path, declared_inputs, started_utc, pid):
        """Ledger a real Popen result before communicate/finalization can fail.

        This deliberately cannot become CHILD_OBSERVED.  A successful finalization replaces it
        with the pending capability entry; any exceptional path converts it to an aborted entry.
        """
        if any(d.get("record_token") == token for d in self.declared_subprocesses):
            raise RuntimeError("the same run_observed token was registered twice")
        entry = {
            "argv_key": "cmd:%s" % identity, "argv": list(argv),
            "command_identity": identity, "command_display": display,
            "cwd": cwd, "root": root,
            "executable": executable, "executable_sha256": executable_sha256,
            "env_keys": sorted(env_keys or []), "env_policy": copy.deepcopy(env_policy),
            "nonce": nonce, "sidecar_path": sidecar_path,
            "declared_inputs": dict(declared_inputs), "inputs_after": {},
            "declared_outputs": {},
            "process_started": True, "process_returned": False,
            "started_utc": started_utc, "returned_utc": None,
            "pid": pid, "exit": None, "timed_out": None,
            "process_proof_ok": False, "execution_proof_ok": False,
            "stdout_bytes": None, "stderr_bytes": None,
            "stdout_sha256": None, "stderr_sha256": None,
            "sidecar_sha256": None,
            "sidecar_failures": ["run_observed has not completed record finalization"],
            "sidecar_path_classes": [], "child_provenance": None,
            "child_closure": CHILD_NOT_OBSERVED,
            "owner": "the operation that created the child", "record_token": token,
            "observation_pending": True, "observation_aborted": False,
            "adoption_pending": False,
        }
        self.declared_subprocesses.append(entry)
        return entry

    def _mark_observation_aborted(self, token, process, failure, timed_out=False):
        """Permanently fail closed after Popen succeeded but finalization did not."""
        matches = [d for d in self.declared_subprocesses if d.get("record_token") == token]
        if len(matches) != 1:                         # pragma: no cover - internal invariant
            raise RuntimeError("aborted run_observed token has no unique started ledger entry")
        entry = matches[0]
        entry.update({
            "process_returned": process.returncode is not None,
            "returned_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "exit": process.returncode,
            "timed_out": bool(timed_out),
            "process_proof_ok": False,
            "execution_proof_ok": False,
            "observation_pending": False,
            "observation_aborted": True,
            "observation_failure": failure,
            "sidecar_failures": ["run_observed failed after its real Popen returned: %s"
                                 % failure],
        })
        return entry

    def _absorb(self, entry, obs):
        """Copy the OBSERVER's measurements into the report entry."""
        rec = obs.record or {}
        for k in ("process_started", "process_returned", "started_utc", "returned_utc", "pid",
                  "exit", "timed_out", "process_proof_ok", "execution_proof_ok",
                  "stdout_bytes", "stderr_bytes", "stdout_sha256", "stderr_sha256",
                  "inputs_after", "declared_outputs", "env_policy", "output_encoding",
                  "sidecar_sha256", "sidecar_failures", "sidecar_path_classes"):
            if k in rec:
                entry[k] = rec[k]
        drift = [rel for rel, v in entry["declared_inputs"].items()
                 if entry["inputs_after"].get(rel) != v]
        if drift:
            entry["input_drift"] = drift
        return entry

    def _read_and_validate_sidecar(self, entry, obs):
        """Consume the document snapshot run_observed authenticated; never reopen its path."""
        side, doc = obs.sidecar_path, copy.deepcopy(obs.sidecar_document)
        fails = list(obs.sidecar_failures)
        if not fails and doc is not None:
            fails = self._validate_sidecar(entry, doc, side)
        entry["sidecar_failures"] = fails
        if not fails:
            entry["child_provenance"] = doc
            entry["child_closure"] = CHILD_OBSERVED
        elif doc is not None:
            entry["unvalidated_sidecar"] = doc
        return entry

    def _validate_sidecar(self, entry, doc, sidecar_path):
        """This recorder's view of sidecar_failures(), with its own single-use registries."""
        return sidecar_failures(entry, doc, sidecar_path, self.used_nonces, self.used_sidecars)

    def _register_pending_observation(self, obs):
        """Account for a real completed child before its capability is explicitly adopted.

        `run_observed` calls this for every recorder active at the launch boundary.  It is a
        fail-closed ledger entry, not an adoption: the frozen process facts are visible, while
        CHILD_NOT_OBSERVED and `adoption_pending` keep closure red if the caller discards the
        returned record.
        """
        prior = [i for i, d in enumerate(self.declared_subprocesses)
                 if d.get("record_token") == obs.token]
        if len(prior) > 1:                           # pragma: no cover - internal invariant
            raise RuntimeError("the same run_observed token has multiple ledger entries")
        if prior and not self.declared_subprocesses[prior[0]].get("observation_pending"):
            raise RuntimeError("the same run_observed token was registered twice")
        entry = self._entry_from_observer(obs, env_keys=obs.record.get("env_keys"))
        entry["owner"] = "the operation that created the child"
        entry["record_token"] = obs.token
        entry["observation_pending"] = False
        entry["observation_aborted"] = False
        entry["adoption_pending"] = True
        self._absorb(entry, obs)
        # Preserve the process owner's frozen failure snapshot, but do not authenticate the
        # sidecar into CHILD_OBSERVED until the exact capability is consumed.
        entry["sidecar_failures"] = list(obs.sidecar_failures)
        if prior:
            self.declared_subprocesses[prior[0]] = entry
        else:
            self.declared_subprocesses.append(entry)
        return entry

    def adopt_child_record(self, record):
        """Adopt a child record produced by the operation that OWNED the child.

        Only run_observed registers a record, after its own real Popen returned and its frozen
        sidecar was validated. The exact object and exact bytes must remain unchanged. One
        capability is consumed globally; on that single adoption it is also attached to every
        recorder that was already active at the real launch boundary."""
        if not isinstance(record, dict) or record.get("schema") != CHILD_RECORD_SCHEMA:
            raise ValueError("a child record must carry schema %r" % CHILD_RECORD_SCHEMA)
        token = record.get("record_token")
        with _RECORDER_STATE_LOCK:
            obs = _ADOPTABLE.get(token) if isinstance(token, str) else None
            if obs is None:
                raise ValueError(
                    "this child record was not produced by run_observed's real Popen in this "
                    "process. A caller-manufactured dictionary carrying %r is a claim, not an "
                    "observation (R6-1)" % CHILD_RECORD_SCHEMA)
            if obs.adopted:
                raise ValueError("this real child record has already been adopted; its capability "
                                 "is globally single-use")
            if not any(r is self for r in obs.eligible_recorders):
                raise ValueError("this recorder was not active when the real child was launched; "
                                 "a recorder begun later cannot adopt history from before its "
                                 "observation window")
            if not self._active or self.end is not None:
                raise ValueError("the child record must be adopted while its launch-eligible "
                                 "recorder is still active")
            if obs.record is not record:
                raise ValueError("the child record is a copy or a rebuild, not the exact object "
                                 "the process-owning operation produced")
            if _record_digest(record) != obs.record_sha256:
                raise ValueError("the process-owning operation's child record was modified after "
                                 "it was finalized")
            fails = validate_child_record(record)
            if fails:
                raise ValueError("the child record failed validation: %s" % fails)
            with _internal():
                obs.adopted = True
                returned = None
                for recorder in obs.eligible_recorders:
                    pending = [i for i, d in enumerate(recorder.declared_subprocesses)
                               if d.get("record_token") == obs.token]
                    if len(pending) != 1:             # pragma: no cover - internal invariant
                        raise RuntimeError("the run_observed token has no unique pending entry")
                    if not recorder._active or recorder.end is not None:
                        old = recorder.declared_subprocesses[pending[0]]
                        old["post_finish_adoption_refused"] = True
                        old.setdefault("sidecar_failures", []).append(
                            "adoption was attempted after this recorder's observation window")
                        recorder.finish_boundary_failures.append(
                            "a child capability was presented after the observation window "
                            "closed; it was not adopted")
                        continue
                    key = "cmd:%s" % obs.identity
                    recorder.undeclared_subprocesses = [
                        d for d in recorder.undeclared_subprocesses if d["argv_key"] != key]
                    entry = recorder._entry_from_observer(obs, env_keys=record.get("env_keys"))
                    entry["owner"] = "the operation that created the child"
                    entry["record_token"] = obs.token
                    entry["observation_pending"] = False
                    entry["observation_aborted"] = False
                    entry["adoption_pending"] = False
                    recorder._absorb(entry, obs)
                    recorder._read_and_validate_sidecar(entry, obs)
                    if entry["child_closure"] == CHILD_NOT_OBSERVED and not obs.sidecar_path \
                            and record.get("process_proof_ok"):
                        entry["child_closure"] = CHILD_PROOF_ONLY
                    recorder.declared_subprocesses[pending[0]] = entry
                    if recorder is self:
                        returned = entry
                return returned

    def note_diagnostic_child(self, argv, reason):
        """Record that this run DELIBERATELY started a child whose provenance is invalid.

        This is disclosure only. It never changes child_closure and never exempts any failure
        from the completeness or provenance decisions."""
        if not isinstance(reason, str) or not reason.strip():
            raise ValueError("a diagnostic negative control must carry a reason")
        key = argv_key(argv)
        for d in self.declared_subprocesses:
            if d["argv_key"] != key:
                continue
            if not d.get("process_started") or not d.get("process_returned"):
                raise ValueError(
                    "only a child this recorder OBSERVED starting and returning may be marked a "
                    "diagnostic negative control; this one was never observed, so marking it "
                    "would hide it rather than disclose it")
            d["diagnostic_reason"] = reason.strip()
            return d
        raise ValueError("no declared child matches %r" % (argv_display(argv),))

    def diagnostic_children(self):
        return [{"command_display": d.get("command_display") or d["argv_key"],
                 "reason": d.get("diagnostic_reason"),
                 "sidecar_failures": list(d.get("sidecar_failures") or []),
                 "child_closure": d.get("child_closure"),
                 "grandchildren": copy.deepcopy((d.get("child_provenance") or {}).get(
                     "grandchildren") or []),
                 "exit": d.get("exit")}
                for d in self.declared_subprocesses
                if d.get("diagnostic_reason")]

    def attach_child_provenance(self, argv, sidecar_path):
        """Attach a sidecar to a declared child.

        R5-7: a declaration plus a caller-written file is not evidence a process ran. The sidecar
        becomes an OBSERVATION only if this recorder's own subprocess.Popen interception watched
        that command start and return; otherwise the child is UNBOUND and the closure stays
        incomplete. Use run_observed()/adopt_child_record() -- or run_declared() -- when the
        recorder does not intercept the launch."""
        key = argv_key(argv)
        with _internal():
            for d in self.declared_subprocesses:
                if d["argv_key"] == key:
                    d["sidecar_path"] = sidecar_path
                    if not os.path.isfile(sidecar_path):
                        d["sidecar_failures"] = ["no sidecar was written at %r" % sidecar_path]
                        return d
                    try:
                        with _io.FileIO(sidecar_path, "r") as stream:
                            doc = _strict_json_bytes(stream.read())
                    except Exception as e:
                        d["sidecar_failures"] = ["unreadable sidecar: %s: %s"
                                                 % (type(e).__name__, e)]
                        return d
                    fails = self._validate_sidecar(d, doc, sidecar_path)
                    d["sidecar_failures"] = fails
                    if not fails:
                        d["child_provenance"] = doc
                        d["child_closure"] = CHILD_OBSERVED
                    else:
                        d["unvalidated_sidecar"] = doc
                        d["child_closure"] = (CHILD_UNBOUND if not d.get("process_started")
                                              else CHILD_NOT_OBSERVED)
                    return d
        return None

    def declare_subprocess(self, argv, inputs=(), nonce=None, cwd=None):
        """DIAGNOSTIC. Declare a child WITHOUT observing it.

        The entry carries process_started=False for ever: nothing attached to it can become an
        observation. It exists so a caller can name a child it intends to run plainly, and so
        the report says honestly that the child was never observed."""
        argv = [str(a) for a in argv]
        entry = {"argv_key": argv_key(argv), "argv": argv,
                 "command_identity": command_identity(argv),
                 "command_display": argv_display(argv),
                 "declared_inputs": {}, "inputs_after": {},
                 "nonce": nonce or secrets.token_hex(16),
                 "cwd": os.path.abspath(cwd) if cwd else None, "root": None,
                 "executable": None, "executable_sha256": None,
                 "process_started": False, "process_returned": False,
                 "pid": None, "exit": None, "child_provenance": None,
                 "child_closure": CHILD_NOT_OBSERVED}
        with _internal():
            for q in list(inputs):
                ap = os.path.abspath(q)
                if self._project_local(ap):
                    rel = os.path.relpath(ap, self.repo).replace(os.sep, "/")
                    entry["declared_inputs"][rel] = sha256_file(ap)
        self.declared_subprocesses.append(entry)
        return entry

    def pin_test_inventory(self, ids, expected_check_count, meta_check_count=0):
        """Pin the expected test IDs and the exact check arithmetic.

        `expected_check_count` is the FUNCTIONAL total; `meta_check_count` counts the checks the
        suite makes about its own inventory. Declaring the split is what stops the two totals
        drifting by one while each looks correct on its own."""
        ids = list(ids)
        self.test_inventory = {
            "expected_ids": ids,
            "expected_test_count": len(ids),
            "functional_check_count": int(expected_check_count),
            "meta_check_count": int(meta_check_count),
            "expected_total_checks": int(expected_check_count) + int(meta_check_count),
            "expected_digest": hashlib.sha256("\n".join(ids).encode("utf-8")).hexdigest(),
            "split_note": ("functional checks come from the test functions; meta checks are the "
                           "suite's checks about its own inventory. functional + meta == total, "
                           "and all three are compared"),
        }
        return self.test_inventory

    # ---- report ----
    def dependency_report(self, tested_commit=None):
      with _internal():
        closure = {}
        paths = {os.path.relpath(f, self.repo).replace(os.sep, "/"): name
                 for name, f in self.observer.local_modules().items()}
        for rel in self.executed:
            paths.setdefault(rel, "<executed>")
        for rel, name in sorted(paths.items()):
            f = os.path.join(self.repo, rel.replace("/", os.sep))
            entry = {"module": name, "path": rel, "sha256": sha256_file(f),
                     "exists": os.path.exists(f)}
            led = self.executed.get(rel)
            if led:
                entry["sha256_at_execution"] = led["sha256_at_execution"]
                entry["stable_since_execution"] = (led["sha256_at_execution"] == entry["sha256"])
            if tested_commit:
                raw = subprocess.run(["git", "-C", self.repo, "show",
                                      "%s:%s" % (tested_commit, rel)],
                                     capture_output=True)
                if raw.returncode != 0:
                    entry["matches_tested_commit"] = False
                    entry["note"] = "not present at the tested commit"
                else:
                    entry["matches_tested_commit"] = (
                        hashlib.sha256(raw.stdout).hexdigest() == entry["sha256"])
            closure[rel] = entry
        return dict(sorted(closure.items()))

    def undeclared_imports(self, declared_source_map):
        declared = set(declared_source_map or ())
        imported = {os.path.relpath(f, self.repo).replace(os.sep, "/")
                    for f in self.observer.local_modules().values()}
        return sorted(imported - declared)

    def _state_changes(self):
        out = []
        s, e = self.start, self.end
        if s["head"] != e["head"]:
            out.append("HEAD moved during the run: %s -> %s" % (s["head"], e["head"]))
        if s["dirty_paths"] != e["dirty_paths"]:
            out.append("the set of dirty paths changed")
        for rel, fp in e["dirty_fingerprints"].items():
            if rel in s["dirty_fingerprints"] and s["dirty_fingerprints"][rel] != fp:
                out.append("content of %r changed during the run (same status line)" % rel)
        if s["bytecode_cache"] != e["bytecode_cache"]:
            added = sorted(set(e["bytecode_cache"]) - set(s["bytecode_cache"]))
            removed = sorted(set(s["bytecode_cache"]) - set(e["bytecode_cache"]))
            changed = sorted(k for k in set(s["bytecode_cache"]) & set(e["bytecode_cache"])
                             if s["bytecode_cache"][k] != e["bytecode_cache"][k])
            out.append("bytecode cache changed: added=%s removed=%s changed=%s"
                       % (added[:4], removed[:4], changed[:4]))
        return out

    def child_inputs(self, closure=None):
        """(undeclared_child_reads, child_code_outside_tested_commit, child_metadata).

        R5-8 and R5-9: a genuine child read a project document nobody declared, and another
        chose between project files with iterdir/stat alone, and both reports stayed complete
        and green because nothing ever COMPARED the child's channels with anything."""
        undeclared, outside, meta = {}, {}, {}
        closure = closure or {}
        for d in self.declared_subprocesses:
            cp = d.get("child_provenance") or {}
            if not cp:
                continue
            tag = d["argv_key"][:24]
            declared = set()
            for named in (d.get("declared_inputs") or {}):
                if isinstance(named, str) and os.path.isabs(named) \
                        and self._project_local(os.path.realpath(named)):
                    declared.add(os.path.relpath(os.path.realpath(named), self.repo).replace(
                        os.sep, "/"))
                else:
                    declared.add(named)
            root = d.get("root")
            for item in (cp.get("reads") or []):
                raw = item.get("path")
                if not isinstance(raw, str) or not os.path.isabs(raw):
                    continue                    # strict sidecar validation already rejected it
                ap = os.path.realpath(raw)
                if not self._project_local(ap):
                    continue
                rel = os.path.relpath(ap, self.repo).replace(os.sep, "/")
                if rel in declared or rel in self.registered:
                    continue
                if root and os.path.normcase(os.path.realpath(ap)).startswith(
                        os.path.normcase(os.path.realpath(root)) + os.sep):
                    pass                            # inside the declared root, still undeclared
                undeclared.setdefault(rel, []).append(
                    {"child": tag, "how": item.get("how"), "sha256": item.get("sha256")})
            for item in (cp.get("code_reads") or []):
                raw = item.get("path")
                if not isinstance(raw, str) or not os.path.isabs(raw):
                    continue
                ap = os.path.realpath(raw)
                if not self._project_local(ap):
                    continue
                rel = os.path.relpath(ap, self.repo).replace(os.sep, "/")
                led = closure.get(rel)
                if led is None:
                    outside.setdefault(rel, []).append(
                        {"child": tag, "why": "executed by a child but absent from the "
                                              "tested-commit source closure"})
                elif led.get("matches_tested_commit") is False:
                    outside.setdefault(rel, []).append(
                        {"child": tag, "why": "executed by a child and differs from the tested "
                                              "commit"})
            for item in (cp.get("metadata") or []):
                raw = item.get("path")
                if not isinstance(raw, str) or not os.path.isabs(raw):
                    continue
                ap = os.path.realpath(raw)
                if not self._project_local(ap):
                    continue
                rel = os.path.relpath(ap, self.repo).replace(os.sep, "/")
                meta.setdefault(rel, []).append(dict(item, child=tag))
        return undeclared, outside, meta

    def _closure_completeness(self, closure=None):
        """(complete, reasons). A class that could not be observed is never reported as clean."""
        reasons = list(self.finish_boundary_failures)
        for d in self.declared_subprocesses:
            if d.get("observation_pending"):
                reasons.append("subprocess %r started under observation, but run_observed did "
                               "not finish record finalization" % d["argv_key"][:80])
            if d.get("observation_aborted"):
                reasons.append("subprocess %r started under observation, but run_observed "
                               "aborted: %s" % (d["argv_key"][:80],
                                                d.get("observation_failure")))
            if d.get("adoption_pending"):
                reasons.append("subprocess %r completed under observation, but its returned "
                               "capability was never adopted" % d["argv_key"][:80])
            if d.get("sidecar_failures"):
                reasons.append("subprocess %r returned a sidecar that failed validation: %s"
                               % (d["argv_key"][:60], d["sidecar_failures"][:3]))
            if d.get("child_closure") not in (CHILD_OBSERVED,):
                reasons.append("subprocess %r is not an observed child: %s"
                               % (d["argv_key"][:80], d.get("child_closure")))
            if d.get("input_drift"):
                reasons.append("subprocess %r: declared input(s) %s changed while it ran"
                               % (d["argv_key"][:60], d["input_drift"]))
            cp = d.get("child_provenance") or {}
            for g in (cp.get("grandchildren") or []):
                gav = g.get("argv") if isinstance(g, dict) else g
                reasons.append("subprocess %r started an unobserved grandchild %s"
                               % (d["argv_key"][:60], " ".join(gav or [])[:80]))
            for field in ("reads", "code_reads"):
                for item in (cp.get(field) or []):
                    raw = item.get("path")
                    if not isinstance(raw, str) or not os.path.isabs(raw):
                        reasons.append("child %s returned a non-absolute %s path %r"
                                       % (d["argv_key"][:24], field, raw))
                        continue
                    ap = os.path.realpath(raw)
                    if not self._project_local(ap):
                        continue
                    rel = os.path.relpath(ap, self.repo).replace(os.sep, "/")
                    now = sha256_file(os.path.join(self.repo, rel.replace("/", os.sep)))
                    was = item.get("sha256")
                    if was != now:
                        reasons.append("child %s read %r as %s; it is %s now"
                                       % (d["argv_key"][:24], rel, str(was)[:12], str(now)[:12]))
        for rel, led in sorted(self.executed.items()):
            now = sha256_file(os.path.join(self.repo, rel.replace("/", os.sep)))
            if now != led["sha256_at_execution"]:
                reasons.append("executed source %r changed after it ran (%s -> %s)"
                               % (rel, str(led["sha256_at_execution"])[:12], str(now)[:12]))
        for p in self.path_problems:
            reasons.append("path identity: %s" % p["problem"])
        return (not reasons), reasons

    def report(self, suite, argv, tested_commit=None, live=False, extra=None,
               canonical=True, actual_test_ids=None, actual_check_count=None,
               allow_invalid_diagnostic=False):
        """Build a provenance document, raising on problems in strict mode by default.

        `allow_invalid_diagnostic=True` is a narrow evidence-preservation mode: it is accepted
        only for a noncanonical report, never removes a problem, and merely returns the truthful
        `provenance_ok=false` document instead of raising.  It cannot turn a failed closure green.
        """
        if allow_invalid_diagnostic and canonical:
            raise ValueError("allow_invalid_diagnostic is valid only for canonical=False")
        if self.start is None or self.end is None:
            raise RuntimeError("begin() and finish() must both have run before report()")
        closure = self.dependency_report(tested_commit)
        unmatched = sorted(k for k, v in closure.items()
                           if v.get("matches_tested_commit") is False)
        changes = self._state_changes()
        undeclared_child, child_code_outside, child_meta = self.child_inputs(closure)
        complete, incomplete_reasons = self._closure_completeness(closure)
        problems = []

        if canonical:
            if not self.start["git_available"] or not self.end["git_available"]:
                problems.append("git state was unavailable at one or both observations")
            resolved = _git(self.repo, "rev-parse", "--verify",
                            "%s^{commit}" % tested_commit) if tested_commit else None
            if not tested_commit:
                problems.append("a canonical report must name a tested_commit")
            elif resolved is None:
                problems.append("tested_commit %r does not resolve in this repository"
                                % tested_commit)
            elif not (resolved == self.start["head"] == self.end["head"]):
                problems.append("tested_commit %s must equal the start HEAD (%s) and the end "
                                "HEAD (%s)" % (str(resolved)[:12], str(self.start["head"])[:12],
                                               str(self.end["head"])[:12]))
            if self.start["dirty_count"] or self.end["dirty_count"]:
                problems.append("a canonical report requires a clean tree at both ends "
                                "(start=%d end=%d dirty paths)"
                                % (self.start["dirty_count"], self.end["dirty_count"]))
        if unmatched:
            problems.append("modules differing from, or absent at, the tested commit: %s"
                            % unmatched)
        if self.undeclared:
            problems.append("undeclared project-local reads: %s" % sorted(self.undeclared))
        if undeclared_child:
            problems.append("undeclared project-local reads by a CHILD: %s"
                            % sorted(undeclared_child))
        if child_code_outside:
            problems.append("child-executed source absent from, or differing from, the tested "
                            "commit: %s" % sorted(child_code_outside))
        if self.undeclared_subprocesses:
            problems.append("undeclared subprocesses: %s"
                            % [d["argv_key"][:80] for d in self.undeclared_subprocesses])
        if changes:
            problems.append("state changed during the run: %s" % changes)
        if not complete and (canonical or self.strict or allow_invalid_diagnostic):
            problems.append("the API-observed source closure is INCOMPLETE, so provenance cannot "
                            "be claimed: %s" % incomplete_reasons[:6])

        # ---- the pinned inventory is enforced HERE, not by the suite that reports to it ----
        ti = self.test_inventory
        if ti is None:
            if canonical:
                problems.append("a canonical report must pin its test inventory")
        else:
            if actual_test_ids is None:
                problems.append("a pinned test inventory requires the EXACT actual test-id set; "
                                "expected_count on its own compares against nothing")
            else:
                got = list(actual_test_ids)
                if got != ti["expected_ids"]:
                    miss = sorted(set(ti["expected_ids"]) - set(got))
                    new = sorted(set(got) - set(ti["expected_ids"]))
                    problems.append("the test inventory does not match the pin: missing=%s "
                                    "unexpected=%s order_changed=%s"
                                    % (miss[:6], new[:6],
                                       sorted(got) == sorted(ti["expected_ids"])))
                if len(got) != ti["expected_test_count"]:
                    problems.append("the pin declares %d tests but %d ran"
                                    % (ti["expected_test_count"], len(got)))
            if actual_check_count is None:
                problems.append("a pinned test inventory requires the EXACT actual check count")
            elif actual_check_count != ti["expected_total_checks"]:
                problems.append("the pin declares %d checks (%d functional + %d meta) but %d were "
                                "recorded" % (ti["expected_total_checks"],
                                              ti["functional_check_count"],
                                              ti["meta_check_count"], actual_check_count))

        doc = {
            "schema": SCHEMA,
            "suite": suite,
            "non_evidence": True,
            "live": bool(live),
            "canonical": bool(canonical),
            "invalid_diagnostic_return": bool(allow_invalid_diagnostic),
            "finish_boundary_clean": not self.finish_boundary_failures,
            "finish_boundary_failures": list(self.finish_boundary_failures),
            "tested_commit": tested_commit,
            "command": " ".join([os.path.basename(sys.executable)] + [str(a) for a in argv]),
            "interpreter": {"version": sys.version.split()[0], "executable": sys.executable,
                            "dont_write_bytecode": bool(sys.dont_write_bytecode),
                            "pycache_prefix": sys.pycache_prefix,
                            "flags_no_user_site": bool(getattr(sys.flags, "no_user_site", 0)),
                            "PYTHONDONTWRITEBYTECODE":
                                os.environ.get("PYTHONDONTWRITEBYTECODE"),
                            "PYTHONPYCACHEPREFIX": os.environ.get("PYTHONPYCACHEPREFIX"),
                            "PYTHONNOUSERSITE": os.environ.get("PYTHONNOUSERSITE")},
            "observed_at_start": self.start,
            "observed_at_end": self.end,
            "state_changes": changes,
            "state_changed_during_run": bool(changes),
            "import_closure": closure,
            "import_closure_unmatched_at_tested_commit": unmatched,
            "executed_source_ledger": dict(sorted(self.executed.items())),
            "observation_model": OBSERVATION_MODEL,
            "api_observed_closure_complete": bool(complete),
            "closure_incomplete_reasons": incomplete_reasons,
            "path_identity_problems": list(self.path_problems),
            "metadata_observations": dict(sorted(self.metadata.items())),
            "child_metadata_observations": dict(sorted(child_meta.items())),
            "diagnostic_children": self.diagnostic_children(),
            "undeclared_child_local_reads": dict(sorted(undeclared_child.items())),
            "child_code_reads_outside_tested_commit": dict(sorted(child_code_outside.items())),
            "registered_reads": dict(sorted(self.registered.items())),
            "code_self_reads": dict(sorted(self.code_self_reads.items())),
            "undeclared_local_reads": dict(sorted(self.undeclared.items())),
            "declared_subprocesses": list(self.declared_subprocesses),
            "undeclared_subprocesses": list(self.undeclared_subprocesses),
            "test_inventory": self.test_inventory,
            "actual_test_ids": list(actual_test_ids) if actual_test_ids is not None else None,
            "actual_check_count": actual_check_count,
            "observation_boundaries": {
                "model": OBSERVATION_MODEL,
                "what_this_is_not": ("this is API observation inside one Python process. It is "
                                     "NOT an operating-system tracer, and arbitrary same-process "
                                     "Python can bypass any of it. The claim is bounded to the "
                                     "APIs listed here"),
                "observed": ["project-local DATA reads through builtins.open, io.open, _io.open, "
                             "os.open (readable unless O_WRONLY) and pathlib -- no suffix is "
                             "exempt",
                             "decision-relevant METADATA on project-local paths: os.listdir, "
                             "os.scandir, pathlib.Path.iterdir and pathlib.Path.stat, recorded "
                             "with a stable entry/type/size identity",
                             "project-local SOURCE fetched through _io.open_code, which covers "
                             "imports, runpy.run_path and explicit file loaders",
                             "an APPEND-ONLY executed-source ledger that module eviction cannot "
                             "erase, re-hashed at the end of the run",
                             "subprocess creation through subprocess.Popen; a declared child's "
                             "executable bytes, argv, cwd, environment keys, inputs before and "
                             "after, exit and output sizes",
                             "a declared child's OWN reads, code reads, decision METADATA "
                             "(os.listdir, os.scandir, pathlib.Path.iterdir, "
                             "pathlib.Path.stat) and grandchildren, when it runs "
                             "CHILD_SHIM_SOURCE and returns a validated sidecar; a child "
                             "project-local read that nobody declared, and child-executed "
                             "source that is not the tested commit, each fail a canonical "
                             "report",
                             "git HEAD, dirty-path content fingerprints and bytecode cache"],
                "NOT observed": ["reads through mmap after the file object closes",
                                 "reads made inside native extension code",
                                 "the internals of a child whose sidecar is absent or fails "
                                 "validation; a child bound only by an execution proof is "
                                 "labelled parent-bound, never observed",
                                 "os.stat and os.path.getsize called directly rather than "
                                 "through pathlib -- OUTSIDE the boundary and not claimed",
                                 "non-Python readers invoked by shell tools"],
                "consequence": "an unobservable class sets closure_complete=false with a reason "
                               "and fails the canonical gate; it is never reported as clean",
            },
            "retained_local_evidence": {
                "meaning": "what this machine still holds",
                "does_not_prove": ("that no other run happened elsewhere, and that no run was "
                                   "discarded before this observation. A local inventory cannot "
                                   "establish a negative about the wider filesystem or another "
                                   "machine."),
            },
            "limitations": [
                "observed_at_start is a genuine start observation; observed_at_end is reported "
                "separately so drift is visible rather than assumed absent",
                "PYTHONDONTWRITEBYTECODE and -B stop bytecode being WRITTEN and do not prove a "
                "pre-existing valid cache was not READ",
                "read interception covers the Python file API only; see observation_boundaries",
                "a child's provenance is self-reported by the shim running inside it: it is an "
                "observation made by that process, not an external one",
            ],
            "utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        if extra:
            clashes = sorted(set(extra) & RESERVED_REPORT_KEYS)
            conflicts = [k for k in clashes if extra.get(k) != doc.get(k)]
            if conflicts:
                raise ValueError("extra may not overwrite reserved report key(s) with different "
                                 "values: %s" % conflicts)
            doc.update({k: v for k, v in extra.items() if k not in RESERVED_REPORT_KEYS})
        doc["provenance_problems"] = problems
        doc["provenance_ok"] = not problems
        if problems and self.strict and not allow_invalid_diagnostic:
            raise UndeclaredReadError("; ".join(problems))
        return doc


# ------------------------------------------------------------------ source-only staging
def _wrap_internal(fn):
    """Mark a provenance helper as tooling, so its own file and process activity is not attributed
    to the code under test."""
    def inner(*a, **kw):
        with _internal():
            return fn(*a, **kw)
    inner.__name__ = fn.__name__
    inner.__doc__ = fn.__doc__
    return inner


@_wrap_internal
def stage_source_only(repo, commit, dest, paths=("node", "docs")):
    """Materialise a SOURCE-ONLY tree at `dest` from `commit`, and prove it equals the archive."""
    dest = os.path.abspath(dest)
    if os.path.exists(dest):
        if not os.path.isdir(dest) or os.listdir(dest):
            raise RuntimeError("staging destination %r must not exist or must be exactly empty"
                               % dest)
    else:
        os.makedirs(dest)
    r = subprocess.run(["git", "-C", repo, "archive", "--format=tar", commit] + list(paths),
                       capture_output=True)
    if r.returncode != 0:
        raise RuntimeError("git archive failed: %s" % r.stderr.decode("utf-8", "replace")[:300])
    import tarfile
    expected = {}
    with tarfile.open(fileobj=_io_mod.BytesIO(r.stdout)) as tf:
        for m in tf.getmembers():
            if m.name.startswith("/") or ".." in m.name.split("/"):
                raise RuntimeError("unsafe archive member %r" % m.name)
            if m.isreg():
                expected[m.name] = m.size
        tf.extractall(dest, filter="data")
    actual = {}
    for dirpath, _d, files in os.walk(dest):
        for fn in files:
            full = os.path.join(dirpath, fn)
            actual[os.path.relpath(full, dest).replace(os.sep, "/")] = os.path.getsize(full)
    if set(actual) != set(expected):
        raise RuntimeError("the staged tree does not equal the git archive inventory: "
                           "extra=%s missing=%s"
                           % (sorted(set(actual) - set(expected))[:5],
                              sorted(set(expected) - set(actual))[:5]))
    strays = [k for k in actual if k.endswith(".pyc") or "__pycache__" in k]
    if strays:
        raise RuntimeError("staging tree is not source-only: %s" % strays[:5])
    return dest


def sterile_child_env(pycache_dir, home_dir=None, extra=None):
    keep = ("PATH", "SYSTEMROOT", "LANG", "LC_ALL", "TMPDIR", "TEMP", "TMP", "WSLENV")
    e = {k: v for k, v in os.environ.items() if k in keep}
    e["PYTHONDONTWRITEBYTECODE"] = "1"
    e["PYTHONPYCACHEPREFIX"] = pycache_dir
    e["PYTHONNOUSERSITE"] = "1"
    e["PYTHONPATH"] = ""
    if home_dir:
        e["HOME"] = home_dir
        e["USERPROFILE"] = home_dir
    if extra:
        e.update(extra)
    return e
