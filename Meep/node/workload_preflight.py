#!/usr/bin/env python3
"""Fail-closed competing-workload preflight. READ-ONLY. It terminates nothing, ever.

PROSPECTIVE INFRASTRUCTURE. NON-EVIDENCE.

CADENCEQ v1 was launched with p2pool running -- PID 42976, present in all 549 environment-trace
rows from lead-in through lead-out. The controlling authorisation said not to launch while a
user's own miner was running and to ask the user to close it. No such gate existed anywhere in
the harness. This module is that missing gate.

FAIL CLOSED, NOT FAIL QUIET. Every way of not knowing is a refusal:

  * an inventory source that errors, times out or is unavailable   -> refuse
  * a process whose executable path cannot be resolved but whose
    name matches a denied entry                                    -> refuse as AMBIGUOUS
  * a denied process at EITHER the lead-in check or the immediately
    -before-launch check                                           -> refuse

An empty inventory is not evidence of an idle machine; it is evidence that nothing was seen, and
the source must say why it saw nothing.

WHAT THE THIRD CORRECTIVE AUDIT REPRODUCED (R3-8)

    wsl_inventory() ran `bash -lc '<read /proc>'`. On Windows `bash` on PATH is very often
    Git-for-Windows or MSYS bash, which has no /proc/<pid>/exe at all; a synthetic runner
    returning Git-Bash-shaped rows produced an Inventory labelled "wsl:/proc" with status
    "available", and the preflight ALLOWED the stage. No distribution was ever named, none was
    enumerated, and the module-level constant WSL_ROUTING_UNKNOWN -- which describes exactly this
    hole -- was defined and never referenced. A constant in the source is not enforcement.

WHAT NOW HOLDS ON WINDOWS

    Native Windows and WSL inventories are BOTH mandatory and neither can substitute for the
    other. The WSL side enumerates distributions read-only with `wsl.exe --list --verbose`, takes
    the ones whose STATE is Running, and queries EACH ONE explicitly by identity with
    `wsl.exe -d <name> --exec ...`. Every enumerated distribution and every per-distribution
    result is recorded. Enumeration that errors, cannot be parsed, or reports a state this module
    does not recognise is a refusal. A stopped distribution is never queried, because querying it
    would START it.

    Generic `bash -lc` is available as a SEPARATE source called "shell:bash". It is recorded, it
    is checked for denied workloads like any other inventory, and it can never satisfy the `wsl`
    requirement. Git/MSYS/Cygwin bash is detected and labelled.

MATCHING IS EXACT, NOT SUBSTRING. Names are normalised (basename, case-folded, one trailing
executable suffix removed) and compared for EQUALITY.

WHAT THAT DOES NOT PROVE. Basename normalisation is a NAME test, not an identity test. It cannot
tell that `innocent.exe` living in a directory called `p2pool` is or is not a miner. Establishing
identity would need content hashing against a known-binary list, or code signing, and neither
exists here.

WHAT IS NOT A BLOCKER. Windows AI / NPU workloads are recorded as covariates. They are never an
automatic blocker and never an outcome filter.

THIS MODULE HAS NO TERMINATION PATH. There is no kill, terminate, taskkill, Stop-Process or
signal anywhere in it, and a test asserts that by parsing the source rather than trusting the
sentence you are reading. It also never STARTS anything: only running distributions are queried.
"""
import json
import os
import subprocess
import sys
import time

sys.dont_write_bytecode = True

SCHEMA = "meepcoin-workload-preflight/1"

STATUS_AVAILABLE = "available"
STATUS_UNAVAILABLE = "unavailable"
STATUS_ERROR = "error"
STATUSES = (STATUS_AVAILABLE, STATUS_UNAVAILABLE, STATUS_ERROR)

STAGES = ("lead_in", "pre_launch")
# Both must answer. A machine where only one side could be inventoried is a machine whose state is
# unknown, and unknown is a refusal. This floor cannot be shrunk by a caller; passing a shorter
# required_sources EXTENDS it rather than replacing it.
REQUIRED_SOURCES = ("windows", "wsl")

WSL_EXE = "wsl.exe"
WSL_STATE_RUNNING = "running"
WSL_STATES_KNOWN = ("running", "stopped", "installing", "uninstalling", "converting")
# The exact header `wsl.exe --list --verbose` prints, upper-cased. It is VALIDATED, not skipped.
WSL_LIST_HEADER = ("NAME", "STATE", "VERSION")
# USED, not merely defined: emitted as a refusal reason whenever the WSL side cannot be
# enumerated, and carried in the inventory detail so a reader sees why the machine is unknown.
WSL_ROUTING_UNKNOWN = ("the WSL inventory could not enumerate this machine's distributions, so "
                       "an unknown number of installed distributions were NOT inspected and this "
                       "machine's state is not known. Generic `bash -lc` is not WSL coverage: on "
                       "Windows it is commonly Git-for-Windows or MSYS bash, which has no "
                       "/proc/<pid>/exe and reaches no distribution at all")
GIT_BASH_MARKERS = ("/mingw", "/msys", "/cygdrive", "\\git\\", "/git/", "usr/bin/bash.exe")

# Denied by default. A specification may extend this; it may not shrink it below this floor.
DEFAULT_DENYLIST = ("p2pool", "xmrig", "monerod", "meepcoind", "meepcoind.expgen", "xmr-stak",
                    "cpuminer", "cgminer", "bfgminer", "nbminer", "t-rex", "lolminer")

# Recorded, never blocking.
COVARIATE_NAMES = ("workloadssessionhost", "aihost", "npuservice")

_EXE_SUFFIXES = (".exe", ".com", ".bat", ".cmd")

# The read-only inventory script. Never `ps -eo comm=`: it truncates at 15 characters, so
# `meepcoind.expgen` could never match.
PROC_SCRIPT = ('for e in /proc/[0-9]*/exe; do p=${e%/exe}; p=${p#/proc/}; '
               't=$(readlink -f "$e" 2>/dev/null) || t=""; '
               'n=$(tr -d "\\0" < /proc/$p/comm 2>/dev/null) || n=""; '
               'printf "%s\\t%s\\t%s\\n" "$p" "$n" "$t"; done')


def normalize_name(value):
    """basename -> casefold -> drop ONE trailing executable suffix."""
    if not value:
        return ""
    base = os.path.basename(str(value).replace("\\", "/").rstrip("/"))
    low = base.casefold()
    for suf in _EXE_SUFFIXES:
        if low.endswith(suf):
            return low[: -len(suf)]
    return low


class ProcessRecord:
    """One observed process. `exe` is the resolved executable path, or None when unresolved."""

    __slots__ = ("pid", "name", "exe", "source", "raw")

    def __init__(self, pid, name, exe=None, source="unknown", raw=None):
        self.pid = pid
        self.name = name
        self.exe = exe
        self.source = source
        self.raw = raw

    @property
    def normalized_name(self):
        return normalize_name(self.name)

    @property
    def normalized_exe(self):
        return normalize_name(self.exe) if self.exe else None

    def as_dict(self):
        return {"pid": self.pid, "name": self.name, "exe": self.exe, "source": self.source,
                "normalized_name": self.normalized_name, "normalized_exe": self.normalized_exe}


class Inventory:
    """The result of asking one source what is running."""

    def __init__(self, source, status, records=None, error=None, detail=None, extra=None):
        if status not in STATUSES:
            raise ValueError("inventory status %r is not one of %s" % (status, list(STATUSES)))
        self.source = source
        self.status = status
        self.records = list(records or [])
        self.error = error
        self.detail = detail
        self.extra = dict(extra or {})

    def as_dict(self):
        return {"source": self.source, "status": self.status, "error": self.error,
                "detail": self.detail, "count": len(self.records),
                "records": [r.as_dict() for r in self.records], "extra": self.extra}


class PreflightResult:
    def __init__(self, stage, allowed, inventories, denied, ambiguous, covariates, reasons):
        self.stage = stage
        self.allowed = allowed
        self.inventories = inventories
        self.denied = denied
        self.ambiguous = ambiguous
        self.covariates = covariates
        self.reasons = reasons

    def summary(self):
        if self.allowed:
            return "stage %s: no denied workload observed by any required source" % self.stage
        return "stage %s refused: %s" % (self.stage, "; ".join(self.reasons))

    def as_dict(self):
        return {
            "schema": SCHEMA, "stage": self.stage, "allowed": self.allowed,
            "reasons": self.reasons,
            "denied": [r.as_dict() for r in self.denied],
            "ambiguous": [r.as_dict() for r in self.ambiguous],
            "covariates_observed": [r.as_dict() for r in self.covariates],
            "covariate_policy": "recorded only; never a blocker and never an outcome filter",
            "inventories": [i.as_dict() for i in self.inventories],
            "operator_action": (None if self.allowed else
                                "close these processes yourself and re-run the preflight; this "
                                "program never terminates anything"),
            "utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }


# ------------------------------------------------------------------ real, read-only providers
def _text(stream):
    """wsl.exe writes UTF-16LE; the NULs survive a naive text decode."""
    if isinstance(stream, bytes):
        try:
            return stream.decode("utf-16-le")
        except Exception:                             # pragma: no cover - defensive
            return stream.decode("utf-8", "replace")
    return (stream or "").replace("\x00", "")


def wsl_distributions(runner=subprocess.run, timeout=30):
    """READ-ONLY enumeration: (rows, status, error). Never starts a distribution.

    `wsl.exe --list --verbose` reports NAME, STATE and VERSION for every installed distribution
    without touching any of them. A stopped distribution is reported and NOT queried, because
    `wsl -d <stopped>` would start it."""
    argv = [WSL_EXE, "--list", "--verbose"]
    try:
        r = runner(argv, capture_output=True, text=True, timeout=timeout)
    except Exception as e:
        return None, STATUS_ERROR, "%s: %s: %s" % (" ".join(argv), type(e).__name__, e)
    if getattr(r, "returncode", 1) != 0:
        return None, STATUS_ERROR, "%s exited %s: %s" % (" ".join(argv), r.returncode,
                                                         _text(r.stderr)[:200])
    lines = [ln for ln in _text(r.stdout).splitlines() if ln.strip()]
    if not lines:
        return None, STATUS_UNAVAILABLE, "the enumeration returned nothing"
    # R5-15: line 0 was DISCARDED without ever being read. If the header is absent or is not the
    # header, the discarded line was a distribution -- so the inventory silently omitted one and
    # still reported AVAILABLE. The header is now a checked part of the grammar.
    header = [t for t in lines[0].replace("*", " ", 1).split() if t]
    if [t.upper() for t in header] != list(WSL_LIST_HEADER):
        return None, STATUS_ERROR, ("the distribution list does not begin with the %s header; "
                                    "its first line is %r, and discarding an unverified first "
                                    "line would silently drop a distribution"
                                    % (" ".join(WSL_LIST_HEADER), lines[0][:80]))
    rows = []
    for ln in lines[1:]:
        parts = ln.replace("*", " ", 1).split()
        if len(parts) < 2:
            return None, STATUS_ERROR, "unparseable distribution line %r" % ln[:80]
        name, state = parts[0], parts[1].casefold()
        if state not in WSL_STATES_KNOWN:
            return None, STATUS_ERROR, ("distribution %r reports state %r, which this module does "
                                        "not recognise; an unrecognised state is ambiguous and "
                                        "ambiguity is a refusal" % (name, parts[1]))
        rows.append({"name": name, "state": state,
                     "version": parts[2] if len(parts) > 2 else None})
    if not rows:
        return None, STATUS_UNAVAILABLE, "no distributions were listed"
    return rows, STATUS_AVAILABLE, None


def wsl_inventory(runner=subprocess.run, timeout=30, distributions=None):
    """WSL processes, per RUNNING distribution, each queried EXPLICITLY BY IDENTITY.

    Generic `bash -lc` is never used here; see bash_inventory, which is a different source."""
    rows, status, err = (distributions if distributions is not None
                         else wsl_distributions(runner=runner, timeout=timeout))
    if rows is None:
        return Inventory("wsl:distributions", status if status != STATUS_AVAILABLE
                         else STATUS_ERROR, error=err,
                         detail=WSL_ROUTING_UNKNOWN,
                         extra={"enumerated": None, "per_distribution": {}})
    running = [d for d in rows if d["state"] == WSL_STATE_RUNNING]
    per = {}
    recs = []
    for d in running:
        name = d["name"]
        argv = [WSL_EXE, "-d", name, "--exec", "/bin/sh", "-c", PROC_SCRIPT]
        try:
            r = runner(argv, capture_output=True, text=True, timeout=timeout)
        except Exception as e:
            per[name] = {"ok": False, "error": "%s: %s" % (type(e).__name__, e)}
            continue
        if getattr(r, "returncode", 1) != 0:
            per[name] = {"ok": False,
                         "error": "exit %s: %s" % (r.returncode, _text(r.stderr)[:200])}
            continue
        got, malformed = 0, []
        for line in _text(r.stdout).splitlines():
            if not line.strip():
                continue
            parts = line.split("\t")
            if len(parts) != 3 or not parts[0].strip():
                # R4-13: a malformed row was SKIPPED, so a denied process with one extra field
                # vanished while the distribution still reported AVAILABLE. A row this module
                # cannot parse is a process it cannot rule out.
                malformed.append(line[:60].replace("\t", "<TAB>"))
                continue
            pid, pname, exe = parts
            if not pname.strip() and not exe.strip():
                # R5-15: a syntactically valid row for a PID whose comm AND executable are both
                # unreadable. An observed process this module cannot identify is UNKNOWN, not
                # evidence of absence, and ambiguity is a refusal.
                malformed.append(("%s<TAB><TAB>  (pid %s: name and executable both unreadable)"
                                  % (pid.strip(), pid.strip()))[:120])
                continue
            recs.append(ProcessRecord(pid, pname or None, exe or None,
                                      "wsl:%s:/proc" % name, line))
            got += 1
        if malformed:
            per[name] = {"ok": False, "records": got, "malformed_rows": len(malformed),
                         "malformed_excerpt": malformed[:3],
                         "error": "%d unreadable /proc row(s); a row this module cannot parse, "
                                  "or a PID whose name and executable are both unreadable, is a "
                                  "process it cannot rule out" % len(malformed)}
        else:
            per[name] = {"ok": got > 0, "records": got, "malformed_rows": 0,
                         "error": None if got else "no readable /proc entries were returned"}
    extra = {"enumerated": rows, "running": [d["name"] for d in running],
             "per_distribution": per,
             "malformed_rows": sum(v.get("malformed_rows", 0) for v in per.values()),
             "stopped_not_queried": [d["name"] for d in rows if d["state"] != WSL_STATE_RUNNING],
             "policy": "a stopped distribution is recorded and NEVER queried; querying it would "
                       "start it"}
    failed = sorted(n for n, v in per.items() if not v.get("ok"))
    if failed:
        return Inventory("wsl:distributions", STATUS_ERROR,
                         records=recs,
                         error="distribution(s) %s could not be inventoried: %s"
                               % (failed, {n: per[n].get("error") for n in failed}),
                         detail=WSL_ROUTING_UNKNOWN, extra=extra)
    if not running:
        return Inventory("wsl:distributions", STATUS_UNAVAILABLE, records=recs,
                         detail="no WSL distribution is running, so no WSL process inventory "
                                "exists; that is not evidence that the machine is idle",
                         extra=extra)
    return Inventory("wsl:distributions", STATUS_AVAILABLE, recs, extra=extra)


def bash_inventory(runner=subprocess.run, timeout=20):
    """Whatever `bash` on PATH is. A SEPARATE source. It can never satisfy the WSL requirement."""
    try:
        r = runner(["bash", "-lc", PROC_SCRIPT], capture_output=True, text=True, timeout=timeout)
    except Exception as e:
        return Inventory("shell:bash", STATUS_ERROR, error="%s: %s" % (type(e).__name__, e))
    if getattr(r, "returncode", 1) != 0:
        return Inventory("shell:bash", STATUS_ERROR,
                         error="exit %s: %s" % (r.returncode, (r.stderr or "")[:200]))
    recs, looks_like_git_bash, malformed = [], False, []
    for line in (r.stdout or "").splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        if len(parts) != 3 or not parts[0]:
            malformed.append(line[:60].replace("\t", "<TAB>"))
            continue
        pid, name, exe = parts
        if not name.strip() and not exe.strip():
            # R5-15: a PID whose comm AND executable are both unreadable is UNKNOWN,
            # not evidence of absence, so the whole source refuses.
            malformed.append("%s<TAB><TAB>  (pid %s: name and executable both unreadable)"
                             % (pid.strip(), pid.strip()))
            continue
        if exe and any(m in exe.casefold() for m in GIT_BASH_MARKERS):
            looks_like_git_bash = True
        recs.append(ProcessRecord(pid, name or None, exe or None, "shell:bash", line))
    extra = {"looks_like_git_msys_or_cygwin_bash": looks_like_git_bash,
             "satisfies_wsl_requirement": False,
             "malformed_rows": len(malformed), "malformed_excerpt": malformed[:3],
             "why": "this source names no distribution and reaches at most one environment; it is "
                    "recorded and matched like any other inventory, and it is not WSL coverage"}
    if malformed:
        return Inventory("shell:bash", STATUS_ERROR, records=recs,
                         error="%d unparseable /proc row(s)" % len(malformed), extra=extra)
    if not recs:
        return Inventory("shell:bash", STATUS_UNAVAILABLE,
                         detail="no readable /proc entries were returned", extra=extra)
    return Inventory("shell:bash", STATUS_AVAILABLE, recs, extra=extra)


def windows_inventory(runner=subprocess.run, timeout=60):
    """Windows processes via Win32_Process. ExecutablePath may be unreadable without elevation;
    that produces an unresolved record, which the matcher treats as AMBIGUOUS, not as absent."""
    ps = ("$ErrorActionPreference='Stop';"
          "Get-CimInstance Win32_Process | "
          "Select-Object ProcessId,Name,ExecutablePath | ConvertTo-Json -Compress -Depth 3")
    try:
        r = runner(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", ps],
                   capture_output=True, text=True, timeout=timeout)
    except Exception as e:
        return Inventory("windows:Win32_Process", STATUS_ERROR,
                         error="%s: %s" % (type(e).__name__, e))
    if getattr(r, "returncode", 1) != 0:
        return Inventory("windows:Win32_Process", STATUS_ERROR,
                         error="exit %s: %s" % (r.returncode, (r.stderr or "")[:200]))
    try:
        rows = json.loads(r.stdout or "null")
    except Exception as e:
        return Inventory("windows:Win32_Process", STATUS_ERROR,
                         error="unparseable output: %s: %s" % (type(e).__name__, e))
    if rows is None:
        return Inventory("windows:Win32_Process", STATUS_UNAVAILABLE,
                         detail="the query returned nothing")
    if isinstance(rows, dict):
        rows = [rows]
    recs = [ProcessRecord(x.get("ProcessId"), x.get("Name"), x.get("ExecutablePath"),
                          "windows:Win32_Process", x) for x in rows]
    if not recs:
        return Inventory("windows:Win32_Process", STATUS_UNAVAILABLE,
                         detail="no rows returned; an empty inventory is not evidence that the "
                                "machine is idle")
    return Inventory("windows:Win32_Process", STATUS_AVAILABLE, recs)


DEFAULT_PROVIDERS = {"windows": windows_inventory, "wsl": wsl_inventory,
                     "shell": bash_inventory}


# ------------------------------------------------------------------ the gate
class WorkloadPreflight:
    """Fail-closed. Providers are injected so tests drive synthetic inventories."""

    def __init__(self, providers=None, denylist=DEFAULT_DENYLIST, required_sources=None,
                 covariate_names=COVARIATE_NAMES, denied_path_fragments=()):
        self.providers = dict(providers or DEFAULT_PROVIDERS)
        # A specification may EXTEND the denylist; the default floor is always included.
        self.denylist = frozenset(normalize_name(n) for n in denylist) | frozenset(
            normalize_name(n) for n in DEFAULT_DENYLIST)
        # The floor is IMMUTABLE. A caller may only EXTEND.
        extra = tuple(s for s in (required_sources or ()) if s not in REQUIRED_SOURCES)
        self.required_sources = tuple(REQUIRED_SOURCES) + extra
        self.requested_sources = tuple(required_sources or REQUIRED_SOURCES)
        self.floor_sources = tuple(REQUIRED_SOURCES)
        self.covariate_names = frozenset(normalize_name(n) for n in covariate_names)
        self.denied_path_fragments = tuple(f.casefold() for f in denied_path_fragments)

    def check(self, stage, spec=None):
        if stage not in STAGES:
            raise ValueError("stage %r is not one of %s" % (stage, list(STAGES)))
        inventories, reasons = [], []

        # Required sources first, then every optional source that is configured. An optional
        # source cannot make the stage pass, but what it sees still counts against the denylist.
        keys = list(self.required_sources) + [k for k in sorted(self.providers)
                                              if k not in self.required_sources]
        for key in keys:
            provider = self.providers.get(key)
            if provider is None:
                if key in self.required_sources:
                    missing = Inventory(key, STATUS_UNAVAILABLE,
                                        detail="no provider is configured for this required "
                                               "source, so nothing was asked and nothing is "
                                               "known")
                    missing.extra["requested_as"] = key
                    missing.extra["is_a_required_source"] = True
                    inventories.append(missing)
                continue
            try:
                inv = provider()
            except Exception as e:
                inv = Inventory(key, STATUS_ERROR, error="%s: %s" % (type(e).__name__, e))
            if not isinstance(inv, Inventory):
                inv = Inventory(key, STATUS_ERROR,
                                error="provider returned %s, not an Inventory"
                                      % type(inv).__name__)
            inv.extra.setdefault("requested_as", key)
            inv.extra["is_a_required_source"] = key in self.required_sources
            inventories.append(inv)

        for inv in inventories:
            if inv.extra.get("is_a_required_source") and inv.status != STATUS_AVAILABLE:
                reasons.append("required inventory %r (%s) is %s (%s) -- not knowing what is "
                               "running is a refusal, not a pass"
                               % (inv.extra.get("requested_as"), inv.source, inv.status,
                                  inv.error or inv.detail or "no detail"))
            if inv.extra.get("requested_as") == "wsl":
                if inv.extra.get("enumerated") is None and inv.status != STATUS_AVAILABLE:
                    reasons.append(WSL_ROUTING_UNKNOWN)
                bad = sorted(n for n, v in (inv.extra.get("per_distribution") or {}).items()
                             if not v.get("ok"))
                if bad:
                    reasons.append("WSL distribution(s) %s were enumerated but could not be "
                                   "inventoried; a partial answer is not an answer" % bad)
                if inv.extra.get("satisfies_wsl_requirement") is False:
                    reasons.append("the source offered for 'wsl' declares that it does not "
                                   "satisfy the WSL requirement: %s" % inv.extra.get("why"))

        deny = self.denylist | frozenset(
            normalize_name(n) for n in ((spec or {}).get("denied_workloads") or ()))

        denied, ambiguous, covariates = [], [], []
        for inv in inventories:
            if inv.status != STATUS_AVAILABLE and not inv.records:
                continue
            for rec in inv.records:
                nn, ne = rec.normalized_name, rec.normalized_exe
                if nn in self.covariate_names or (ne and ne in self.covariate_names):
                    covariates.append(rec)
                # EQUALITY on the normal form, never substring.
                hit = (nn in deny) or (ne is not None and ne in deny)
                path_hit = bool(rec.exe) and any(
                    f in rec.exe.casefold() for f in self.denied_path_fragments)
                if hit or path_hit:
                    denied.append(rec)
                elif rec.exe is None and self._name_is_suspicious(nn, deny):
                    ambiguous.append(rec)

        for rec in denied:
            reasons.append("denied workload %r (pid %s, exe %s) observed by %s"
                           % (rec.name, rec.pid, rec.exe or "UNRESOLVED", rec.source))
        for rec in ambiguous:
            reasons.append("process %r (pid %s) from %s has no resolvable executable path and its "
                           "name cannot be ruled out; ambiguity is a refusal"
                           % (rec.name, rec.pid, rec.source))

        shrunk = [x for x in self.requested_sources if x not in self.required_sources]
        if shrunk:                                    # pragma: no cover - structurally impossible
            reasons.append("required_sources cannot be shrunk; %s was ignored" % shrunk)
        return PreflightResult(stage, not reasons, inventories, denied, ambiguous, covariates,
                               reasons)

    @staticmethod
    def _name_is_suspicious(normalized, deny):
        """A name that CONTAINS a denied token without equalling one, on a record whose executable
        path could not be resolved. Equality is already handled as a denial; this is the
        unresolvable middle, and it fails closed."""
        return bool(normalized) and any(tok in normalized for tok in deny)

    def check_both_stages(self, spec=None):
        """Lead-in and immediately-before-launch, over the SAME complete source set. Both must
        pass, and the second is re-run from scratch rather than reusing the first answer."""
        out = [self.check("lead_in", spec), self.check("pre_launch", spec)]
        return out, all(r.allowed for r in out)


def write_refusal(staging_dir, results, spec=None):
    """Record a refusal in a caller-provided staging location. NO result bundle is created."""
    os.makedirs(staging_dir, exist_ok=True)
    if isinstance(results, PreflightResult):
        results = [results]
    doc = {
        "schema": "meepcoin-preflight-refusal/1",
        "non_evidence": True,
        "refused": True,
        "spec_id": (spec or {}).get("spec_id"),
        "spec_status": (spec or {}).get("status"),
        "stages": [r.as_dict() for r in results],
        "no_bundle_created": True,
        "terminated_anything": False,
        "started_anything": False,
        "operator_action": "close the listed processes yourself; this program never terminates, "
                           "signals, reprioritises or starts anything",
        "utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    path = os.path.join(staging_dir, "PREFLIGHT_REFUSED.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=1)
    return path
