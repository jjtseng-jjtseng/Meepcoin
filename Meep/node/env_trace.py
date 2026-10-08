#!/usr/bin/env python3
"""A strictly READ-ONLY environment trace taken alongside a run.

NON-EVIDENCE, AND NEVER A GATE ON THE SCIENCE. This module observes the machine. It starts no
workload, stops no process, and changes no priority, affinity, power, thermal or scheduler
setting. Nothing it records can exclude a record, invalidate a replicate or authorise a rerun.

WHAT IS A GATE AND WHAT IS NOT

  the STRUCTURE of the trace is a gate      -- rows at the scheduled cadence, a lead-in before
                                               launch and a lead-out after cleanup, and an
                                               explicit status on every single metric
  the VALUES in the trace are covariates    -- CPU, NPU, memory and process facts are context for
                                               interpreting a result, never grounds for discarding
                                               one

That separation is the whole point. A trace that is allowed to condemn a measurement becomes an
after-the-fact filter, and an after-the-fact filter is how a null result quietly turns into a
positive one. verify_trace() below therefore reads only structure and status; it never reads a
measured value, so it cannot be made to reject a row for being inconvenient.

NEVER SUBSTITUTE ZERO

Every metric is a {"status", "value", "source", "detail"} envelope. `value` exists only when
status is "available". A counter that does not exist on this host, a process that is not running,
a permission failure -- each is reported as "unavailable" or "error" with the reason. Zero is a
measurement, not a way of saying "I could not look", and a trace that confuses the two would make
an idle machine and an unreadable one indistinguishable.

WINDOWS METRICS FROM WSL

The driver runs in WSL and the interesting contention is on the Windows side, so one long-lived
powershell.exe helper is started and asked for a sample per tick over stdin. Starting a fresh
PowerShell per tick costs seconds; one persistent process costs about 1 s per sample, comfortably
inside a 5 s cadence.

NPU ATTRIBUTION IS A STATED HEURISTIC

This host exposes no `NPU Engine` counter set. NPU work appears in the GPU-engine counters under
its own adapter LUID, so the NPU LUID is identified as the one whose engine types are exactly
{Compute} while exactly one ComputeAccelerator device is present. When that is not unambiguous the
metric is reported unavailable WITH the reason, never guessed and never zeroed. The raw per-LUID
engine rows are always kept so a later analyst can re-attribute them.

Usage:
    python3 node/env_trace.py --out=trace.json --seconds=90 [--interval=5]
    python3 node/env_trace.py --out=trace.json --wrap="<command>" [--lead=35]
    python3 node/env_trace.py --verify=trace.json
"""
import base64, json, os, subprocess, sys, threading, time

INTERVAL_S = 5.0
LEAD_IN_S = 30.0            # trace must start at least this long before launch
LEAD_OUT_S = 30.0           # and run at least this long after cleanup

WATCH_NAMES = ("WorkloadsSessionHost", "p2pool", "xmrig", "monerod", "meepcoind",
               "meepcoind.expgen")
WSL_WATCH = ("meepcoind", "monerod", "xmrig", "p2pool", "symmetric_series", "sym_miner")

# every metric key a row must carry; a missing key is a structural failure, not a silent gap
REQUIRED_METRICS = ("windows_cpu_percent", "windows_memory", "gpu_engine", "npu",
                    "watched_processes", "windows_process_inventory",
                    "wsl_load", "wsl_memory", "wsl_cpu_percent", "wsl_process_inventory")
STATUSES = ("available", "unavailable", "error")

PS_SAMPLER = r"""
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
$names = @(__NAMES__)

function Env-Metric($status, $value, $source, $detail) {
  return [ordered]@{ status = $status; value = $value; source = $source; detail = $detail }
}

# resolved once: the set of ComputeAccelerator devices present on this host
$accel = @(Get-PnpDevice -Class ComputeAccelerator -PresentOnly -ErrorAction SilentlyContinue |
           Select-Object -ExpandProperty FriendlyName)

while ($true) {
  $line = [Console]::In.ReadLine()
  if ($null -eq $line) { break }
  if ($line -eq 'QUIT') { break }
  $o = [ordered]@{}

  # ---- total CPU ----
  try {
    $c = Get-CimInstance Win32_PerfFormattedData_PerfOS_Processor -Filter "Name='_Total'" -ErrorAction Stop
    if ($null -eq $c) {
      $o.windows_cpu_percent = Env-Metric 'unavailable' $null 'Win32_PerfFormattedData_PerfOS_Processor' 'the _Total instance was not returned'
    } else {
      $o.windows_cpu_percent = Env-Metric 'available' ([int]$c.PercentProcessorTime) 'Win32_PerfFormattedData_PerfOS_Processor(_Total)' $null
    }
  } catch {
    $o.windows_cpu_percent = Env-Metric 'error' $null 'Win32_PerfFormattedData_PerfOS_Processor' "$($_.Exception.GetType().Name): $($_.Exception.Message)"
  }

  # ---- physical memory ----
  try {
    $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop
    $o.windows_memory = Env-Metric 'available' ([ordered]@{
      total_mb = [int][math]::Round($os.TotalVisibleMemorySize / 1KB)
      free_mb  = [int][math]::Round($os.FreePhysicalMemory / 1KB)
    }) 'Win32_OperatingSystem' $null
  } catch {
    $o.windows_memory = Env-Metric 'error' $null 'Win32_OperatingSystem' "$($_.Exception.GetType().Name): $($_.Exception.Message)"
  }

  # ---- GPU/NPU engine utilisation, with the owning pid from the instance name ----
  $luidEng = @{}
  try {
    $g = Get-CimInstance -Namespace root\cimv2 -ClassName Win32_PerfFormattedData_GPUPerformanceCounters_GPUEngine -ErrorAction Stop
    $rows = @()
    foreach ($r in $g) {
      if ($r.Name -match 'pid_(\d+)_luid_(0x[0-9A-Fa-f]+_0x[0-9A-Fa-f]+)_phys_(\d+)_eng_(\d+)_engtype_(\w+)') {
        $luid = $Matches[2].ToLower()
        $eng  = $Matches[5]
        if (-not $luidEng.ContainsKey($luid)) { $luidEng[$luid] = New-Object 'System.Collections.Generic.HashSet[string]' }
        [void]$luidEng[$luid].Add($eng)
        if ($r.UtilizationPercentage -gt 0) {
          $rows += [ordered]@{ pid = [int]$Matches[1]; luid = $luid; engine = $eng
                               utilization_percent = [double]$r.UtilizationPercentage }
        }
      }
    }
    $o.gpu_engine = Env-Metric 'available' ([ordered]@{
      instance_count = $g.Count
      nonzero = @($rows | Sort-Object -Property utilization_percent -Descending | Select-Object -First 24)
    }) 'Win32_PerfFormattedData_GPUPerformanceCounters_GPUEngine' $null

    # ---- NPU: the compute-only LUID, when that is unambiguous ----
    $computeOnly = @($luidEng.Keys | Where-Object { $luidEng[$_].Count -eq 1 -and $luidEng[$_].Contains('Compute') })
    if ($accel.Count -ne 1) {
      $o.npu = Env-Metric 'unavailable' $null 'derived from GPU-engine LUIDs' "expected exactly one ComputeAccelerator device, found $($accel.Count) -- the NPU LUID cannot be identified and is NOT guessed"
    } elseif ($computeOnly.Count -ne 1) {
      $o.npu = Env-Metric 'unavailable' $null 'derived from GPU-engine LUIDs' "expected exactly one compute-only LUID, found $($computeOnly.Count) -- the NPU LUID cannot be identified and is NOT guessed"
    } else {
      $luid = $computeOnly[0]
      $mine = @($rows | Where-Object { $_.luid -eq $luid })
      $top = $mine | Sort-Object -Property utilization_percent -Descending | Select-Object -First 1
      $o.npu = Env-Metric 'available' ([ordered]@{
        device = $accel[0]
        luid = $luid
        total_utilization_percent = [double](($mine | ForEach-Object { $_.utilization_percent } |
                                              Measure-Object -Sum).Sum)
        busiest_pid = $(if ($top) { [int]$top.pid } else { $null })
        busiest_pid_utilization_percent = $(if ($top) { [double]$top.utilization_percent } else { $null })
        by_pid = @($mine | Sort-Object -Property utilization_percent -Descending | Select-Object -First 8)
      }) 'HEURISTIC: the compute-only GPU-engine LUID on a host with exactly one ComputeAccelerator' 'this host exposes no NPU Engine counter set; the attribution is by engine-type composition, not by a device-reported identifier'
    }
  } catch {
    $msg = "$($_.Exception.GetType().Name): $($_.Exception.Message)"
    $o.gpu_engine = Env-Metric 'error' $null 'Win32_PerfFormattedData_GPUPerformanceCounters_GPUEngine' $msg
    $o.npu = Env-Metric 'error' $null 'derived from GPU-engine LUIDs' "the GPU-engine sample failed: $msg"
  }

  # ---- the named processes we care about ----
  try {
    $out = @()
    foreach ($n in $names) {
      $ps = @(Get-Process -Name $n -ErrorAction SilentlyContinue)
      if ($ps.Count -eq 0) {
        $out += [ordered]@{ name = $n; status = 'not_running'; instances = @() }
        continue
      }
      $inst = @()
      foreach ($p in $ps) {
        $cpu = $null; $cpuStatus = 'available'
        try { $cpu = [double]$p.CPU } catch { $cpuStatus = 'error' }
        if ($null -eq $p.CPU) { $cpuStatus = 'unavailable' }
        $inst += [ordered]@{
          pid = $p.Id
          cpu_seconds_status = $cpuStatus
          cpu_seconds = $(if ($cpuStatus -eq 'available') { [math]::Round($cpu, 3) } else { $null })
          cpu_seconds_detail = $(if ($cpuStatus -eq 'available') { $null } else { 'the process total-processor-time property was not readable from this (non-elevated) session; it is reported as unread, never as zero' })
          working_set_mb = [math]::Round($p.WorkingSet64 / 1MB, 2)
        }
      }
      $out += [ordered]@{ name = $n; status = 'running'; instances = $inst }
    }
    $o.watched_processes = Env-Metric 'available' $out 'Get-Process' 'a name with status not_running was looked for and genuinely absent'
  } catch {
    $o.watched_processes = Env-Metric 'error' $null 'Get-Process' "$($_.Exception.GetType().Name): $($_.Exception.Message)"
  }

  # ---- coarse process inventory ----
  try {
    $all = Get-Process -ErrorAction Stop
    $top = $all | Group-Object ProcessName | Sort-Object Count -Descending | Select-Object -First 12
    $o.windows_process_inventory = Env-Metric 'available' ([ordered]@{
      total = $all.Count
      by_name = @($top | ForEach-Object { [ordered]@{ name = $_.Name; count = $_.Count } })
    }) 'Get-Process' $null
  } catch {
    $o.windows_process_inventory = Env-Metric 'error' $null 'Get-Process' "$($_.Exception.GetType().Name): $($_.Exception.Message)"
  }

  $o | ConvertTo-Json -Compress -Depth 8
  [Console]::Out.Flush()
}
"""


def _metric(status, value=None, source=None, detail=None):
    """A metric envelope. `value` is present only when the metric was actually read."""
    if status not in STATUSES:
        raise ValueError(f"metric status must be one of {STATUSES}, got {status!r}")
    return {"status": status, "value": value if status == "available" else None,
            "source": source, "detail": detail}


def _read(path):
    with open(path, encoding="utf-8", errors="replace") as f:
        return f.read()


class WindowsSampler:
    """One long-lived powershell.exe, asked for a sample per tick over stdin."""

    def __init__(self, names=WATCH_NAMES, timeout_s=4.0):
        self.names = names
        self.timeout_s = timeout_s
        self.proc = None
        self.start_error = None
        self.lock = threading.Lock()

    def start(self):
        script = PS_SAMPLER.replace(
            "__NAMES__", ",".join("'%s'" % n.replace("'", "''") for n in self.names))
        enc = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
        try:
            self.proc = subprocess.Popen(
                ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                 "-EncodedCommand", enc],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                text=True, bufsize=1)
        except Exception as e:                       # no powershell.exe reachable from this WSL
            self.start_error = f"{type(e).__name__}: {e}"

    def sample(self):
        """Returns a dict of metric envelopes. Never raises, never fabricates a value."""
        if self.proc is None:
            why = self.start_error or "the Windows sampler was never started"
            return {k: _metric("unavailable", source="powershell.exe", detail=why)
                    for k in ("windows_cpu_percent", "windows_memory", "gpu_engine", "npu",
                              "watched_processes", "windows_process_inventory")}
        with self.lock:
            try:
                if self.proc.poll() is not None:
                    raise RuntimeError(f"the sampler exited with code {self.proc.returncode}")
                self.proc.stdin.write("SAMPLE\n")
                self.proc.stdin.flush()
                line = self._readline_with_timeout()
                if line is None:
                    raise TimeoutError(f"no sample within {self.timeout_s}s")
                got = json.loads(line)
            except Exception as e:
                why = f"{type(e).__name__}: {e}"
                return {k: _metric("error", source="powershell.exe", detail=why)
                        for k in ("windows_cpu_percent", "windows_memory", "gpu_engine", "npu",
                                  "watched_processes", "windows_process_inventory")}
        out = {}
        for k in ("windows_cpu_percent", "windows_memory", "gpu_engine", "npu",
                  "watched_processes", "windows_process_inventory"):
            m = got.get(k)
            if not isinstance(m, dict) or m.get("status") not in STATUSES:
                out[k] = _metric("error", source="powershell.exe",
                                 detail=f"the sampler returned no usable envelope for {k}")
            else:
                out[k] = {"status": m["status"],
                          "value": m.get("value") if m["status"] == "available" else None,
                          "source": m.get("source"), "detail": m.get("detail")}
        return out

    def _readline_with_timeout(self):
        box = {}

        def rd():
            try:
                box["line"] = self.proc.stdout.readline()
            except Exception as e:
                box["err"] = e
        t = threading.Thread(target=rd, daemon=True)
        t.start()
        t.join(self.timeout_s)
        if t.is_alive() or "line" not in box:
            return None
        return box["line"].strip() or None

    def stop(self):
        if self.proc is None:
            return
        try:
            self.proc.stdin.write("QUIT\n")
            self.proc.stdin.flush()
        except Exception:
            pass
        try:
            self.proc.wait(timeout=5)
        except Exception:
            # only OUR OWN helper is ever terminated here, and only after asking it to quit
            try:
                self.proc.terminate()
            except Exception:
                pass


class WslSampler:
    """/proc reads. Nothing here writes, signals or reprioritises anything."""

    def __init__(self, watch=WSL_WATCH):
        self.watch = watch
        self.prev = None

    def sample(self):
        out = {}
        try:
            la = _read("/proc/loadavg").split()
            out["wsl_load"] = _metric("available",
                                      {"1m": float(la[0]), "5m": float(la[1]),
                                       "15m": float(la[2]), "runnable": la[3]},
                                      "/proc/loadavg")
        except Exception as e:
            out["wsl_load"] = _metric("error", source="/proc/loadavg",
                                      detail=f"{type(e).__name__}: {e}")
        try:
            mem = {}
            for ln in _read("/proc/meminfo").splitlines():
                k, _, v = ln.partition(":")
                if k in ("MemTotal", "MemAvailable", "MemFree", "SwapTotal", "SwapFree"):
                    mem[k] = int(v.split()[0]) // 1024
            missing = [k for k in ("MemTotal", "MemAvailable") if k not in mem]
            if missing:
                out["wsl_memory"] = _metric("unavailable", source="/proc/meminfo",
                                            detail=f"missing fields {missing}")
            else:
                out["wsl_memory"] = _metric("available", {k + "_mb": v for k, v in mem.items()},
                                            "/proc/meminfo")
        except Exception as e:
            out["wsl_memory"] = _metric("error", source="/proc/meminfo",
                                        detail=f"{type(e).__name__}: {e}")
        out["wsl_cpu_percent"] = self._cpu()
        out["wsl_process_inventory"] = self._procs()
        return out

    def _cpu(self):
        """Busy percentage since the PREVIOUS tick. The first tick has no previous tick, and that
        is reported as unavailable rather than as 0."""
        try:
            first = _read("/proc/stat").splitlines()[0].split()
            vals = [int(x) for x in first[1:]]
            total, idle = sum(vals), vals[3] + (vals[4] if len(vals) > 4 else 0)
            prev, self.prev = self.prev, (total, idle)
            if prev is None:
                return _metric("unavailable", source="/proc/stat",
                               detail="no previous tick to difference against")
            dt, di = total - prev[0], idle - prev[1]
            if dt <= 0:
                return _metric("unavailable", source="/proc/stat",
                               detail=f"the jiffy counter did not advance (delta {dt})")
            return _metric("available", round(100.0 * (dt - di) / dt, 2), "/proc/stat",
                           "busy percentage over the interval since the previous row")
        except Exception as e:
            return _metric("error", source="/proc/stat", detail=f"{type(e).__name__}: {e}")

    def _procs(self):
        """Resolved executables, so a 15-character-truncated comm can never hide a daemon."""
        try:
            total, found = 0, {}
            for entry in os.listdir("/proc"):
                if not entry.isdigit():
                    continue
                total += 1
                try:
                    exe = os.path.realpath(os.path.join("/proc", entry, "exe"))
                except OSError:
                    continue
                for w in self.watch:
                    if w in exe:
                        found.setdefault(w, []).append({"pid": int(entry), "exe": exe})
            return _metric("available", {"total": total, "watched": found},
                           "/proc/*/exe",
                           "matched on the RESOLVED executable path; /proc/*/comm truncates at 15 "
                           "characters and cannot be used for this")
        except Exception as e:
            return _metric("error", source="/proc", detail=f"{type(e).__name__}: {e}")


class EnvTrace:
    """A fixed-cadence read-only trace with an explicit lead-in and lead-out."""

    def __init__(self, out_path, interval_s=INTERVAL_S, names=WATCH_NAMES, label=None):
        self.out_path = out_path
        self.interval_s = float(interval_s)
        self.label = label
        self.win = WindowsSampler(names=names)
        self.wsl = WslSampler()
        self.rows = []
        self.markers = []
        self.t0_mono = None
        self.t0_wall = None
        self.stop_evt = threading.Event()
        self.thread = None
        self.lock = threading.Lock()

    # ---- lifecycle -------------------------------------------------------------------
    def start(self):
        self.win.start()
        self.t0_mono, self.t0_wall = time.monotonic(), time.time()
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()
        return self

    def mark(self, name):
        """Record a milestone -- 'launch' and 'cleanup' are the two the structure gate needs."""
        with self.lock:
            self.markers.append({"name": name, "mono": time.monotonic(), "wall": time.time(),
                                 "utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())})

    def stop(self):
        self.stop_evt.set()
        if self.thread is not None:
            self.thread.join(timeout=self.interval_s * 3)
        self.win.stop()
        self.write()
        return self.out_path

    # ---- the loop --------------------------------------------------------------------
    def _loop(self):
        i = 0
        while not self.stop_evt.is_set():
            scheduled_mono = self.t0_mono + i * self.interval_s
            wait = scheduled_mono - time.monotonic()
            if wait > 0 and self.stop_evt.wait(wait):
                break
            self._row(i, scheduled_mono)
            i += 1

    def _row(self, index, scheduled_mono):
        actual_mono, actual_wall = time.monotonic(), time.time()
        row = {"index": index,
               "scheduled_mono": scheduled_mono,
               "scheduled_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ",
                                              time.gmtime(self.t0_wall + index * self.interval_s)),
               "actual_mono": actual_mono,
               "actual_wall": actual_wall,
               "actual_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(actual_wall)),
               "lateness_s": round(actual_mono - scheduled_mono, 6)}
        row.update(self.wsl.sample())
        row.update(self.win.sample())
        row["completed_mono"] = time.monotonic()
        row["sample_duration_s"] = round(row["completed_mono"] - actual_mono, 6)
        with self.lock:
            self.rows.append(row)

    def write(self):
        with self.lock:
            doc = {
                "kind": "environment_trace",
                "non_evidence": True,
                "label": self.label,
                "policy": {
                    "structure_is_a_gate": True,
                    "values_are_covariates_only": True,
                    "may_exclude_a_record": False,
                    "may_authorise_a_rerun": False,
                    "note": "verify_trace() reads structure and status only. No measured value "
                            "in this file may exclude a record, invalidate a replicate or "
                            "authorise a rerun.",
                },
                "interval_s": self.interval_s,
                "required_lead_in_s": LEAD_IN_S,
                "required_lead_out_s": LEAD_OUT_S,
                "t0_mono": self.t0_mono,
                "t0_wall": self.t0_wall,
                "t0_utc": (time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self.t0_wall))
                           if self.t0_wall else None),
                "windows_sampler_start_error": self.win.start_error,
                "markers": list(self.markers),
                "row_count": len(self.rows),
                "rows": list(self.rows),
            }
        d = os.path.dirname(os.path.abspath(self.out_path))
        if d:
            os.makedirs(d, exist_ok=True)
        with open(self.out_path, "w", encoding="utf-8") as f:
            json.dump(doc, f, indent=1)
        return doc


# ---------------------------------------------------------------------- the structure gate
def verify_trace(doc, require_markers=("launch", "cleanup")):
    """Structural verification. Returns a list of failures.

    This function deliberately never inspects a measured VALUE. It reads indices, times, statuses
    and the presence of keys. A trace can therefore fail for being badly shaped and can never fail
    for what it happened to observe."""
    fails = []
    if isinstance(doc, str):
        try:
            with open(doc, encoding="utf-8") as f:
                doc = json.load(f)
        except Exception as e:
            return [f"the trace could not be read: {type(e).__name__}: {e}"]
    if doc.get("kind") != "environment_trace":
        fails.append(f"kind {doc.get('kind')!r} is not an environment_trace")
    pol = doc.get("policy") or {}
    if pol.get("may_exclude_a_record") is not False or \
            pol.get("may_authorise_a_rerun") is not False:
        fails.append("the trace does not declare that its values are covariates only")

    interval = doc.get("interval_s")
    if interval != INTERVAL_S:
        fails.append(f"cadence {interval!r} != the required {INTERVAL_S}s")
    rows = doc.get("rows")
    if not isinstance(rows, list) or not rows:
        return fails + ["the trace carries no rows"]
    if doc.get("row_count") != len(rows):
        fails.append(f"row_count {doc.get('row_count')!r} != {len(rows)} rows")

    # ---- cadence and ordering ----
    for i, r in enumerate(rows):
        if r.get("index") != i:
            fails.append(f"row {i} declares index {r.get('index')!r}")
        for k in ("scheduled_mono", "actual_mono", "scheduled_utc", "actual_utc", "lateness_s"):
            if r.get(k) is None:
                fails.append(f"row {i} has no {k}")
        sm, am, late = r.get("scheduled_mono"), r.get("actual_mono"), r.get("lateness_s")
        if isinstance(sm, (int, float)) and isinstance(am, (int, float)):
            if abs((am - sm) - (late if isinstance(late, (int, float)) else 1e9)) > 1e-3:
                fails.append(f"row {i} lateness {late!r} != actual - scheduled")
            if am < sm - 1e-6:
                fails.append(f"row {i} was taken before it was scheduled")
        if i and isinstance(sm, (int, float)):
            prev = rows[i - 1].get("scheduled_mono")
            if isinstance(prev, (int, float)) and abs((sm - prev) - interval) > 1e-6:
                fails.append(f"row {i} is scheduled {sm - prev:.3f}s after row {i - 1}, "
                             f"not {interval}s")
        if isinstance(late, (int, float)) and isinstance(interval, (int, float)) \
                and late >= interval:
            fails.append(f"row {i} was {late:.3f}s late, a full cadence interval or more -- the "
                         f"trace lost a slot rather than merely drifting")

        # ---- every metric present, with a legal status and no value without one ----
        for k in REQUIRED_METRICS:
            m = r.get(k)
            if not isinstance(m, dict):
                fails.append(f"row {i} has no {k} envelope")
                continue
            st = m.get("status")
            if st not in STATUSES:
                fails.append(f"row {i} {k} status {st!r} is not one of {list(STATUSES)}")
            elif st == "available" and m.get("value") is None:
                fails.append(f"row {i} {k} claims to be available but carries no value")
            elif st != "available" and m.get("value") is not None:
                fails.append(f"row {i} {k} is {st} yet carries a value -- an unread metric must "
                             f"not be filled in")
            if st in ("unavailable", "error") and not m.get("detail"):
                fails.append(f"row {i} {k} is {st} without a reason")

    # ---- lead-in and lead-out around the run ----
    marks = {m.get("name"): m for m in (doc.get("markers") or []) if isinstance(m, dict)}
    for want in require_markers:
        if want not in marks:
            fails.append(f"the trace records no {want!r} marker, so its lead-in/lead-out cannot "
                         f"be checked")
    if all(w in marks for w in require_markers) and len(require_markers) == 2:
        launch, cleanup = marks[require_markers[0]], marks[require_markers[1]]
        first, last = rows[0].get("scheduled_mono"), rows[-1].get("scheduled_mono")
        lm, cm = launch.get("mono"), cleanup.get("mono")
        if not all(isinstance(x, (int, float)) for x in (first, last, lm, cm)):
            fails.append("the markers or row times are not numeric, so the lead-in and lead-out "
                         "cannot be checked")
        else:
            if cm < lm:
                fails.append(f"{require_markers[1]!r} is before {require_markers[0]!r}")
            if lm - first < LEAD_IN_S:
                fails.append(f"the trace begins only {lm - first:.1f}s before "
                             f"{require_markers[0]}, less than the required {LEAD_IN_S}s")
            if last - cm < LEAD_OUT_S:
                fails.append(f"the trace ends only {last - cm:.1f}s after "
                             f"{require_markers[1]}, less than the required {LEAD_OUT_S}s")
    return fails


def _wrap(arg):
    """Trace AROUND a command: lead-in, launch, the command, cleanup, lead-out.

    The command's exit status and the trace's structural status are reported separately and are
    never combined. A failed trace does not condemn the run it observed, and -- just as important
    -- it does not authorise re-running it either. Nothing here retries anything."""
    out, cmd = arg["--out"], arg["--wrap"]
    lead = float(arg.get("--lead", LEAD_IN_S))
    tr = EnvTrace(out, interval_s=float(arg.get("--interval", INTERVAL_S)),
                  label=arg.get("--label") or cmd[:120]).start()
    rc = None
    try:
        _wait_for_slot(tr, tr.t0_mono + lead)
        tr.mark("launch")
        print(f"[env_trace] lead-in complete, launching: {cmd}", flush=True)
        rc = subprocess.call(cmd, shell=True)
        tr.mark("cleanup")
        print(f"[env_trace] command exited {rc}; holding for the {lead:.0f}s lead-out",
              flush=True)
        _wait_for_slot(tr, tr.markers[-1]["mono"] + lead)
    finally:
        tr.stop()
    doc = json.load(open(out, encoding="utf-8"))
    fails = verify_trace(doc)
    print(f"[env_trace] {doc['row_count']} rows -> {out}")
    for f in fails[:10]:
        print(f"  ! {f}")
    print(f"[env_trace] TRACE STRUCTURE: {'PASS' if not fails else f'FAIL ({len(fails)})'}")
    print(f"[env_trace] WRAPPED COMMAND EXIT: {rc}")
    print("[env_trace] these two verdicts are independent: the trace neither validates nor "
          "invalidates the command, and never authorises a rerun.")
    return rc if rc is not None else 1


def _wait_for_slot(tr, target_mono, grace_s=120.0):
    """Block until a row SCHEDULED at or after target_mono has been taken."""
    deadline = time.monotonic() + (target_mono - time.monotonic()) + grace_s
    while time.monotonic() < deadline:
        with tr.lock:
            last = tr.rows[-1]["scheduled_mono"] if tr.rows else float("-inf")
        if last >= target_mono:
            return True
        time.sleep(0.2)
    return False


def main(argv):
    arg = {a.split("=", 1)[0]: a.split("=", 1)[1] for a in argv if "=" in a}
    if "--verify" in arg:
        fails = verify_trace(arg["--verify"])
        for f in fails:
            print(f"  ! {f}")
        print(f"{'PASS' if not fails else 'FAIL'}: {arg['--verify']} "
              f"({len(fails)} structural failure(s))")
        return 0 if not fails else 1
    out = arg.get("--out")
    if not out:
        print(__doc__)
        return 2
    if "--wrap" in arg:
        return _wrap(arg)
    seconds = float(arg.get("--seconds", 90))
    tr = EnvTrace(out, interval_s=float(arg.get("--interval", INTERVAL_S)),
                  label=arg.get("--label")).start()
    _wait_for_slot(tr, tr.t0_mono + float(arg.get("--lead", LEAD_IN_S)))
    lead = float(arg.get("--lead", LEAD_IN_S))
    try:
        # the gate is on SCHEDULED row times, not on wall-clock sleeps: stopping the tracer the
        # instant the lead-out sleep ends leaves the last scheduled row short of the requirement
        tr.mark("launch")
        _wait_for_slot(tr, tr.markers[-1]["mono"] + max(0.0, seconds))
        tr.mark("cleanup")
        _wait_for_slot(tr, tr.markers[-1]["mono"] + lead)
    finally:
        tr.stop()
    doc = json.load(open(out, encoding="utf-8"))
    fails = verify_trace(doc)
    print(f"{doc['row_count']} rows -> {out}")
    for f in fails[:10]:
        print(f"  ! {f}")
    print("STRUCTURE:", "PASS" if not fails else f"FAIL ({len(fails)})")
    return 0 if not fails else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
