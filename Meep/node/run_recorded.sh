#!/usr/bin/env bash
# Run a command with its evidence recorded persistently, on the Windows-mounted repo.
#
# /tmp is NOT used as a store: a WSL restart wiped /tmp mid-checkpoint once already and destroyed
# the per-target fuzz logs. Everything here lands under results/ inside the git repo, output is
# streamed incrementally (tee, line-buffered) so a crash or restart keeps whatever was produced,
# and a manifest is written BEFORE the command starts and completed after it exits.
#
# Usage: run_recorded.sh <run-name> <command...>
#
# Produces results/<UTC-timestamp>__<run-name>/
#   manifest.json   start/end, commit, tree state, toolchain, sanitizers, exit status, command
#   stdout.log      streamed incrementally
#   SHA256SUMS      hashes of every final raw output
set -u

REPO=/mnt/c/Users/tseng/meepcoin
NAME=${1:?usage: run_recorded.sh <run-name> <command...>}
shift

TS=$(date -u +%Y%m%dT%H%M%SZ)
DIR="$REPO/results/${TS}__${NAME}"
mkdir -p "$DIR"

COMMIT=$(git -C "$REPO" rev-parse HEAD 2>/dev/null || echo unknown)
BRANCH=$(git -C "$REPO" rev-parse --abbrev-ref HEAD 2>/dev/null || echo unknown)
DIRTY=$(git -C "$REPO" status --porcelain 2>/dev/null | wc -l)
FROZEN=$(git -C "$REPO" rev-parse v16-economics-freeze^{commit} 2>/dev/null || echo unknown)

# Written BEFORE the run, so an interrupted run still has provenance.
cat > "$DIR/manifest.json" <<EOF
{
  "run_name": "$NAME",
  "start_utc": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "end_utc": null,
  "exit_status": null,
  "status": "RUNNING",
  "commit": "$COMMIT",
  "branch": "$BRANCH",
  "uncommitted_files": $DIRTY,
  "frozen_tag_commit": "$FROZEN",
  "command": $(printf '%s\n' "$*" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read().strip()))'),
  "host": {
    "uname": "$(uname -sr)",
    "cpus": $(nproc),
    "mem_kb": $(awk '/MemTotal/{print $2}' /proc/meminfo)
  },
  "toolchain": {
    "gcc": "$(gcc --version 2>/dev/null | head -1)",
    "clang": "$(clang --version 2>/dev/null | head -1)",
    "cmake": "$(cmake --version 2>/dev/null | head -1)",
    "python": "$(python3 --version 2>&1)"
  },
  "sanitizers": "none (release build) unless the command is a fuzz target; fuzz builds use -fsanitize=fuzzer,address,undefined"
}
EOF

echo "results dir: $DIR"
echo "commit: $COMMIT ($BRANCH, $DIRTY uncommitted)"
echo

START=$(date +%s)
# stdbuf keeps the stream line-buffered so partial output survives an abrupt stop.
stdbuf -oL -eL "$@" 2>&1 | tee "$DIR/stdout.log"
RC=${PIPESTATUS[0]}
END=$(date +%s)

( cd "$DIR" && sha256sum * 2>/dev/null > SHA256SUMS.tmp && mv SHA256SUMS.tmp SHA256SUMS )

python3 - "$DIR/manifest.json" "$RC" "$((END-START))" <<'PY'
import json, sys, datetime
p, rc, dur = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
m = json.load(open(p))
m["end_utc"] = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
m["exit_status"] = rc
m["duration_seconds"] = dur
m["status"] = "COMPLETED" if rc == 0 else "FAILED"
json.dump(m, open(p, "w"), indent=2)
print(f"\n[manifest] status={m['status']} exit={rc} duration={dur}s")
PY

echo "[evidence] $DIR"
ls -la "$DIR" | tail -n +2 | awk '{printf "  %8s  %s\n", $5, $9}'
exit $RC
