#!/usr/bin/env python3
"""Remove the hardcoded 12-decimal assumption from the PowerShell devnet scripts.

MeepCoin now uses 11 decimals (COIN = 10^11). Three scripts converted between MEEP and atomic units
with a literal 1e12 and formatted balances with N12:

    demo.ps1              7 occurrences
    devnet.ps1            3 occurrences
    integration-test.ps1  7 occurrences

Left alone, `-SendAmount 1.0` would have sent 10 MEEP while every message said 1, and the
integration test's "transaction amount is exactly 1" assertion would have passed on the wrong
amount. That is precisely the class of silent scale error the decimal audit was asked to rule out.

Each script gets one constant, and every conversion goes through it:

    $AtomicPerMeep = [uint64]100000000000   # 10^11 -- MeepCoin uses 11 decimals

Conversions use [decimal] rather than the double that `* 1e12` produced, so a fractional
-SendAmount cannot pick up binary floating-point error on the way to an integer atomic amount.

Idempotent.
"""
import os, re, sys

SCRIPTS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "scripts")
MARK = "$AtomicPerMeep"

# The constant is inserted after the param block / initial setup, before first use.
CONST = ("\n# MeepCoin uses 11 decimals (COIN = 10^11). Every MEEP <-> atomic conversion in this\n"
         "# script goes through this constant; never hardcode a power of ten.\n"
         "$AtomicPerMeep = [uint64]100000000000\n")

SUBS = [
    # atomic <- MEEP, via decimal so a fractional amount cannot pick up float error
    (r'\[uint64\]\(\$SendAmount\s*\*\s*1e12\)',
     '[uint64]([decimal]$SendAmount * $AtomicPerMeep)'),
    # MEEP <- atomic
    (r'/1e12', '/$AtomicPerMeep'),
    # display precision: 12 fractional digits -> 11
    (r'\{0:N12\}', '{0:N11}'),
    (r'\{1:N12\}', '{1:N11}'),
    (r'\{2:N12\}', '{2:N11}'),
]

total = 0
for name in ("demo.ps1", "devnet.ps1", "integration-test.ps1"):
    path = os.path.join(SCRIPTS, name)
    if not os.path.exists(path):
        print(f"! missing {name}")
        sys.exit(1)
    s = open(path, encoding="utf-8-sig").read()

    if MARK in s:
        print(f"= {name} already converted")
        continue

    n_here = 0
    for pat, rep in SUBS:
        s, n = re.subn(pat, rep, s)
        n_here += n

    if n_here == 0:
        print(f"! {name}: no 12-decimal occurrences found -- refusing to insert an unused constant")
        sys.exit(1)

    # Insert the constant at a top-level statement boundary. Inserting "just before first use"
    # is wrong: in devnet.ps1 the first use sits on the continuation line of a backtick-continued
    # Write-Host, and splitting that produced 9 parse errors.
    #
    # PowerShell requires param() to be the first statement, so when a param block exists the
    # constant goes after it; otherwise it goes after the leading <# ... #> header.
    lines = s.split("\n")
    insert_at = None

    for i, ln in enumerate(lines):
        if ln.strip().startswith("param("):
            depth = 0
            for j in range(i, len(lines)):
                depth += lines[j].count("(") - lines[j].count(")")
                if depth <= 0:
                    insert_at = j + 1
                    break
            break

    if insert_at is None:
        for i, ln in enumerate(lines):
            if ln.rstrip().endswith("#>"):
                insert_at = i + 1
                break

    if insert_at is None:
        print(f"! {name}: no safe insertion point (no param block, no <#...#> header)")
        sys.exit(1)

    lines[insert_at:insert_at] = ["", CONST.strip("\n")]
    s = "\n".join(lines)

    # Preserve the originals' encoding exactly: UTF-8, no BOM, CRLF line endings. These files
    # contain UTF-8 em-dashes, and a BOM-less file read by PowerShell 5.1 is decoded as ANSI, which
    # turns them into mojibake and breaks the parser. Run these scripts with pwsh (7+), not
    # powershell.exe (5.1).
    open(path, "w", encoding="utf-8", newline="\r\n").write(s)
    print(f"+ {name}: {n_here} occurrence(s) converted")
    total += n_here

print(f"\nconverted {total} occurrence(s)")

# Prove nothing was missed.
leftovers = []
for name in os.listdir(SCRIPTS):
    if not name.endswith(".ps1"):
        continue
    s = open(os.path.join(SCRIPTS, name), encoding="utf-8-sig").read()
    for pat in ("1e12", "N12", "1000000000000"):
        if pat in s:
            leftovers.append(f"{name}: {pat}")
if leftovers:
    print("! remaining 12-decimal patterns:")
    for l in leftovers:
        print("   " + l)
    sys.exit(1)
print("no 12-decimal patterns remain in any .ps1 script")

# Verify with PowerShell's own parser. Editing a script and not checking that it still parses is
# how an earlier revision of this script shipped 9 parse errors in devnet.ps1.
import subprocess
check = r'''
$bad = 0
foreach ($f in @("demo.ps1","devnet.ps1","integration-test.ps1")) {
  $p = Join-Path "C:\Users\tseng\meepcoin\node\scripts" $f
  $errs = $null
  [void][System.Management.Automation.Language.Parser]::ParseFile($p, [ref]$null, [ref]$errs)
  if ($errs.Count) {
    Write-Output ("PARSE-FAIL {0}: {1} error(s): {2}" -f $f, $errs.Count, $errs[0].Message)
    $bad++
  } else { Write-Output ("parses cleanly: {0}" -f $f) }
}
if ($bad) { exit 1 } else { exit 0 }
'''
r = subprocess.run(["pwsh.exe", "-NoProfile", "-Command", check],
                   capture_output=True, text=True)
print(r.stdout.strip())
if r.returncode != 0:
    print("! PowerShell parser rejected an edited script")
    sys.exit(1)

print("SCRIPT_DECIMALS_OK")
