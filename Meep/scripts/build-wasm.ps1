# Build the Wasm module from Windows by delegating to WSL (which has the pinned emsdk).
# Usage: powershell -File scripts/build-wasm.ps1
#
# Checkout-relative: the repository root is derived from this script's own location, so the
# wrapper works from any clone path and for any user. Nothing here is hard-coded to one machine.
$ErrorActionPreference = "Stop"

# scripts/ -> repository root
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path

$ShellScript = Join-Path $PSScriptRoot "build-wasm.sh"
if (-not (Test-Path -LiteralPath $ShellScript)) {
    throw "expected sibling build script not found: $ShellScript"
}

# Translate the Windows path to the WSL mount point (C:\foo\bar -> /mnt/c/foo/bar). wslpath is
# authoritative when available; the manual conversion is a fallback for drive-letter paths.
$WslRoot = $null
try {
    $WslRoot = (& wsl -e wslpath -a "$RepoRoot" 2>$null | Select-Object -First 1)
} catch {
    $WslRoot = $null
}
if ([string]::IsNullOrWhiteSpace($WslRoot)) {
    if ($RepoRoot -notmatch '^([A-Za-z]):\\(.*)$') {
        throw "cannot convert '$RepoRoot' to a WSL path; run scripts/build-wasm.sh from WSL instead"
    }
    $Drive = $Matches[1].ToLower()
    $Rest = $Matches[2] -replace '\\', '/'
    $WslRoot = "/mnt/$Drive/$Rest"
}
$WslRoot = $WslRoot.Trim()

Write-Host "repository (Windows): $RepoRoot"
Write-Host "repository (WSL)    : $WslRoot"

if ($env:MEEP_BUILD_WASM_DRY_RUN -eq "1") {
    # Path-resolution check only: prove the wrapper found the repository and the sibling script
    # without starting a real Emscripten build.
    Write-Host "DRY RUN: would run  wsl.exe --cd <repo> --exec bash scripts/build-wasm.sh"
    Write-Host "         working directory: $WslRoot"
    Write-Host "         (dry run exits before the WSL launch, so it does not prove quoting)"
    exit 0
}

# ARGUMENT-NATIVE LAUNCH. The repository path is passed to wsl.exe as its own argument and the
# build script is exec'd directly -- there is no inner shell program string, so nothing re-parses
# the path.
#
# The previous form was `wsl -e bash -lc 'cd "$1" && bash scripts/build-wasm.sh' bash "$WslRoot"`.
# Its quoting is correct under PowerShell 7, but Windows PowerShell 5.1 rewrites the arguments it
# hands to a native executable and strips the inner quotes, so a path containing a space arrived
# as two words and Bash reported `cd: too many arguments` (exit 2). This file documents
# `powershell -File ...`, which is 5.1 on most machines, so the nested-shell form had to go.
wsl.exe --cd "$WslRoot" --exec bash scripts/build-wasm.sh
if ($LASTEXITCODE -ne 0) { throw "WSL build failed with exit code $LASTEXITCODE" }

Write-Host ""
Write-Host "Built. Now confirm the artifacts against the frozen v2 vectors and the pinned identity:"
Write-Host "  node meepow/wasm/v2_regress.mjs"
Write-Host "  node --test `"pool/dev/tests/identity.test.mjs`""
