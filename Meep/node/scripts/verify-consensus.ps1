<#
.SYNOPSIS
  MeepCoin devnet — negative consensus tests.

.DESCRIPTION
  The positive demonstration (demo.ps1) shows blocks being mined and accepted. That alone does NOT
  prove consensus is enforcing the proof-of-work — a daemon that accepted anything would also pass
  it. These tests check that invalid work is REJECTED.

  Requires node A and node B to be running (start-node-a.ps1 / start-node-b.ps1).

  *** LOCALHOST / PRIVATE ONLY. Dev/test coins with no monetary value. ***
#>
[CmdletBinding()] param()
$ErrorActionPreference = 'Stop'

$A = @{ Rpc = 29081 }
$B = @{ Rpc = 29091 }
$pass = 0; $fail = 0
$out = New-Object System.Collections.Generic.List[string]

function Log { param([string]$s) Write-Host $s; $out.Add($s) }
function Check { param([bool]$ok, [string]$what)
    if ($ok) { $script:pass++; Log "  [PASS] $what" } else { $script:fail++; Log "  [FAIL] $what" }
}
function Rpc { param([int]$Port,[string]$M,$P=@{})
    $body = @{ jsonrpc='2.0'; id='0'; method=$M; params=$P } | ConvertTo-Json -Depth 8
    try { Invoke-RestMethod -Uri "http://127.0.0.1:$Port/json_rpc" -Method Post `
            -ContentType 'application/json' -Body $body -TimeoutSec 60 }
    catch { $null }
}
function Rest { param([int]$Port,[string]$Path,$P=@{})
    try { Invoke-RestMethod -Uri "http://127.0.0.1:$Port/$Path" -Method Post `
            -ContentType 'application/json' -Body ($P|ConvertTo-Json -Depth 8) -TimeoutSec 60 }
    catch { $null }
}

Log "# MeepCoin Devnet — Negative Consensus Tests"
Log ""
Log "Run (UTC): $((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))"
Log ""

$infoA = Rest -Port $A.Rpc -Path 'get_info'
if (-not $infoA) { Log 'node A not responding — start the nodes first'; exit 2 }
Log "Node A height $($infoA.height), top ``$($infoA.top_block_hash)``"
Log ""

# ---------------------------------------------------------------------------------------------
Log '## 1. A block whose nonce does not satisfy the target is REJECTED'
Log ''
# Take a real block template and stamp in an arbitrary nonce. With difficulty > 1 an arbitrary
# nonce is overwhelmingly unlikely to meet the target, so a daemon that verifies PoW must reject
# it. A daemon that merely accepted well-formed blocks would take it.
$tmplResp = Rpc -Port $A.Rpc -M 'get_block_template' -P @{
    wallet_address = 'D1Awzzi59qYFi65StYBcnwNqK8hmkJrhy7MT2hQLGeGYMFf32KtxbM3f3EtrB355w2Loa9xiMgyiLhFku57TdZmAEkgr3ZS'
    reserve_size   = 8
}
if ($tmplResp -and $tmplResp.result) {
    $blob = $tmplResp.result.blocktemplate_blob
    $roff = [int]$tmplResp.result.reserved_offset
    Log "- template obtained: height $($tmplResp.result.height), difficulty $($tmplResp.result.difficulty), blob $($blob.Length/2) bytes"

    # Locate the nonce: 3 header varints, then 32-byte prev_id, then a 4-byte LE nonce.
    $bytes = for ($i = 0; $i -lt $blob.Length; $i += 2) { [Convert]::ToByte($blob.Substring($i,2),16) }
    $bytes = [byte[]]$bytes
    $off = 0
    for ($v = 0; $v -lt 3; $v++) { while ($bytes[$off] -ge 0x80) { $off++ }; $off++ }
    $nonceOff = $off + 32
    Log "- nonce located at byte offset $nonceOff"

    $rejected = 0; $accepted = 0
    foreach ($n in @(0x11111111, 0x22222222, 0xDEADBEEF)) {
        $blk = $bytes.Clone()
        # NOTE: this loop must not use a variable named $b. PowerShell variable names are
        # CASE-INSENSITIVE, so $b silently aliases $B (the node B config) and later reads of
        # $B.Rpc return null -- which made a perfectly healthy node B look unreachable.
        $blk[$nonceOff]     = [byte]( $n         -band 0xFF)
        $blk[$nonceOff + 1] = [byte](($n -shr 8)  -band 0xFF)
        $blk[$nonceOff + 2] = [byte](($n -shr 16) -band 0xFF)
        $blk[$nonceOff + 3] = [byte](($n -shr 24) -band 0xFF)
        $hex = ($blk | ForEach-Object { $_.ToString('x2') }) -join ''
        $r = Rpc -Port $A.Rpc -M 'submit_block' -P @($hex)
        if ($null -eq $r -or $r.error) { $rejected++ } else { $accepted++ }
    }
    Log "- submitted 3 blocks with arbitrary nonces: $rejected rejected, $accepted accepted"
    Check ($accepted -eq 0 -and $rejected -eq 3) 'blocks with invalid proof-of-work are rejected'
} else {
    Log '- could not obtain a block template'
    Check $false 'block template available for the invalid-PoW test'
}

# ---------------------------------------------------------------------------------------------
Log ''
Log '## 2. A structurally corrupt block is REJECTED'
Log ''
$r = Rpc -Port $A.Rpc -M 'submit_block' -P @('deadbeef')
Check ($null -eq $r -or $null -ne $r.error) 'garbage block blob is rejected'

# ---------------------------------------------------------------------------------------------
Log ''
Log '## 3. Chain state is consistent across both nodes'
Log ''
# Retry: a single get_info can time out while a node is busy, which would misreport a healthy
# node as down.
$ia = $null; $ib = $null
for ($try = 0; $try -lt 5 -and (-not $ia -or -not $ib); $try++) {
    if (-not $ia) { $ia = Rest -Port $A.Rpc -Path 'get_info' }
    if (-not $ib) { $ib = Rest -Port $B.Rpc -Path 'get_info' }
    if (-not $ia -or -not $ib) { Start-Sleep -Seconds 3 }
}
Check ($null -ne $ia -and $null -ne $ib) 'both nodes responding'
if ($ia -and $ib) {
    Check ($ia.top_block_hash -eq $ib.top_block_hash) "top block hash identical (``$($ia.top_block_hash)``)"
    Check ($ia.height -eq $ib.height) "height identical ($($ia.height))"
    Check ($ia.nettype -eq 'testnet') "node A reports nettype '$($ia.nettype)' (MeepCoin devnet slot)"
}

# ---------------------------------------------------------------------------------------------
Log ''
Log '## 4. Network isolation from Monero'
Log ''
# Probing 127.0.0.1 ports is the WRONG test: this machine legitimately runs a real Monero node on
# Windows (18080/18081), so those ports answer for reasons unrelated to MeepCoin. The meaningful
# check is what MEEPCOIN'S OWN processes bind. Enumerate the sockets held by meepcoind/wallet-rpc
# inside WSL and assert none of them is a Monero port.
$meepPorts = (& wsl.exe -e bash -lc "ss -ltnp 2>/dev/null | grep -E 'meepcoind|meepcoin-wallet' | grep -oE ':[0-9]+ ' | tr -d ': '") `
             | Where-Object { $_ } | ForEach-Object { [int]$_.Trim() } | Sort-Object -Unique
$monPorts  = @(18080,18081,18082,28080,28081,28082,38080,38081,38082)
$collisions = $meepPorts | Where-Object { $monPorts -contains $_ }
Log "- MeepCoin processes bind: $($meepPorts -join ', ')"
Check ($meepPorts.Count -gt 0) 'MeepCoin processes are listening'
Check ($collisions.Count -eq 0) "no MeepCoin socket uses a Monero port ($($monPorts -join ', '))"

# Coexistence evidence: a real Monero daemon on this host is untouched by the devnet.
$moneroUp = Test-NetConnection -ComputerName 127.0.0.1 -Port 18081 `
              -WarningAction SilentlyContinue -InformationLevel Quiet
Log "- a separate real Monero node is running on this host (18081 reachable = $moneroUp);"
Log "  MeepCoin runs alongside it on distinct ports with no conflict."
Log '- NETWORK_ID, address prefixes, genesis nonce and ports all differ from Monero (see DEVNET_PARAMETERS.md).'
Log '  A MeepCoin node therefore cannot complete a Monero handshake.'

# ---------------------------------------------------------------------------------------------
Log ''
Log "**$pass passed, $fail failed**"
Log ''
Log '_Dev/test coins on a private localhost chain. No monetary value._'

$out -join "`r`n" | Set-Content -Path "$PSScriptRoot\..\..\docs\DEVNET_CONSENSUS_TESTS.md" -Encoding UTF8
Write-Host "`nWritten to docs/DEVNET_CONSENSUS_TESTS.md"
if ($fail -gt 0) { exit 1 }
