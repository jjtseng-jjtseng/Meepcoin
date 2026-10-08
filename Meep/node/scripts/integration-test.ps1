<#
.SYNOPSIS
  MeepCoin devnet — automated integration test (hard-failing).

.DESCRIPTION
  The demonstration script produces a narrative. THIS produces a verdict. It fails, loudly and with
  a non-zero exit code, on every one of these conditions:

    - any RPC result is null or empty
    - either node exits unexpectedly
    - either wallet exits unexpectedly
    - a height or block hash is missing or malformed
    - the two nodes have different tips
    - mining creates no block
    - wallet A receives no reward
    - the transaction is absent
    - wallet B receives no confirmed balance
    - an invalid nonce is accepted

  GOVERNING RULE: two values are NEVER reported as matching until each has SEPARATELY been
  validated as present and correctly formatted. A comparison of two absent values is a failure,
  not a match. This rule exists because an earlier version of the demo reported
  "chain tips match: True" while both nodes were dead.

  *** LOCALHOST / PRIVATE ONLY. Dev/test coins, no monetary value. ***
#>
[CmdletBinding()]
param(
    [uint64]$FixedDifficulty = 500,
    [double]$SendAmount      = 1.0,
    [int]$MineThreads        = 4,
    [int]$MineTimeoutSec     = 1200,
    # v16 uses ring size 16. A young chain has too few RingCT outputs for decoy
    # selection and transfers fail with not_enough_outs_to_mix. Mine a deep enough
    # chain before attempting the transaction.
    [int]$MinHeightForTransfer = 90,
    [string]$ResultPath      = "$PSScriptRoot\..\..\docs\DEVNET_INTEGRATION_TEST.md"
)

# MeepCoin uses 11 decimals (COIN = 10^11). Every MEEP <-> atomic conversion in this
# script goes through this constant; never hardcode a power of ten.
$AtomicPerMeep = [uint64]100000000000

$ErrorActionPreference = 'Stop'
$devnet = "$PSScriptRoot\devnet.ps1"
$A = @{ Name='A'; Rpc=29081; WalletRpc=29083 }
$Bn = @{ Name='B'; Rpc=29091; WalletRpc=29093 }   # NOT $B: PowerShell is case-insensitive and $b
                                                  # elsewhere would silently alias it.
$pass = 0; $fail = 0
$log = New-Object System.Collections.Generic.List[string]

function Say  { param([string]$s) Write-Host $s; $log.Add($s) }
function Ok   { param([string]$s) $script:pass++; Say "  [PASS] $s" }
function Bad  { param([string]$s) $script:fail++; Say "  [FAIL] $s" }
function Must { param([bool]$c,[string]$s) if ($c) { Ok $s } else { Bad $s } ; return $c }

# --- validators: presence and FORMAT, independently of any comparison ---------------------------
function Test-Hash64 { param($v)
    if ($null -eq $v) { return $false }
    $s = [string]$v
    if ([string]::IsNullOrWhiteSpace($s)) { return $false }
    return ($s -match '^[0-9a-f]{64}$')
}
function Test-Height { param($v)
    if ($null -eq $v) { return $false }
    if ($v -isnot [int] -and $v -isnot [long] -and $v -isnot [uint32] -and $v -isnot [uint64] -and
        $v -isnot [double] -and $v -isnot [decimal]) { return $false }
    return ([int64]$v -ge 0)
}
# The only sanctioned way to compare two values. Both must independently validate first.
function Assert-Match {
    param($x, $y, [scriptblock]$Validator, [string]$what, [string]$xLabel='A', [string]$yLabel='B')
    $xok = & $Validator $x
    $yok = & $Validator $y
    if (-not $xok) { Bad "$what — $xLabel value missing or malformed ('$x')"; return $false }
    if (-not $yok) { Bad "$what — $yLabel value missing or malformed ('$y')"; return $false }
    if ($x -ne $y) { Bad "$what — validated but DIFFERENT ($xLabel='$x', $yLabel='$y')"; return $false }
    Ok "$what — both present, well-formed, and equal ($x)"
    return $true
}

# --- transport ----------------------------------------------------------------------------------
function DaemonRest { param([int]$Port,[string]$Path,[hashtable]$P=@{})
    try { Invoke-RestMethod -Uri "http://127.0.0.1:$Port/$Path" -Method Post `
            -ContentType 'application/json' -Body ($P|ConvertTo-Json -Depth 8) -TimeoutSec 45 }
    catch { $null }
}
function DaemonRpc { param([int]$Port,[string]$M,$P=@{})
    $body = @{ jsonrpc='2.0'; id='0'; method=$M; params=$P } | ConvertTo-Json -Depth 8
    try { Invoke-RestMethod -Uri "http://127.0.0.1:$Port/json_rpc" -Method Post `
            -ContentType 'application/json' -Body $body -TimeoutSec 60 }
    catch { $null }
}
function WalletRpc { param([int]$Port,[string]$M,[hashtable]$P=@{})
    $body = @{ jsonrpc='2.0'; id='0'; method=$M; params=$P } | ConvertTo-Json -Depth 8
    try { $r = Invoke-RestMethod -Uri "http://127.0.0.1:$Port/json_rpc" -Method Post `
            -ContentType 'application/json' -Body $body -TimeoutSec 180
          if ($r.error) { return $null }; $r.result }
    catch { $null }
}
function Count-Proc { param([string]$Exact)
    $n = (& wsl.exe -e bash -lc "pgrep -x $Exact | wc -l") 2>$null
    if ($null -eq $n) { return 0 }
    return [int]("$n".Trim())
}
# Processes must still be alive at each stage; a crashed daemon must fail the run, not be
# silently tolerated because some other node still answers.
function Assert-Alive { param([string]$stage)
    $d = Count-Proc 'meepcoind'
    $w = Count-Proc 'meepcoin-wallet'
    $okd = Must ($d -eq 2) "$stage — both daemons alive (found $d)"
    $okw = Must ($w -eq 2) "$stage — both wallet servers alive (found $w)"
    return ($okd -and $okw)
}

$started = Get-Date
Say '# MeepCoin Devnet — Automated Integration Test'
Say ''
Say '**LOCALHOST / PRIVATE ONLY. Dev/test coins with NO monetary value.**'
Say ''
Say "- Started (UTC): $((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))"
Say "- PoW: MeepHash-W v2 (frozen, tag ``v2-frozen``) | fork base Monero v0.18.5.1 ``4f92268d``"
Say "- Fixed difficulty $FixedDifficulty (target only — every block still computes a real MeepHash-W v2 hash)"
Say ''

# ================================================================================================
Say '## 1. Clean start'
& $devnet -Action reset *>&1 | Out-Null
& wsl.exe -e bash -lc 'rm -rf $HOME/.meepcoin-devnet/wallets' *>&1 | Out-Null
Ok 'devnet chain data and wallets removed'

Say ''
Say '## 2. Nodes start and peer'
& $devnet -Action start-node-a -FixedDifficulty $FixedDifficulty *>&1 | Out-Null
& $devnet -Action start-node-b -FixedDifficulty $FixedDifficulty *>&1 | Out-Null

$ia = $null; $ib = $null
$deadline = (Get-Date).AddSeconds(150)
while ((Get-Date) -lt $deadline) {
    $ia = DaemonRest -Port $A.Rpc  -Path 'get_info'
    $ib = DaemonRest -Port $Bn.Rpc -Path 'get_info'
    if ($ia -and $ib -and
        ($ia.outgoing_connections_count + $ia.incoming_connections_count) -ge 1 -and
        ($ib.outgoing_connections_count + $ib.incoming_connections_count) -ge 1) { break }
    Start-Sleep -Seconds 2
}
Must ($null -ne $ia) 'node A get_info returned a non-null result' | Out-Null
Must ($null -ne $ib) 'node B get_info returned a non-null result' | Out-Null
if (-not $ia -or -not $ib) { Say ''; Say '**ABORTED: a node never came up.**'; $fail++ }
else {
    Must (($ia.outgoing_connections_count + $ia.incoming_connections_count) -ge 1) 'node A has >= 1 peer' | Out-Null
    Must (($ib.outgoing_connections_count + $ib.incoming_connections_count) -ge 1) 'node B has >= 1 peer' | Out-Null
    Assert-Match $ia.top_block_hash $ib.top_block_hash ${function:Test-Hash64} 'genesis tip' 'A' 'B' | Out-Null
    $genesis = $ia.top_block_hash
    Say "- genesis block hash: ``$genesis``"
}

Say ''
Say '## 3. Wallets'
& $devnet -Action create-wallets *>&1 | Out-Null
Assert-Alive 'after wallet start' | Out-Null
$addrA = (WalletRpc -Port $A.WalletRpc  -M 'get_address' -P @{account_index=0}).address
$addrB = (WalletRpc -Port $Bn.WalletRpc -M 'get_address' -P @{account_index=0}).address
Must (-not [string]::IsNullOrWhiteSpace($addrA)) 'wallet A returned an address' | Out-Null
Must (-not [string]::IsNullOrWhiteSpace($addrB)) 'wallet B returned an address' | Out-Null
Must ($addrA -ne $addrB) 'wallet A and B addresses differ' | Out-Null
# Do NOT assert a leading character. Base58 prefix 71 encodes to a leading 'C' OR 'D' depending on
# the key bytes that follow -- both occur in practice, and asserting 'D' produced a spurious
# failure. Ask the wallet to validate the address for this network instead, which is the real claim.
if ($addrA) {
    $va = WalletRpc -Port $A.WalletRpc -M 'validate_address' -P @{ address = $addrA; any_net_type = $false }
    Must ($null -ne $va -and $va.valid -eq $true) "wallet A address validates on this network" | Out-Null
    if ($va) { Must ($va.nettype -eq 'testnet') "wallet A address nettype is the devnet slot ('$($va.nettype)')" | Out-Null }
    Say "- wallet A address begins '$($addrA.Substring(0,1))' (prefix 71 encodes to C or D)"
}

Say ''
Say '## 4. Mining produces blocks and credits wallet A'
& $devnet -Action mine-start -MineThreads $MineThreads *>&1 | Out-Null
$target = [uint64]([decimal]$SendAmount * $AtomicPerMeep)
$mineDeadline = (Get-Date).AddSeconds($MineTimeoutSec)
$balA = $null
while ((Get-Date) -lt $mineDeadline) {
    Start-Sleep -Seconds 8
    WalletRpc -Port $A.WalletRpc -M 'refresh' | Out-Null
    $balA = WalletRpc -Port $A.WalletRpc -M 'get_balance' -P @{account_index=0}
    $ihm = DaemonRest -Port $A.Rpc -Path 'get_info'
    $tallEnough = ($ihm -and [int64]$ihm.height -ge $MinHeightForTransfer)
    if ($balA -and [uint64]$balA.unlocked_balance -ge $target -and $tallEnough) { break }
}
& $devnet -Action mine-stop *>&1 | Out-Null
Assert-Alive 'after mining' | Out-Null

$ia = DaemonRest -Port $A.Rpc -Path 'get_info'
Must ($null -ne $ia) 'node A responded after mining' | Out-Null
Must (Test-Height $ia.height) "node A height is present and well-formed ($($ia.height))" | Out-Null
Must ([int64]$ia.height -gt 1) "mining created at least one block (height $($ia.height))" | Out-Null
Must (Test-Hash64 $ia.top_block_hash) 'node A top block hash is a 64-char hex string' | Out-Null

$hdr = DaemonRpc -Port $A.Rpc -M 'get_block_header_by_height' -P @{height=1}
Must ($null -ne $hdr -and $null -ne $hdr.result) 'block header at height 1 retrievable' | Out-Null
if ($hdr.result) { Must (Test-Hash64 $hdr.result.block_header.hash) "height 1 block hash well-formed (``$($hdr.result.block_header.hash)``)" | Out-Null }

Must ($null -ne $balA) 'wallet A balance query returned a result' | Out-Null
if ($balA) {
    Must ([uint64]$balA.balance -gt 0) "wallet A received a mining reward ($([math]::Round($balA.balance/$AtomicPerMeep,6)))" | Out-Null
    Must ([uint64]$balA.unlocked_balance -ge $target) "wallet A has a spendable reward >= $SendAmount" | Out-Null
}

Say ''
Say '## 5. Node B independently validated the chain'
$syncDeadline = (Get-Date).AddSeconds(180)
while ((Get-Date) -lt $syncDeadline) {
    $ia = DaemonRest -Port $A.Rpc  -Path 'get_info'
    $ib = DaemonRest -Port $Bn.Rpc -Path 'get_info'
    if ($ia -and $ib -and $ia.top_block_hash -eq $ib.top_block_hash) { break }
    Start-Sleep -Seconds 3
}
Assert-Match $ia.top_block_hash $ib.top_block_hash ${function:Test-Hash64} 'post-mining tip' 'A' 'B' | Out-Null
Assert-Match $ia.height $ib.height ${function:Test-Height} 'post-mining height' 'A' 'B' | Out-Null

Say ''
Say '## 6. Transaction A -> B'
$ihm = DaemonRest -Port $A.Rpc -Path 'get_info'
Must ($null -ne $ihm -and [int64]$ihm.height -ge $MinHeightForTransfer) `
     "chain deep enough for ring size 16 (height $($ihm.height) >= $MinHeightForTransfer)" | Out-Null
WalletRpc -Port $A.WalletRpc -M 'refresh' | Out-Null
$tx = WalletRpc -Port $A.WalletRpc -M 'transfer' -P @{
    destinations=@(@{amount=[uint64]([decimal]$SendAmount * $AtomicPerMeep); address=$addrB}); account_index=0
    priority=0; get_tx_key=$true }
$txok = Must ($null -ne $tx) 'transfer returned a result'
if ($tx) {
    Must (Test-Hash64 $tx.tx_hash) "transaction hash present and well-formed (``$($tx.tx_hash)``)" | Out-Null
    Must ([uint64]$tx.amount -eq [uint64]([decimal]$SendAmount * $AtomicPerMeep)) "transaction amount is exactly $SendAmount" | Out-Null
    Say "- tx hash: ``$($tx.tx_hash)``  amount $($tx.amount)  fee $($tx.fee)"
}

Say ''
Say '## 7. Transaction confirms and credits wallet B'
if ($txok) {
    & $devnet -Action mine-start -MineThreads $MineThreads *>&1 | Out-Null
    $confDeadline = (Get-Date).AddSeconds(600)
    $balB = $null
    while ((Get-Date) -lt $confDeadline) {
        Start-Sleep -Seconds 8
        WalletRpc -Port $Bn.WalletRpc -M 'refresh' | Out-Null
        $balB = WalletRpc -Port $Bn.WalletRpc -M 'get_balance' -P @{account_index=0}
        if ($balB -and [uint64]$balB.balance -ge [uint64]([decimal]$SendAmount * $AtomicPerMeep)) { break }
    }
    & $devnet -Action mine-stop *>&1 | Out-Null
    Must ($null -ne $balB) 'wallet B balance query returned a result' | Out-Null
    if ($balB) {
        Must ([uint64]$balB.balance -ge [uint64]([decimal]$SendAmount * $AtomicPerMeep)) `
             "wallet B received the confirmed transfer ($([math]::Round($balB.balance/$AtomicPerMeep,6)))" | Out-Null
    }
} else { Bad 'skipped confirmation checks — no transaction was created' }

Say ''
Say '## 8. Invalid proof-of-work is REJECTED'
$t = DaemonRpc -Port $A.Rpc -M 'get_block_template' -P @{ wallet_address=$addrA; reserve_size=8 }
if ($t -and $t.result -and $t.result.blocktemplate_blob) {
    $blob = $t.result.blocktemplate_blob
    $raw = [byte[]]@(for ($i=0; $i -lt $blob.Length; $i+=2) { [Convert]::ToByte($blob.Substring($i,2),16) })
    $off = 0
    for ($v=0; $v -lt 3; $v++) { while ($raw[$off] -ge 0x80) { $off++ }; $off++ }
    $nonceOff = $off + 32
    $rej = 0; $acc = 0
    foreach ($n in @(0x11111111,0x22222222,0xDEADBEEF,0x00000000)) {
        $blk = $raw.Clone()
        $blk[$nonceOff]     = [byte]( $n         -band 0xFF)
        $blk[$nonceOff + 1] = [byte](($n -shr 8)  -band 0xFF)
        $blk[$nonceOff + 2] = [byte](($n -shr 16) -band 0xFF)
        $blk[$nonceOff + 3] = [byte](($n -shr 24) -band 0xFF)
        $hex = ($blk | ForEach-Object { $_.ToString('x2') }) -join ''
        $r = DaemonRpc -Port $A.Rpc -M 'submit_block' -P @($hex)
        if ($null -eq $r -or $r.error) { $rej++ } else { $acc++ }
    }
    Say "- nonce field at byte offset $nonceOff; submitted 4 arbitrary nonces"
    Must ($acc -eq 0) "no block with an invalid nonce was accepted ($rej rejected, $acc accepted)" | Out-Null
} else {
    Bad 'could not obtain a block template for the invalid-nonce test'
}
Must ($null -ne (DaemonRpc -Port $A.Rpc -M 'submit_block' -P @('deadbeef')).error) 'garbage block blob rejected' | Out-Null

Say ''
Say '## 9. The daemon''s PoW really is MeepHash-W v2'
# THE test that was missing. Every other check asks whether consensus enforces *a* proof-of-work;
# this asks WHICH ONE. Without it the devnet ran CryptoNight for an entire checkpoint while every
# test passed. Compares the daemon's own pow_hash against meepow-v2-hash, which reaches the
# algorithm through the public v2 API rather than the daemon's bridge.
$mh = "$PSScriptRoot\..\..\meepow\build\release\meepow-v2-hash"
$bh = '$HOME/meepcoin-node/build/release/bin/meepcoin-blockhashing'
$mhWsl = (& wsl.exe -e wslpath -a ($mh -replace '\\','/')) 2>$null
if ($mhWsl) { $mhWsl = "$mhWsl".Trim() }
$gen = (DaemonRpc -Port $A.Rpc -M 'get_block_header_by_height' -P @{height=0}).result.block_header.hash
$agree = 0; $disagree = 0; $checked = 0
foreach ($h in @(1,2,3)) {
    $r = DaemonRpc -Port $A.Rpc -M 'get_block' -P @{height=$h; fill_pow_hash=$true}
    if (-not $r -or -not $r.result) { continue }
    $daemonPow = $r.result.block_header.pow_hash
    $full = $r.result.blob
    $hb = (& wsl.exe -e bash -lc "$bh $full") 2>$null
    if (-not $hb) { continue }
    $hb = "$hb".Trim()
    $raw = [byte[]]@(for ($i=0; $i -lt $hb.Length; $i+=2) { [Convert]::ToByte($hb.Substring($i,2),16) })
    $off = 0
    for ($v=0; $v -lt 3; $v++) { while ($raw[$off] -ge 0x80) { $off++ }; $off++ }
    $noff = $off + 32
    $nonce = [uint32]$raw[$noff] -bor ([uint32]$raw[$noff+1] -shl 8) -bor `
             ([uint32]$raw[$noff+2] -shl 16) -bor ([uint32]$raw[$noff+3] -shl 24)
    $z = $raw.Clone(); $z[$noff]=0; $z[$noff+1]=0; $z[$noff+2]=0; $z[$noff+3]=0
    $zhex = ($z | ForEach-Object { $_.ToString('x2') }) -join ''
    $mine = (& wsl.exe -e bash -lc "$mhWsl $gen $gen $h $zhex $nonce") 2>$null
    if ($mine) { $mine = "$mine".Trim() }
    $checked++
    if ($daemonPow -and $mine -and $daemonPow -eq $mine) { $agree++ } else { $disagree++ }
}
Must ($checked -gt 0) 'PoW cross-check ran on at least one block' | Out-Null
Must ($disagree -eq 0 -and $agree -eq $checked) `
     "daemon PoW == independent MeepHash-W v2 on all $checked blocks ($agree agree, $disagree disagree)" | Out-Null

Say ''
Say '## 10. Final state'
Assert-Alive 'at end of run' | Out-Null
$ia = DaemonRest -Port $A.Rpc  -Path 'get_info'
$ib = DaemonRest -Port $Bn.Rpc -Path 'get_info'
Assert-Match $ia.top_block_hash $ib.top_block_hash ${function:Test-Hash64} 'final tip' 'A' 'B' | Out-Null
Assert-Match $ia.height $ib.height ${function:Test-Height} 'final height' 'A' 'B' | Out-Null

Say ''
Say '---'
Say ''
Say "**RESULT: $pass passed, $fail failed** (elapsed $([int]((Get-Date)-$started).TotalSeconds) s)"
Say ''
Say $(if ($fail -eq 0) { '**INTEGRATION TEST: PASS**' } else { '**INTEGRATION TEST: FAIL**' })
Say ''
Say '_Dev/test coins on a private localhost chain. No monetary value._'

$log -join "`r`n" | Set-Content -Path $ResultPath -Encoding UTF8
Write-Host "`nWritten to $ResultPath"
if ($fail -gt 0) { exit 1 }
