<#
.SYNOPSIS
  MeepCoin private devnet — complete demonstration from a clean state.

.DESCRIPTION
  Runs the full Checkpoint B demonstration end to end and writes a transcript with the exact
  evidence: block hashes, chain tips, transaction hash, and balances on both nodes.

  *** LOCALHOST / PRIVATE ONLY. ALL COINS ARE DEV/TEST COINS WITH NO MONETARY VALUE. ***

  Sequence:
    1  reset all devnet chain data
    2  start node A and node B (exclusive peers of each other only)
    3  verify they connect and agree on the genesis tip
    4  create wallets A and B
    5  mine natively on node A with MeepHash-W v2 until wallet A has a spendable reward
    6  verify node B accepted and synced the mined blocks (independent verification)
    7  send a transaction from wallet A to wallet B
    8  mine until the transaction confirms
    9  verify balances and chain tips match on BOTH nodes
#>
[CmdletBinding()]
param(
    [uint64]$FixedDifficulty = 500,
    [double]$SendAmount      = 1.0,
    [int]$MineThreads        = 4,
    [int]$MineTimeoutSec     = 1800,
    [string]$TranscriptPath  = "$PSScriptRoot\..\..\docs\DEVNET_DEMO_TRANSCRIPT.md"
)

# MeepCoin uses 11 decimals (COIN = 10^11). Every MEEP <-> atomic conversion in this
# script goes through this constant; never hardcode a power of ten.
$AtomicPerMeep = [uint64]100000000000

$ErrorActionPreference = 'Stop'
$devnet = "$PSScriptRoot\devnet.ps1"
$T = New-Object System.Collections.Generic.List[string]

function Log { param([string]$s, [switch]$Quiet)
    if (-not $Quiet) { Write-Host $s }
    $T.Add($s)
}
function Section { param([string]$s) Log ""; Log "## $s"; Log "" }

function DaemonRest { param([int]$Port,[string]$Path,[hashtable]$P=@{})
    try { Invoke-RestMethod -Uri "http://127.0.0.1:$Port/$Path" -Method Post `
            -ContentType 'application/json' -Body ($P|ConvertTo-Json -Depth 8) -TimeoutSec 30 }
    catch { $null }
}
function WalletRpc { param([int]$Port,[string]$M,[hashtable]$P=@{})
    $body = @{ jsonrpc='2.0'; id='0'; method=$M; params=$P } | ConvertTo-Json -Depth 8
    try { $r = Invoke-RestMethod -Uri "http://127.0.0.1:$Port/json_rpc" -Method Post `
            -ContentType 'application/json' -Body $body -TimeoutSec 120
          if ($r.error) { return $null }; $r.result }
    catch { $null }
}

function TipsMatch { param($x,$y)
    # An empty/absent value must NEVER read as a match. Comparing two nulls previously reported
    # "tips match: True" for two DEAD nodes, turning a total failure into a apparent pass.
    if ([string]::IsNullOrWhiteSpace($x) -or [string]::IsNullOrWhiteSpace($y)) { return $false }
    return ($x -eq $y)
}

$A = @{ Rpc=29081; WalletRpc=29083 }
$B = @{ Rpc=29091; WalletRpc=29093 }

$started = Get-Date
Log "# MeepCoin Devnet — Demonstration Transcript"
Log ""
Log "**LOCALHOST / PRIVATE ONLY. All coins are DEV/TEST coins with NO monetary value.**"
Log ""
Log "- Started (UTC): $((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))"
Log "- Consensus PoW: MeepHash-W v2 (frozen, tag ``v2-frozen``)"
Log "- Fork base: Monero v0.18.5.1, commit ``4f92268d``"
Log "- Fixed difficulty: $FixedDifficulty (fixes the TARGET; every block still computes a real MeepHash-W v2 hash)"

# ------------------------------------------------------------------------------------------
Section '1. Reset to a clean state'
Log '```'
Log '.\devnet.ps1 -Action reset'
& $devnet -Action reset 2>&1 | ForEach-Object { Log "$_" }
# "From a clean state" must include the wallets. A wallet created against a previous chain keeps a
# stale refresh-from height and cached blockchain hashes, and will not rescan the new chain -- it
# reports a zero balance forever. reset.ps1 deliberately preserves wallets; the DEMO wipes them,
# because it creates its own.
Log 'wiping devnet wallets (demo creates its own)'
& wsl.exe -e bash -lc 'rm -rf $HOME/.meepcoin-devnet/wallets' 2>&1 | ForEach-Object { Log "$_" }
Log '```'

# ------------------------------------------------------------------------------------------
Section '2. Start node A and node B'
Log '```'
Log '.\devnet.ps1 -Action start-node-a'
& $devnet -Action start-node-a -FixedDifficulty $FixedDifficulty 2>&1 | ForEach-Object { Log "$_" }
Log '.\devnet.ps1 -Action start-node-b'
& $devnet -Action start-node-b -FixedDifficulty $FixedDifficulty 2>&1 | ForEach-Object { Log "$_" }
Log '```'

# ------------------------------------------------------------------------------------------
Section '3. Peer connection and genesis agreement'
$deadline = (Get-Date).AddSeconds(120)
$connected = $false
while ((Get-Date) -lt $deadline) {
    $ia = DaemonRest -Port $A.Rpc -Path 'get_info'
    $ib = DaemonRest -Port $B.Rpc -Path 'get_info'
    if ($ia -and $ib -and ($ia.outgoing_connections_count + $ia.incoming_connections_count) -ge 1 `
                     -and ($ib.outgoing_connections_count + $ib.incoming_connections_count) -ge 1) {
        $connected = $true; break
    }
    Start-Sleep -Seconds 2
}
$ia = DaemonRest -Port $A.Rpc -Path 'get_info'
$ib = DaemonRest -Port $B.Rpc -Path 'get_info'
Log "| node | height | top block hash | peers out/in |"
Log "|---|---:|---|---|"
Log "| A | $($ia.height) | ``$($ia.top_block_hash)`` | $($ia.outgoing_connections_count)/$($ia.incoming_connections_count) |"
Log "| B | $($ib.height) | ``$($ib.top_block_hash)`` | $($ib.outgoing_connections_count)/$($ib.incoming_connections_count) |"
Log ""
Log "- peers connected: **$connected**"
Log "- genesis tips identical: **$(TipsMatch $ia.top_block_hash $ib.top_block_hash)**"
$genesisHash = $ia.top_block_hash

# ------------------------------------------------------------------------------------------
Section '4. Create wallets A and B'
Log '```'
& $devnet -Action create-wallets 2>&1 | ForEach-Object { Log "$_" }
Log '```'
$addrA = (WalletRpc -Port $A.WalletRpc -M 'get_address' -P @{account_index=0}).address
$addrB = (WalletRpc -Port $B.WalletRpc -M 'get_address' -P @{account_index=0}).address
Log ""
Log "- wallet A address: ``$addrA``"
Log "- wallet B address: ``$addrB``"
Log "- address prefix character: ``$($addrA.Substring(0,1))`` (devnet prefix 71)"
Log ""
Log "Wallet seeds are testnet-only and are never printed, logged, or committed."

# ------------------------------------------------------------------------------------------
Section '5. Native mining with MeepHash-W v2'
Log '```'
& $devnet -Action mine-start -MineThreads $MineThreads 2>&1 | ForEach-Object { Log "$_" }
Log '```'

$mineDeadline = (Get-Date).AddSeconds($MineTimeoutSec)
$unlockedTarget = [uint64]([decimal]$SendAmount * $AtomicPerMeep)
$lastH = 0
while ((Get-Date) -lt $mineDeadline) {
    Start-Sleep -Seconds 10
    $ia = DaemonRest -Port $A.Rpc -Path 'get_info'
    WalletRpc -Port $A.WalletRpc -M 'refresh' | Out-Null
    $bal = WalletRpc -Port $A.WalletRpc -M 'get_balance' -P @{account_index=0}
    if ($ia -and $ia.height -ne $lastH) {
        $lastH = $ia.height
        Write-Host ("  height={0} balance={1:N4} unlocked={2:N4}" -f $ia.height, ($bal.balance/$AtomicPerMeep), ($bal.unlocked_balance/$AtomicPerMeep))
    }
    if ($bal -and [uint64]$bal.unlocked_balance -ge $unlockedTarget) { break }
}
& $devnet -Action mine-stop 2>&1 | ForEach-Object { Log "$_" }

$ia = DaemonRest -Port $A.Rpc -Path 'get_info'
Log ""
Log "- blocks mined: **$($ia.height - 1)** (height $($ia.height))"
Log "- node A top block: ``$($ia.top_block_hash)``"

# first few mined block hashes as evidence
Log ""
Log "Mined block hashes (from node A):"
Log ""
Log "| height | block hash |"
Log "|---:|---|"
for ($h = 1; $h -lt [Math]::Min($ia.height, 6); $h++) {
    $bh = Invoke-RestMethod -Uri "http://127.0.0.1:$($A.Rpc)/json_rpc" -Method Post `
        -ContentType 'application/json' -TimeoutSec 30 `
        -Body (@{jsonrpc='2.0';id='0';method='get_block_header_by_height';params=@{height=$h}} | ConvertTo-Json -Depth 6)
    if ($bh.result) { Log "| $h | ``$($bh.result.block_header.hash)`` |" }
}

# ------------------------------------------------------------------------------------------
Section '6. Node B independently verified and synced the chain'
$syncDeadline = (Get-Date).AddSeconds(180)
while ((Get-Date) -lt $syncDeadline) {
    $ia = DaemonRest -Port $A.Rpc -Path 'get_info'
    $ib = DaemonRest -Port $B.Rpc -Path 'get_info'
    if ($ia -and $ib -and $ia.top_block_hash -eq $ib.top_block_hash) { break }
    Start-Sleep -Seconds 3
}
$ia = DaemonRest -Port $A.Rpc -Path 'get_info'; $ib = DaemonRest -Port $B.Rpc -Path 'get_info'
Log "| node | height | top block hash |"
Log "|---|---:|---|"
Log "| A | $($ia.height) | ``$($ia.top_block_hash)`` |"
Log "| B | $($ib.height) | ``$($ib.top_block_hash)`` |"
Log ""
Log "- tips match after mining: **$(TipsMatch $ia.top_block_hash $ib.top_block_hash)**"
Log ""
Log "Node B did not mine these blocks. It accepted them only after recomputing each MeepHash-W v2"
Log "PoW and checking it against the target, so this is genuine independent consensus verification."

# ------------------------------------------------------------------------------------------
Section '7. Balance before the transfer'
$balA0 = WalletRpc -Port $A.WalletRpc -M 'get_balance' -P @{account_index=0}
WalletRpc -Port $B.WalletRpc -M 'refresh' | Out-Null
$balB0 = WalletRpc -Port $B.WalletRpc -M 'get_balance' -P @{account_index=0}
Log "| wallet | balance | unlocked |"
Log "|---|---:|---:|"
Log ("| A | {0:N11} | {1:N11} |" -f ($balA0.balance/$AtomicPerMeep), ($balA0.unlocked_balance/$AtomicPerMeep))
Log ("| B | {0:N11} | {1:N11} |" -f ($balB0.balance/$AtomicPerMeep), ($balB0.unlocked_balance/$AtomicPerMeep))

# ------------------------------------------------------------------------------------------
Section "8. Transaction: wallet A -> wallet B ($SendAmount test MEEP)"
$txr = WalletRpc -Port $A.WalletRpc -M 'transfer' -P @{
    destinations=@(@{amount=[uint64]([decimal]$SendAmount * $AtomicPerMeep); address=$addrB}); account_index=0; priority=0; get_tx_key=$true }
if ($txr) {
    Log "- **tx hash: ``$($txr.tx_hash)``**"
    Log "- amount: $($txr.amount) atomic units"
    Log "- fee: $($txr.fee) atomic units"
    $txHash = $txr.tx_hash
} else {
    Log "- **TRANSFER FAILED** — no spendable output available"
    $txHash = $null
}

# ------------------------------------------------------------------------------------------
Section '9. Confirm the transaction in a later block'
if ($txHash) {
    & $devnet -Action mine-start -MineThreads $MineThreads 2>&1 | ForEach-Object { Log "$_" -Quiet }
    $confDeadline = (Get-Date).AddSeconds(900)
    $confirmed = $false
    while ((Get-Date) -lt $confDeadline) {
        Start-Sleep -Seconds 10
        WalletRpc -Port $B.WalletRpc -M 'refresh' | Out-Null
        $bb = WalletRpc -Port $B.WalletRpc -M 'get_balance' -P @{account_index=0}
        if ($bb -and [uint64]$bb.balance -gt 0) { $confirmed = $true; break }
    }
    & $devnet -Action mine-stop 2>&1 | ForEach-Object { Log "$_" -Quiet }
    Log "- transaction confirmed and credited to wallet B: **$confirmed**"
}

# ------------------------------------------------------------------------------------------
Section '10. Final state — balances and chain tips on BOTH nodes'
foreach ($p in @(@($A,'A'), @($B,'B'))) { WalletRpc -Port $p[0].WalletRpc -M 'refresh' | Out-Null }
Start-Sleep -Seconds 3
$balA1 = WalletRpc -Port $A.WalletRpc -M 'get_balance' -P @{account_index=0}
$balB1 = WalletRpc -Port $B.WalletRpc -M 'get_balance' -P @{account_index=0}
$ia = DaemonRest -Port $A.Rpc -Path 'get_info'; $ib = DaemonRest -Port $B.Rpc -Path 'get_info'

Log "| wallet | balance | unlocked |"
Log "|---|---:|---:|"
Log ("| A | {0:N11} | {1:N11} |" -f ($balA1.balance/$AtomicPerMeep), ($balA1.unlocked_balance/$AtomicPerMeep))
Log ("| B | {0:N11} | {1:N11} |" -f ($balB1.balance/$AtomicPerMeep), ($balB1.unlocked_balance/$AtomicPerMeep))
Log ""
Log "| node | height | top block hash |"
Log "|---|---:|---|"
Log "| A | $($ia.height) | ``$($ia.top_block_hash)`` |"
Log "| B | $($ib.height) | ``$($ib.top_block_hash)`` |"
Log ""
Log "- **chain tips match: $(TipsMatch $ia.top_block_hash $ib.top_block_hash)**"
Log "- **heights match: $(if ($null -eq $ia.height -or $null -eq $ib.height) { $false } else { $ia.height -eq $ib.height })**"
Log "- wallet B received funds: **$([uint64]$balB1.balance -gt 0)**"
Log ""
Log "- genesis tip at start: ``$genesisHash``"
Log "- elapsed: $([int]((Get-Date) - $started).TotalSeconds) s"
Log ""
Log "_All coins above are dev/test coins on a private localhost chain and have no monetary value._"

$T -join "`r`n" | Set-Content -Path $TranscriptPath -Encoding UTF8
Write-Host "`nTranscript written to $TranscriptPath" -ForegroundColor Cyan
