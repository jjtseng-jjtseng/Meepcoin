<#
.SYNOPSIS
  Live wallet tests for MeepCoin's sparse hard-fork schedule (version 16 from genesis).

.DESCRIPTION
  The unit tests (meepow-unit, "sparse schedule ...") cover the lookup logic exhaustively at the
  boundary heights. THIS script exercises the real wallet against a real v16 daemon, because the
  unit tests cannot catch integration failures such as the wallet silently refusing to scan.

  Requires node A + node B running and mined to some depth.

  *** LOCALHOST / PRIVATE ONLY. Test coins, no monetary value. ***
#>
[CmdletBinding()] param(
    [int]$NodeA = 29081, [int]$NodeB = 29091,
    [int]$WalA = 29083,
    [int]$ProbeWallet = 29085,
    [string]$ResultPath = "$PSScriptRoot\..\..\docs\WALLET_HARDFORK_TESTS.md"
)
$ErrorActionPreference = 'Continue'
$pass = 0; $fail = 0; $skip = 0
$out = New-Object System.Collections.Generic.List[string]
function Say { param([string]$s) Write-Host $s; $out.Add($s) }
function Ok   { param([string]$s) $script:pass++; Say "  [PASS] $s" }
function Bad  { param([string]$s) $script:fail++; Say "  [FAIL] $s" }
function Skip { param([string]$s) $script:skip++; Say "  [SKIP] $s" }
function Must { param([bool]$c,[string]$s) if ($c) { Ok $s } else { Bad $s } }

function NodeRest { param([int]$P,[string]$Path)
    try { Invoke-RestMethod -Uri "http://127.0.0.1:$P/$Path" -Method Post -ContentType 'application/json' -Body '{}' -TimeoutSec 45 } catch { $null }
}
function WRpc { param([int]$P,[string]$M,$Params=@{})
    $body = @{ jsonrpc='2.0'; id='0'; method=$M; params=$Params } | ConvertTo-Json -Depth 8
    try { $r = Invoke-RestMethod -Uri "http://127.0.0.1:$P/json_rpc" -Method Post -ContentType 'application/json' -Body $body -TimeoutSec 240
          if ($r.error) { return @{ __error = $r.error.message } }
          return $r.result } catch { return $null }
}
function StartProbeWallet {
    param([int]$Port, [int]$DaemonPort)
    $dir = '$HOME/.meepcoin-devnet/probe-wallets'
    & wsl.exe -e bash -lc "mkdir -p $dir" | Out-Null
    $cmd = "`$HOME/meepcoin-node/build/release/bin/meepcoin-wallet-rpc --testnet --wallet-dir $dir " +
           "--daemon-address 127.0.0.1:$DaemonPort --rpc-bind-ip 127.0.0.1 --rpc-bind-port $Port " +
           "--disable-rpc-login --log-file $dir/probe-$Port.log"
    $b64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("#!/usr/bin/env bash`nexec $cmd`n"))
    & wsl.exe -e bash -lc "echo '$b64' | base64 -d > $dir/launch-$Port.sh && chmod +x $dir/launch-$Port.sh" | Out-Null
    $p = (& wsl.exe -e bash -lc "echo $dir/launch-$Port.sh").Trim()
    Start-Process wsl.exe -ArgumentList @('-e','bash',$p) -WindowStyle Hidden | Out-Null
    $deadline = (Get-Date).AddSeconds(60)
    while ((Get-Date) -lt $deadline) {
        if ($null -ne (WRpc $Port 'get_version')) { return $true }
        Start-Sleep -Milliseconds 800
    }
    return $false
}
function StopProbeWallets { & wsl.exe -e bash -lc "pkill -f 'probe-wallets' ; true" | Out-Null; Start-Sleep -Seconds 2 }
# Probe wallets MUST be wiped before the run. Leftovers from a previous run make
# restore_deterministic_wallet fail with "Wallet already exists", and the follow-up checks then
# operate on an empty result -- which is how a genesis check "passed" against a wallet that had
# never restored. Only probe wallets are touched; the devnet's own wallets are untouched.
function WipeProbeWallets { & wsl.exe -e bash -lc "rm -rf `$HOME/.meepcoin-devnet/probe-wallets ; true" | Out-Null }

Say '# MeepCoin Wallet Tests — Sparse Hard-Fork Schedule (v16 from genesis)'
Say ''
Say "Run (UTC): $((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))"
Say ''
Say '**Test/dev coins, no monetary value. Localhost only.**'
Say ''
Say 'Upstream `check_block_hard_fork_version` indexed the fork table BY VERSION, assuming a dense'
Say '1..N schedule. MeepCoin has a single {16, height 0} entry, so the unpatched wallet declared'
Say 'itself outdated on every block and silently refused to scan. These tests exercise the patched'
Say 'wallet against a live v16 daemon.'
Say ''

$infoA = NodeRest $NodeA 'get_info'
if (-not $infoA) { Say '**ABORTED: node A not responding.**'; $out -join "`r`n" | Set-Content $ResultPath -Encoding UTF8; exit 2 }
$tip = [int64]$infoA.height
Say "- chain height: $tip"
Say ''

# ------------------------------------------------------------------------------------------------
Say '## 1. Unit-level boundary coverage'
Say ''
$u = (& wsl.exe -e bash -lc "cd /mnt/c/Users/tseng/meepcoin/meepow && ./build/release/meepow-unit --test-case='*sparse*,*dense*,*upstream*,*empty schedule*' 2>&1 | tail -4") -join "`n"
Say '```'
Say $u
Say '```'
Must ($u -match 'SUCCESS') 'unit tests for the sparse lookup pass (heights 0,1,15,16,63,64,2048,2113)'

# ------------------------------------------------------------------------------------------------
Say ''
Say '## 2. Fresh wallet synchronises against a v16 daemon'
StopProbeWallets
WipeProbeWallets
$started = StartProbeWallet -Port $ProbeWallet -DaemonPort $NodeA
Must $started 'probe wallet RPC started'
if ($started) {
    $c = WRpc $ProbeWallet 'create_wallet' @{ filename='probe_fresh'; password=''; language='English' }
    if ($c.__error) { WRpc $ProbeWallet 'open_wallet' @{ filename='probe_fresh'; password='' } | Out-Null }
    WRpc $ProbeWallet 'refresh' | Out-Null
    $h = WRpc $ProbeWallet 'get_height'
    Must ($null -ne $h -and [int64]$h.height -ge ($tip - 2)) `
         "fresh wallet scanned to the chain tip (wallet $($h.height) vs chain $tip)"
    # NOTE: a wsl.exe call returns an ARRAY of lines. Joining before parsing matters -- an earlier
    # version passed the array straight to Must and the check errored out instead of asserting.
    $raw = (& wsl.exe -e bash -lc "grep -c 'incorrect_fork_version' `$HOME/.meepcoin-devnet/probe-wallets/probe-$ProbeWallet.log 2>/dev/null; true")
    $errs = 0
    if ($null -ne $raw) { [void][int]::TryParse((($raw -join '').Trim()), [ref]$errs) }
    Must ($errs -eq 0) "no incorrect_fork_version errors during scan (count=$errs)"
}

# ------------------------------------------------------------------------------------------------
Say ''
Say '## 3. Restore from seed, from height 0'
$seed = (WRpc $ProbeWallet 'query_key' @{ key_type='mnemonic' }).key
Must (-not [string]::IsNullOrWhiteSpace($seed)) 'mnemonic seed retrievable from the probe wallet'
if ($seed) {
    WRpc $ProbeWallet 'close_wallet' | Out-Null
    $r0 = WRpc $ProbeWallet 'restore_deterministic_wallet' `
            @{ filename='probe_restore_h0'; password=''; seed=$seed; restore_height=0; language='English' }
    Must ($null -ne $r0 -and -not $r0.__error) "restore from seed at height 0 succeeded$(if($r0.__error){' -- '+$r0.__error})"
    WRpc $ProbeWallet 'refresh' | Out-Null
    $h0 = WRpc $ProbeWallet 'get_height'
    Must ($null -ne $h0 -and [int64]$h0.height -ge ($tip - 2)) `
         "restored-from-0 wallet reached the tip (wallet $($h0.height) vs chain $tip)"
    $b0 = WRpc $ProbeWallet 'get_balance' @{ account_index=0 }
    Say "- balance after restore-from-0: $($b0.balance) atomic"
    # The genesis burn output must NOT appear even when scanning from the very first block.
    # Only meaningful if the restore actually succeeded AND the wallet actually scanned. An
    # absent result must not read as "no genesis output found".
    $restoredOk = ($null -ne $r0 -and -not $r0.__error -and $null -ne $h0 -and [int64]$h0.height -gt 0)
    if ($restoredOk) {
        $inc = WRpc $ProbeWallet 'incoming_transfers' @{ transfer_type='all'; account_index=0 }
        $sawGenesis = $false
        if ($inc -and $inc.transfers) { foreach ($t in $inc.transfers) { if ($t.block_height -eq 0) { $sawGenesis = $true } } }
        Must (-not $sawGenesis) 'restoring from height 0 does NOT reveal the genesis output'
    } else {
        Bad 'restoring from height 0 does NOT reveal the genesis output -- restore failed, check not performed'
    }
}

# ------------------------------------------------------------------------------------------------
Say ''
Say '## 4. Restore from a later height'
if ($seed) {
    $later = [Math]::Max(1, [int]($tip / 2))
    WRpc $ProbeWallet 'close_wallet' | Out-Null
    $rl = WRpc $ProbeWallet 'restore_deterministic_wallet' `
            @{ filename="probe_restore_h$later"; password=''; seed=$seed; restore_height=$later; language='English' }
    Must ($null -ne $rl -and -not $rl.__error) "restore from seed at height $later succeeded"
    WRpc $ProbeWallet 'refresh' | Out-Null
    $hl = WRpc $ProbeWallet 'get_height'
    Must ($null -ne $hl -and [int64]$hl.height -ge ($tip - 2)) `
         "restored-from-$later wallet reached the tip (wallet $($hl.height))"
}

# ------------------------------------------------------------------------------------------------
Say ''
Say '## 5. Wallet restart'
StopProbeWallets
$restarted = StartProbeWallet -Port $ProbeWallet -DaemonPort $NodeA
Must $restarted 'wallet RPC restarted'
if ($restarted) {
    $o = WRpc $ProbeWallet 'open_wallet' @{ filename='probe_fresh'; password='' }
    Must ($null -ne $o -and -not $o.__error) 'wallet reopened after restart'
    WRpc $ProbeWallet 'refresh' | Out-Null
    $hr = WRpc $ProbeWallet 'get_height'
    Must ($null -ne $hr -and [int64]$hr.height -ge ($tip - 2)) "wallet resynced after restart ($($hr.height))"
}

# ------------------------------------------------------------------------------------------------
Say ''
Say '## 6. Wallet against the SECOND node (independent daemon)'
StopProbeWallets
$onB = StartProbeWallet -Port $ProbeWallet -DaemonPort $NodeB
Must $onB 'wallet RPC started against node B'
if ($onB) {
    $o = WRpc $ProbeWallet 'open_wallet' @{ filename='probe_fresh'; password='' }
    WRpc $ProbeWallet 'refresh' | Out-Null
    $hb = WRpc $ProbeWallet 'get_height'
    $ib = NodeRest $NodeB 'get_info'
    Must ($null -ne $hb -and $null -ne $ib -and [int64]$hb.height -ge ([int64]$ib.height - 2)) `
         "wallet synced against node B (wallet $($hb.height) vs node B $($ib.height))"
}

# ------------------------------------------------------------------------------------------------
Say ''
Say '## 7. Node restart, wallet reconnects'
# NOTE: this test must NEVER call `devnet.ps1 -Action reset`. Doing so deletes the chain, which
# would silently destroy any long-running mined chain (e.g. the 2113-block chain used for consensus
# vector generation) and make this script destructive to unrelated work.
Skip 'node-restart reconnection — restarting a node here would disturb the running chain, so this is covered by the'
Say '       full integration test instead (which restarts both nodes from clean state and passes).'

# ------------------------------------------------------------------------------------------------
Say ''
Say '## 8. Not covered here'
Say ''
Say 'Stated rather than silently omitted:'
Say ''
Say '- **Daemon reporting an invalid fork version**: covered at unit level (a daemon claiming v15 or'
Say '  v17 is rejected, and the wallet correctly distinguishes "wallet outdated" from "daemon'
Say '  outdated"). Forcing a live daemon to lie about its version would require a patched daemon'
Say '  build; not done.'
Say '- **Wallet connected to a different network**: MeepCoin has only one live network. Cross-network'
Say '  rejection rests on distinct NETWORK_IDs and address prefixes, verified in'
Say '  `DEVNET_CONSENSUS_TESTS.md`, not on a live mismatched-network wallet.'
Say '- **Reorganisation and alternate-chain wallet handling**: the alt-chain PoW path is verified in'
Say '  `BLOCK_CONSENSUS_VECTORS.md`; wallet-side reorg rescanning is NOT separately tested.'
Say '- **Offline transaction creation/signing**: not exercised.'

StopProbeWallets
Say ''
Say "**$pass passed, $fail failed, $skip skipped**"
Say ''
Say '_Test/dev coins on a private localhost chain. No monetary value._'
$out -join "`r`n" | Set-Content -Path $ResultPath -Encoding UTF8
Write-Host "`nWritten to $ResultPath"
if ($fail -gt 0) { exit 1 }
exit 0
