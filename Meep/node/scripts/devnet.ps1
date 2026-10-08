<#
.SYNOPSIS
  MeepCoin private devnet driver (localhost only).

.DESCRIPTION
  Drives a two-node MeepCoin development network built from the pinned Monero v0.18.5.1 fork with
  MeepHash-W v2 as the consensus proof-of-work.

  *** ALL COINS ON THIS NETWORK ARE DEV/TEST COINS WITH NO MONETARY VALUE. ***
  *** LOCALHOST / PRIVATE ONLY. No seed nodes, no public peers, no faucet, no exchange. ***

  The daemon and wallet binaries live in WSL2; this script invokes them via wsl.exe and talks to
  their JSON-RPC endpoints over localhost.

.PARAMETER Action
  build | start-node-a | start-node-b | create-wallets | mine-start | mine-stop |
  balances | send | reset | status | demo
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('build','start-node-a','start-node-b','create-wallets','mine-start','mine-stop',
                 'balances','send','reset','status','demo')]
    [string]$Action,

    [uint64]$FixedDifficulty = 500,
    [double]$SendAmount      = 1.0,
    [int]$MineThreads        = 4,
    [int]$TimeoutSec         = 900
)

# MeepCoin uses 11 decimals (COIN = 10^11). Every MEEP <-> atomic conversion in this
# script goes through this constant; never hardcode a power of ten.
$AtomicPerMeep = [uint64]100000000000

$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------------------------
# Topology. Node A and node B are exclusive peers of each other and of nothing else.
# ---------------------------------------------------------------------------------------------
$Cfg = @{
    NodeBin    = '$HOME/meepcoin-node/build/release/bin'
    DataRoot   = '$HOME/.meepcoin-devnet'
    WinDataRoot= 'meepcoin-devnet'
    A = @{ Name='A'; P2P=29080; Rpc=29081; Zmq=29082; WalletRpc=29083 }
    B = @{ Name='B'; P2P=29090; Rpc=29091; Zmq=29092; WalletRpc=29093 }
}

function Invoke-Wsl {
    param([string]$Command)
    return (& wsl.exe -e bash -lc $Command) 2>&1
}

# Launch a long-lived process in WSL, owned by a Windows process.
#
# Two traps this works around, both of which produced silent failures:
#  1. WSL kills processes started inside a wsl.exe invocation once that invocation returns, so
#     nohup/disown is NOT sufficient -- a Windows process must own the daemon.
#  2. Start-Process -ArgumentList re-splits a long command string on spaces, so passing it to
#     `bash -lc` delivered only the first token. A daemon launched that way silently started with
#     NO arguments (default mainnet, default data dir).
# Writing the command to a script file and launching that file avoids both.
function Start-WslDaemon {
    param([string]$Name, [string]$Command)
    $scriptPath = "`$HOME/.meepcoin-devnet/launch-$Name.sh"
    $b64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("#!/usr/bin/env bash`nexec $Command`n"))
    Invoke-Wsl "mkdir -p `$HOME/.meepcoin-devnet && echo '$b64' | base64 -d > $scriptPath && chmod +x $scriptPath" | Out-Null
    $wslPath = (Invoke-Wsl "echo $scriptPath").Trim()
    Start-Process wsl.exe -ArgumentList @('-e','bash',$wslPath) -WindowStyle Hidden | Out-Null
    return "started $Name (windows-owned, $wslPath)"
}

function Write-Step { param([string]$Text) Write-Host "`n=== $Text ===" -ForegroundColor Cyan }
function Write-Ok   { param([string]$Text) Write-Host "  [ok] $Text" -ForegroundColor Green }
function Write-Warn2{ param([string]$Text) Write-Host "  [!!] $Text" -ForegroundColor Yellow }

# --- JSON-RPC helpers -------------------------------------------------------------------------
function Invoke-DaemonRpc {
    param([int]$Port, [string]$Method, [hashtable]$Params = @{})
    $body = @{ jsonrpc='2.0'; id='0'; method=$Method; params=$Params } | ConvertTo-Json -Depth 8
    try {
        $r = Invoke-RestMethod -Uri "http://127.0.0.1:$Port/json_rpc" -Method Post `
                               -ContentType 'application/json' -Body $body -TimeoutSec 30
        return $r.result
    } catch { return $null }
}

# Some daemon endpoints are plain REST, not JSON-RPC (start_mining, stop_mining, get_info).
function Invoke-DaemonRest {
    param([int]$Port, [string]$Path, [hashtable]$Params = @{})
    $body = $Params | ConvertTo-Json -Depth 8
    try {
        return Invoke-RestMethod -Uri "http://127.0.0.1:$Port/$Path" -Method Post `
                                 -ContentType 'application/json' -Body $body -TimeoutSec 30
    } catch { return $null }
}

function Invoke-WalletRpc {
    param([int]$Port, [string]$Method, [hashtable]$Params = @{})
    $body = @{ jsonrpc='2.0'; id='0'; method=$Method; params=$Params } | ConvertTo-Json -Depth 8
    try {
        $r = Invoke-RestMethod -Uri "http://127.0.0.1:$Port/json_rpc" -Method Post `
                               -ContentType 'application/json' -Body $body -TimeoutSec 120
        if ($r.error) { Write-Warn2 "wallet rpc $Method : $($r.error.message)"; return $null }
        return $r.result
    } catch { return $null }
}

function Wait-For {
    param([scriptblock]$Test, [int]$Seconds = 60, [string]$What = 'condition')
    $deadline = (Get-Date).AddSeconds($Seconds)
    while ((Get-Date) -lt $deadline) {
        if (& $Test) { return $true }
        Start-Sleep -Milliseconds 1000
    }
    Write-Warn2 "timed out waiting for $What after ${Seconds}s"
    return $false
}

# ---------------------------------------------------------------------------------------------
function Do-Build {
    Write-Step 'Building MeepCoin daemon + wallets (MeepHash-W v2 PoW)'
    $out = Invoke-Wsl @"
set -e
cd `$HOME/meepcoin-node
mkdir -p build/release && cd build/release
cmake -D CMAKE_BUILD_TYPE=Release -D BUILD_TESTS=OFF -D USE_DEVICE_TREZOR=OFF -D MANUAL_SUBMODULES=1 ../.. > /tmp/meep_cmake.log 2>&1
make -j`$(nproc) daemon simplewallet wallet_rpc_server 2>&1 | tail -20
ls -la bin/
"@
    $out | ForEach-Object { Write-Host "  $_" }
}

# Stop every devnet process and WAIT until they are actually gone and their ports are released.
# Without this wait a freshly started daemon dies with "Failed to bind IPv4 (set to required)"
# while the OLD daemon is still answering RPC -- which makes the start look successful when it
# was not. Escalates to SIGKILL if a process will not exit.
function Stop-AllDevnet {
    # Use -x (exact process NAME), never -f (full command line): `pkill -f meepcoind` also matches
    # the very shell running it, so the shell kills itself and everything after the semicolon is
    # silently skipped. Note also that Linux truncates process names to 15 characters, so
    # "meepcoin-wallet-rpc" must be matched as "meepcoin-wallet".
    Invoke-Wsl "pkill -x meepcoind; pkill -x meepcoin-wallet; true" | Out-Null
    $deadline = (Get-Date).AddSeconds(30)
    while ((Get-Date) -lt $deadline) {
        $n = (Invoke-Wsl "pgrep -x meepcoind | wc -l").Trim()
        $w = (Invoke-Wsl "pgrep -x meepcoin-wallet | wc -l").Trim()
        if ($n -eq '0' -and $w -eq '0') { break }
        Start-Sleep -Milliseconds 500
    }
    Invoke-Wsl "pkill -9 -x meepcoind; pkill -9 -x meepcoin-wallet; true" | Out-Null
    # Ports must actually be released, not merely unowned.
    $portList = @($Cfg.A.P2P,$Cfg.A.Rpc,$Cfg.A.Zmq,$Cfg.A.WalletRpc,
                  $Cfg.B.P2P,$Cfg.B.Rpc,$Cfg.B.Zmq,$Cfg.B.WalletRpc) -join '|'
    $deadline = (Get-Date).AddSeconds(30)
    while ((Get-Date) -lt $deadline) {
        $busy = (Invoke-Wsl "ss -ltn 2>/dev/null | grep -cE ':($portList) ' || echo 0").Trim()
        if ($busy -eq '0') { return $true }
        Start-Sleep -Milliseconds 500
    }
    Write-Warn2 'some devnet ports are still bound after 30s'
    return $false
}

function Start-Node {
    param([hashtable]$N, [hashtable]$Peer)
    Write-Step "Starting node $($N.Name)  (p2p $($N.P2P), rpc $($N.Rpc))"
    $data = "$($Cfg.DataRoot)/node$($N.Name)"

    # Refuse to start on top of a live daemon: an already-listening RPC port would make the
    # readiness check below pass against the WRONG process.
    if ($null -ne (Invoke-DaemonRest -Port $N.Rpc -Path 'get_info')) {
        Write-Warn2 "something is already serving RPC on $($N.Rpc) — stopping all devnet processes first"
        Stop-AllDevnet | Out-Null
    }
    Invoke-Wsl "mkdir -p $data" | Out-Null
    $cmd = @(
        "$($Cfg.NodeBin)/meepcoind",
        "--testnet",
        "--data-dir $data",
        "--p2p-bind-ip 127.0.0.1 --p2p-bind-port $($N.P2P)",
        "--rpc-bind-ip 127.0.0.1 --rpc-bind-port $($N.Rpc)",
        "--zmq-rpc-bind-ip 127.0.0.1 --zmq-rpc-bind-port $($N.Zmq)",
        "--add-exclusive-node 127.0.0.1:$($Peer.P2P)",
        "--no-igd --hide-my-port --disable-dns-checkpoints",
        "--fixed-difficulty $FixedDifficulty",
        "--non-interactive",
        "--log-file $data/meepcoind.log"
    ) -join ' '
    Start-WslDaemon -Name "node$($N.Name)" -Command $cmd | Out-Null

    $ok = Wait-For -Seconds 90 -What "node $($N.Name) RPC" -Test {
        $null -ne (Invoke-DaemonRest -Port $N.Rpc -Path 'get_info')
    }
    if ($ok) {
        $info = Invoke-DaemonRest -Port $N.Rpc -Path 'get_info'
        Write-Ok "node $($N.Name) up — height $($info.height), nettype $($info.nettype)"
    } else {
        # Surface the daemon's own reason instead of a bare timeout.
        $fatal = Invoke-Wsl "grep -aE 'FATAL|Exception in main' $data/meepcoind.log 2>/dev/null | tail -3 | sed 's/\x1b\[[0-9;]*m//g'"
        if ($fatal) { $fatal | ForEach-Object { Write-Warn2 "daemon said: $_" } }
        throw "node $($N.Name) failed to start"
    }
}

function Do-CreateWallets {
    Write-Step 'Starting wallet RPC servers and creating wallets A and B'
    $wdir = "$($Cfg.DataRoot)/wallets"
    Invoke-Wsl "mkdir -p $wdir" | Out-Null

    foreach ($pair in @(@($Cfg.A,'A'), @($Cfg.B,'B'))) {
        $n = $pair[0]
        $cmd = @(
            "$($Cfg.NodeBin)/meepcoin-wallet-rpc",
            "--testnet",
            "--wallet-dir $wdir",
            "--daemon-address 127.0.0.1:$($n.Rpc)",
            "--rpc-bind-ip 127.0.0.1 --rpc-bind-port $($n.WalletRpc)",
            "--disable-rpc-login",
            "--log-file $wdir/wallet-rpc-$($n.Name).log"
        ) -join ' '
        Start-WslDaemon -Name "wallet$($n.Name)" -Command $cmd | Out-Null
    }

    foreach ($pair in @(@($Cfg.A,'A'), @($Cfg.B,'B'))) {
        $n = $pair[0]; $label = $pair[1]
        Wait-For -Seconds 60 -What "wallet RPC $label" -Test {
            $null -ne (Invoke-WalletRpc -Port $n.WalletRpc -Method 'get_version')
        } | Out-Null

        $name = "wallet$label"
        $res = Invoke-WalletRpc -Port $n.WalletRpc -Method 'create_wallet' `
                 -Params @{ filename=$name; password=''; language='English' }
        if ($null -eq $res) {
            # Already exists from a previous run — just open it.
            Invoke-WalletRpc -Port $n.WalletRpc -Method 'open_wallet' `
                -Params @{ filename=$name; password='' } | Out-Null
            Write-Ok "wallet $label opened (existing)"
        } else {
            Write-Ok "wallet $label created"
        }
        $addr = Invoke-WalletRpc -Port $n.WalletRpc -Method 'get_address' -Params @{ account_index=0 }
        if ($addr) { Write-Host "  wallet ${label} address: $($addr.address)" }
    }
    Write-Warn2 'Wallet seeds are testnet-only and are NEVER printed, logged, or committed.'
}

function Get-WalletAddress {
    param([hashtable]$N)
    $a = Invoke-WalletRpc -Port $N.WalletRpc -Method 'get_address' -Params @{ account_index=0 }
    if ($a) { return $a.address } else { return $null }
}

function Do-MineStart {
    Write-Step "Starting native miner on node A ($MineThreads threads)"
    $addr = Get-WalletAddress -N $Cfg.A
    if (-not $addr) { throw 'wallet A address unavailable — run create-wallets first' }
    $r = Invoke-DaemonRest -Port $Cfg.A.Rpc -Path 'start_mining' -Params @{
        miner_address     = $addr
        threads_count     = $MineThreads
        do_background_mining = $false
        ignore_battery    = $true
    }
    if ($r -and $r.status -eq 'OK') { Write-Ok "mining to $addr" }
    else { Write-Warn2 "start_mining returned: $($r | ConvertTo-Json -Compress)" }
}

function Do-MineStop {
    Write-Step 'Stopping miner on node A'
    $r = Invoke-DaemonRest -Port $Cfg.A.Rpc -Path 'stop_mining'
    Write-Ok "stop_mining: $($r.status)"
}

function Do-Status {
    Write-Step 'Chain status on both nodes'
    foreach ($n in @($Cfg.A, $Cfg.B)) {
        $i = Invoke-DaemonRest -Port $n.Rpc -Path 'get_info'
        if ($i) {
            Write-Host ("  node {0}: height={1} top={2} diff={3} peers(out/in)={4}/{5} tx_pool={6}" -f `
                $n.Name, $i.height, $i.top_block_hash, $i.difficulty, $i.outgoing_connections_count,
                $i.incoming_connections_count, $i.tx_pool_size)
        } else { Write-Warn2 "node $($n.Name) not responding on $($n.Rpc)" }
    }
}

function Do-Balances {
    Write-Step 'Wallet balances'
    foreach ($pair in @(@($Cfg.A,'A'), @($Cfg.B,'B'))) {
        $n = $pair[0]; $label = $pair[1]
        Invoke-WalletRpc -Port $n.WalletRpc -Method 'refresh' | Out-Null
        $b = Invoke-WalletRpc -Port $n.WalletRpc -Method 'get_balance' -Params @{ account_index=0 }
        if ($b) {
            Write-Host ("  wallet {0}: balance={1:N11}  unlocked={2:N11}  (atomic {3} / {4})" -f `
                $label, ($b.balance/$AtomicPerMeep), ($b.unlocked_balance/$AtomicPerMeep), $b.balance, $b.unlocked_balance)
        } else { Write-Warn2 "wallet $label not responding on $($n.WalletRpc)" }
    }
}

function Do-Send {
    Write-Step "Sending $SendAmount test MEEP from wallet A to wallet B"
    $dest = Get-WalletAddress -N $Cfg.B
    if (-not $dest) { throw 'wallet B address unavailable' }
    $atomic = [uint64]([decimal]$SendAmount * $AtomicPerMeep)
    Invoke-WalletRpc -Port $Cfg.A.WalletRpc -Method 'refresh' | Out-Null
    $r = Invoke-WalletRpc -Port $Cfg.A.WalletRpc -Method 'transfer' -Params @{
        destinations = @(@{ amount = $atomic; address = $dest })
        account_index = 0
        priority = 0
        get_tx_key = $true
    }
    if ($r) {
        Write-Ok "tx_hash: $($r.tx_hash)"
        Write-Host "  amount: $($r.amount) atomic   fee: $($r.fee) atomic"
        return $r.tx_hash
    }
    Write-Warn2 'transfer failed — is the mined reward unlocked yet?'
    return $null
}

function Do-Reset {
    Write-Step 'Resetting devnet chain data'
    Write-Warn2 'This deletes CHAIN DATA for both nodes. Wallet files are preserved.'
    Stop-AllDevnet | Out-Null
    Invoke-Wsl "rm -rf $($Cfg.DataRoot)/nodeA $($Cfg.DataRoot)/nodeB" | Out-Null
    Write-Ok 'chain data removed (wallets kept — delete $HOME/.meepcoin-devnet/wallets to wipe those too)'
}

switch ($Action) {
    'build'          { Do-Build }
    'start-node-a'   { Start-Node -N $Cfg.A -Peer $Cfg.B }
    'start-node-b'   { Start-Node -N $Cfg.B -Peer $Cfg.A }
    'create-wallets' { Do-CreateWallets }
    'mine-start'     { Do-MineStart }
    'mine-stop'      { Do-MineStop }
    'balances'       { Do-Balances }
    'send'           { Do-Send | Out-Null }
    'status'         { Do-Status }
    'reset'          { Do-Reset }
    'demo'           { & $PSCommandPath -Action 'reset' }
}
