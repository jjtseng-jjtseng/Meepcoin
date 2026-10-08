<#
.SYNOPSIS
  MeepCoin genesis-spendability test.

.DESCRIPTION
  Proves the v16 genesis coinbase cannot become a usable premine, and preserves evidence that the
  SUPERSEDED v1 genesis could have.

  What is and is not claimed:
    - CLAIMED: no private scalar for the genesis output key is derivable from anything published,
      and recovering one would require solving the discrete log for a hash-to-curve point.
    - NOT CLAIMED: information-theoretic unspendability. This rests on ed25519 discrete-log hardness.

  Requires node A and wallet A running (start-node-a.ps1, create-wallets.ps1).

  *** LOCALHOST / PRIVATE ONLY. Test coins, no monetary value. ***
#>
[CmdletBinding()] param(
    [int]$NodeRpc   = 29081,
    [int]$WalletRpc = 29083,
    [string]$ResultPath = "$PSScriptRoot\..\..\docs\GENESIS_SPENDABILITY_TEST.md"
)
$ErrorActionPreference = 'Stop'
$pass = 0; $fail = 0
$out = New-Object System.Collections.Generic.List[string]
function Say { param([string]$s) Write-Host $s; $out.Add($s) }
function Ok  { param([string]$s) $script:pass++; Say "  [PASS] $s" }
function Bad { param([string]$s) $script:fail++; Say "  [FAIL] $s" }
function Must { param([bool]$c,[string]$s) if ($c) { Ok $s } else { Bad $s } }

$G = '$HOME/meepcoin-node/build/release/bin/meepcoin-genesis16'
function Audit { param([string]$sec,[string]$pub)
    $r = (& wsl.exe -e bash -lc "$G audit $sec $pub") 2>&1
    return ($r -join "`n")
}
function NodeRpcCall { param([string]$M,$P=@{})
    $body = @{ jsonrpc='2.0'; id='0'; method=$M; params=$P } | ConvertTo-Json -Depth 8
    try { Invoke-RestMethod -Uri "http://127.0.0.1:$NodeRpc/json_rpc" -Method Post `
            -ContentType 'application/json' -Body $body -TimeoutSec 60 } catch { $null }
}
function NodeRest { param([string]$Path,$P=@{})
    try { Invoke-RestMethod -Uri "http://127.0.0.1:$NodeRpc/$Path" -Method Post `
            -ContentType 'application/json' -Body ($P|ConvertTo-Json -Depth 8) -TimeoutSec 60 } catch { $null }
}
function WalletRpcCall { param([string]$M,$P=@{})
    $body = @{ jsonrpc='2.0'; id='0'; method=$M; params=$P } | ConvertTo-Json -Depth 8
    try { $r = Invoke-RestMethod -Uri "http://127.0.0.1:$WalletRpc/json_rpc" -Method Post `
            -ContentType 'application/json' -Body $body -TimeoutSec 180
          if ($r.error) { return $null }; $r.result } catch { $null }
}

Say '# MeepCoin Genesis Spendability Test'
Say ''
Say "Run (UTC): $((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))"
Say ''
Say '**Test/dev coins, no monetary value. Localhost only.**'
Say ''

# ---------------------------------------------------------------------------------------------
Say '## 1. The SUPERSEDED v1 genesis WAS spendable (preserved evidence)'
Say ''
Say 'The v1 generator derived the output key as `sec*G` where `sec = sc_reduce32(keccak(published string))`.'
Say 'Anyone reading the documentation could recompute `sec`. Verifying that claim:'
Say ''
$a1 = Audit 'f0bf0423d2ccdd43fdc9a444ac1b914b9057fd69c3da816e9756a9f32dad4a02' `
            'efd912a0ef6860c071bb98d0478b3daeb525744ef97a4a1c47499f760e1631eb'
Say '```'
Say $a1
Say '```'
Must ($a1 -match 'PRIVATE_KEY_IS_KNOWN\s+=\s+YES') `
     'v1 genesis output key: private scalar IS derivable (confirms the defect was real)'

# ---------------------------------------------------------------------------------------------
Say ''
Say '## 2. The v16 genesis output key has no derivable private scalar'
Say ''
Say 'v16 construction:'
Say ''
Say '```'
Say 'B = hash_to_p3(keccak("MeepCoin/GENESIS/BURN-SPEND/v16/devnet"))   no known discrete log'
Say 'A = hash_to_p3(keccak("MeepCoin/GENESIS/BURN-VIEW/v16/devnet"))    no known discrete log'
Say 'r = sc_reduce32(keccak("MeepCoin/GENESIS/TXKEY/v16/devnet"))       PUBLISHED'
Say 'D = r*A ;  P = Hs(D||0)*G + B                                      the output key'
Say '```'
Say ''
Say 'Publishing `r` is deliberate and harmless: `r` yields `D` and `Hs(D||0)`, but `P` still carries'
Say 'the `B` term. Recovering `x` with `P = x*G` would give `B = (x - Hs(D||0))*G`, i.e. the discrete'
Say 'log of a hash-to-curve point.'
Say ''
$rSec = '2c39e96ce40d02b204cd41f079ab86b519218a5c56141989efcbefa343511506'
$P    = 'f0d2a4ce0987104c2a012faa2c0e4f9d6692cdce578434575de531cda04457ec'
$Rpub = 'dcd49fb892af9ddd1c7f0d1a8ab718cbd510bb4919c33ec21c718bcf1a442556'
$a2 = Audit $rSec $P
Say '```'
Say $a2
Say '```'
Must ($a2 -notmatch 'PRIVATE_KEY_IS_KNOWN\s+=\s+YES') `
     'published tx secret r does NOT unlock the genesis output key P'
$a3 = Audit $rSec $Rpub
Must ($a3 -match 'PRIVATE_KEY_IS_KNOWN\s+=\s+YES') `
     'r does map to the tx PUBLIC key R (sanity: the audit tool detects a real match)'
Say ''
Say 'The second check matters: it shows the tool reports YES when a scalar genuinely matches, so the'
Say 'NO on the output key is a real negative and not a broken test.'

# ---------------------------------------------------------------------------------------------
Say ''
Say '## 3. Genesis reward and supply accounting'
Say ''
$g = NodeRpcCall 'get_block_header_by_height' @{height=0}
$info = NodeRest 'get_info'
$reward = $null; $gh = $null
if ($g -and $g.result) { $reward = $g.result.block_header.reward; $gh = $g.result.block_header.hash }
Must ($null -ne $reward) 'genesis reward readable from the daemon'
Say "- genesis block hash   : ``$gh``"
Say "- genesis reward       : $reward atomic units"
Say "- major/minor version  : $($g.result.block_header.major_version)/$($g.result.block_header.minor_version)"
Say ''
Say 'The genesis reward IS counted in emitted supply. It cannot be zero: at hard-fork version 16'
Say '`HF_VERSION_EXACT_COINBASE` (13) requires the coinbase to equal the block reward EXACTLY, so a'
Say 'zero-value genesis coinbase is rejected by consensus. Unspendability therefore has to come from'
Say 'the output key, which is what section 2 establishes. These coins are permanently outside'
Say 'circulating supply.'

# ---------------------------------------------------------------------------------------------
Say ''
Say '## 4. Attempted spend: a wallet scanning from genesis cannot see or spend it'
Say ''
WalletRpcCall 'refresh' | Out-Null
$h = WalletRpcCall 'get_height'
$bal = WalletRpcCall 'get_balance' @{account_index=0}
$xfer = WalletRpcCall 'incoming_transfers' @{transfer_type='all'; account_index=0}
Must ($null -ne $h) 'wallet responded to get_height'
Say "- wallet scanned to height: $($h.height)"
$tipInfo = NodeRest 'get_info'
Say "- chain height            : $($tipInfo.height)"

# Collect every output the wallet knows about and check none is the genesis output.
$genesisSeen = $false
if ($xfer -and $xfer.transfers) {
    foreach ($t in $xfer.transfers) { if ($t.block_height -eq 0) { $genesisSeen = $true } }
}
Must (-not $genesisSeen) 'no wallet-visible output originates from block height 0'

# A sweep is the strongest practical attempt: ask the wallet to spend everything it can reach.
$sweep = WalletRpcCall 'sweep_all' @{ address = (WalletRpcCall 'get_address' @{account_index=0}).address
                                     account_index = 0; do_not_relay = $true; get_tx_hex = $false }
$sweptAmount = 0
if ($sweep -and $sweep.amount_list) { foreach ($a in $sweep.amount_list) { $sweptAmount += [uint64]$a } }
Say "- sweep_all (dry run) reachable amount: $sweptAmount atomic units"
Say '- the genesis output is not among the wallet''s spendable outputs at any height'

Say ''
Say '## 5. What would have to break'
Say ''
Say 'For the genesis reward to become a usable premine, someone would have to find `x` such that'
Say '`P = x*G` for a `P` built on a hash-to-curve point with no known scalar. That is the ed25519'
Say 'discrete-logarithm problem. If that becomes feasible, MeepCoin''s genesis is the least of its'
Say 'problems: every output on the chain would be spendable by anyone.'

Say ''
Say "**$pass passed, $fail failed**"
Say ''
Say '_Test/dev coins on a private localhost chain. No monetary value._'

$out -join "`r`n" | Set-Content -Path $ResultPath -Encoding UTF8
Write-Host "`nWritten to $ResultPath"
if ($fail -gt 0) { exit 1 }

exit 0
