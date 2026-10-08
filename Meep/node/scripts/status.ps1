# MeepCoin devnet — status
# Thin wrapper. All logic lives in devnet.ps1 so there is one implementation to keep correct.
# LOCALHOST/PRIVATE ONLY. All coins are DEV/TEST coins with NO monetary value.
param([Parameter(ValueFromRemainingArguments = $true)]$Rest)
& "$PSScriptRoot\devnet.ps1" -Action 'status' @Rest
