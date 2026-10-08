# Measure LOCAL CPU power for the MeepHash-W v2 efficiency gate.
#
# METHOD (documented honestly): Windows exposes no CPU *package* power on this AMD part without
# third-party kernel drivers, so this uses the ACPI battery's instantaneous DischargeRate (mW) via
# root\wmi\BatteryStatus. That is **whole-system wall power**, not CPU package power. The laptop
# must therefore be **running on battery** (unplugged) for the counter to be non-zero.
#
# To make the number comparable to a GPU *board* power figure, we report BOTH:
#   * absolute whole-system load power, and
#   * the incremental delta over an idle baseline (load - idle), which attributes to the workload
#     the power it actually adds, excluding the display/SoC idle floor.
#
# Sampling covers ONLY the miner's steady-state window (between its STEADY_BEGIN / STEADY_END
# markers); dataset build, thread startup and post-run idle are excluded.
#
# Usage: powershell -ExecutionPolicy Bypass -File scripts/measure_cpu_power.ps1 [threads] [seconds]

param([int]$Threads = 16, [double]$Seconds = 60)

$ErrorActionPreference = "Stop"

function Get-BatteryW {
    $bs = Get-CimInstance -Namespace root\wmi -ClassName BatteryStatus -ErrorAction SilentlyContinue |
          Select-Object -First 1
    if (-not $bs) { return $null }
    [pscustomobject]@{
        OnAC       = [bool]$bs.PowerOnline
        Charging   = [bool]$bs.Charging
        DischargeW = [double]$bs.DischargeRate / 1000.0    # mW -> W
        ChargeW    = [double]$bs.ChargeRate / 1000.0
        VoltageV   = [double]$bs.Voltage / 1000.0
    }
}

$probe = Get-BatteryW
if (-not $probe) { Write-Host "RESULT: INCONCLUSIVE - no BatteryStatus counter available"; exit 2 }
Write-Host ("battery counter OK  OnAC={0} Charging={1} V={2:N2}" -f $probe.OnAC, $probe.Charging, $probe.VoltageV)
if ($probe.OnAC) {
    Write-Host ""
    Write-Host "!!! ON AC POWER - DischargeRate reads 0, so wall power CANNOT be measured. !!!"
    Write-Host "!!! Unplug the charger and re-run this script to obtain the CPU denominator. !!!"
    Write-Host "RESULT: INCONCLUSIVE - on AC"
    exit 3
}

# ---- idle baseline (20 s) ----
Write-Host "sampling idle baseline (20 s)..."
$idle = @()
$t0 = Get-Date
while (((Get-Date) - $t0).TotalSeconds -lt 20) {
    $b = Get-BatteryW
    if ($b -and $b.DischargeW -gt 0) { $idle += $b.DischargeW }
    Start-Sleep -Milliseconds 250
}

# ---- run miner, sample only inside its steady-state window ----
Write-Host "running sustained miner ($Threads threads, $Seconds s) and sampling load power..."
$out = New-TemporaryFile
$proc = Start-Process -FilePath "wsl" `
    -ArgumentList @("-e","bash","-lc","cd /mnt/c/Users/tseng/meepcoin/meepow && ./build/optimized/meepow-v2-sustained $Threads $Seconds") `
    -RedirectStandardOutput $out -NoNewWindow -PassThru

$load = @(); $steady = $false
while (-not $proc.HasExited) {
    $txt = Get-Content $out -Raw -ErrorAction SilentlyContinue
    if ($txt -match 'STEADY_BEGIN') { $steady = $true }
    if ($txt -match 'STEADY_END')   { $steady = $false }
    if ($steady) {
        $b = Get-BatteryW
        if ($b -and $b.DischargeW -gt 0) { $load += $b.DischargeW }
    }
    Start-Sleep -Milliseconds 250
}
$proc.WaitForExit()
$stdout = Get-Content $out -Raw
Remove-Item $out -Force -ErrorAction SilentlyContinue

$hps = 0.0
if ($stdout -match 'HPS=([0-9.]+)') { $hps = [double]$Matches[1] }

function Stats($a) {
    if (-not $a -or $a.Count -eq 0) { return $null }
    $s = $a | Sort-Object
    [pscustomobject]@{
        N = $a.Count
        Avg = ($a | Measure-Object -Average).Average
        Med = $s[[int]($s.Count/2)]
        Max = ($a | Measure-Object -Maximum).Maximum
        Min = ($a | Measure-Object -Minimum).Minimum
    }
}
$si = Stats $idle; $sl = Stats $load

Write-Host ""
Write-Host "=== CPU POWER (whole-system wall power via battery discharge) ==="
if ($si) { Write-Host ("idle : n={0} avg={1:N1} W med={2:N1} W" -f $si.N, $si.Avg, $si.Med) }
if ($sl) { Write-Host ("load : n={0} avg={1:N1} W med={2:N1} W peak={3:N1} W" -f $sl.N, $sl.Avg, $sl.Med, $sl.Max) }
if ($si -and $sl) {
    $delta = $sl.Med - $si.Med
    Write-Host ("delta (load - idle) = {0:N1} W   (incremental power attributable to the miner)" -f $delta)
    Write-Host ("miner throughput    = {0:N2} H/s" -f $hps)
    if ($sl.Med -gt 0) { Write-Host ("H/s per watt (whole-system load) = {0:N3}" -f ($hps / $sl.Med)) }
    if ($delta -gt 0)  { Write-Host ("H/s per watt (incremental delta) = {0:N3}" -f ($hps / $delta)) }
    Write-Host "SOURCE: whole-system wall power (ACPI battery discharge), NOT CPU package power."
} else {
    Write-Host "RESULT: INCONCLUSIVE - insufficient non-zero samples"
    exit 4
}
