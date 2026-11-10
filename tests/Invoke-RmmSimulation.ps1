<#
.SYNOPSIS
  Safely simulates remote access tool activity so you can verify the
  Wazuh RMM Abuse Detection Pack end to end.

.DESCRIPTION
  Part A (always, no downloads):
    Uses renamed copies of the built-in powershell.exe placed in C:\Temp\RMM-Test.
    Nothing remote is installed and no remote session is opened.
      A1  "AnyDesk.exe" starts from C:\Temp      -> 100910 tool started / 100971 user-writable folder
      A2  "AnyDesk.exe" launches cmd.exe          -> 100901 RMM tool launched a shell

  Part B (only with -IncludeRealAnyDesk):
    Downloads the official AnyDesk portable client from download.anydesk.com,
    runs it briefly, then closes it. No connection is accepted.
      B1  Real AnyDesk runs and contacts its relays -> 100970 different vendors and 100940 DNS lookup
      B2  The same file renamed to svc-update.exe   -> 100902 renamed remote access tool
      B3  A simulated TeamViewer starts right after -> 100971 (same Microsoft company as step A, so not a new vendor)

  Everything is cleaned up at the end.

.EXAMPLE
  # Run in PowerShell as Administrator on the Windows agent:
  Set-ExecutionPolicy -Scope Process Bypass -Force
  .\Invoke-RmmSimulation.ps1                     # Part A only
  .\Invoke-RmmSimulation.ps1 -IncludeRealAnyDesk # Part A + B
#>
param([switch]$IncludeRealAnyDesk)

$ErrorActionPreference = 'Stop'
$Dir = 'C:\Temp\RMM-Test'
$Ps  = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
$Expected = New-Object System.Collections.ArrayList

function Step($t) { Write-Host "`n==> $t" -ForegroundColor Cyan }
function Expect($rule, $what) { [void]$Expected.Add([pscustomobject]@{ Rule = $rule; 'Expected alert' = $what }) }

if (-not (Get-Service Sysmon64, Sysmon -ErrorAction SilentlyContinue)) {
    Write-Host "Sysmon is not installed. Run Install-Sysmon-Wazuh.ps1 first." -ForegroundColor Red; exit 1
}
New-Item -ItemType Directory -Force -Path $Dir | Out-Null

# ---------------- Part A: safe simulation with renamed powershell.exe ----------------
Step "A1  Simulated AnyDesk starts from C:\Temp"
$fakeAnyDesk = Join-Path $Dir 'AnyDesk.exe'
Copy-Item $Ps $fakeAnyDesk -Force
& $fakeAnyDesk -NoProfile -Command "Start-Sleep -Seconds 1" | Out-Null
Expect 100971 'RMM abuse: remote access tool run from a user-writable folder (AnyDesk.exe)'

Step "A2  Simulated AnyDesk launches cmd.exe"
& $fakeAnyDesk -NoProfile -Command "cmd.exe /c echo rmm-pack-test" | Out-Null
Expect 100901 'RMM abuse: ...AnyDesk.exe launched ...cmd.exe'

# ---------------- Part B: real AnyDesk (optional) ----------------
if ($IncludeRealAnyDesk) {
    Step "B1  Downloading the official AnyDesk portable client"
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $real = Join-Path $Dir 'AnyDesk-real\AnyDesk.exe'
    New-Item -ItemType Directory -Force -Path (Split-Path $real) | Out-Null
    Invoke-WebRequest -Uri 'https://download.anydesk.com/AnyDesk.exe' -OutFile $real -UseBasicParsing
    $sig = Get-AuthenticodeSignature $real
    Write-Host "Signature: $($sig.Status) - $($sig.SignerCertificate.Subject)"
    if ($sig.Status -ne 'Valid') { Write-Host "Signature is not valid. Stopping Part B." -ForegroundColor Red; $IncludeRealAnyDesk = $false }
}
if ($IncludeRealAnyDesk) {
    Step "B1  Running real AnyDesk for 25 seconds (it will contact its relay servers)"
    $p = Start-Process $real -PassThru
    Start-Sleep -Seconds 25
    Get-Process -Name AnyDesk -ErrorAction SilentlyContinue | Stop-Process -Force
    Expect 100940 'RMM network activity: ...looked up AnyDesk service ...anydesk.com'
    Expect 100970 'RMM abuse: remote access tools from different vendors started on <this PC> within 10 minutes (real AnyDesk after the simulated one)'

    Step "B2  Running the same AnyDesk renamed to svc-update.exe"
    $renamed = Join-Path $Dir 'svc-update.exe'
    Copy-Item $real $renamed -Force
    $p = Start-Process $renamed -PassThru
    Start-Sleep -Seconds 8
    Get-Process -Name 'svc-update' -ErrorAction SilentlyContinue | Stop-Process -Force
    Expect 100902 'RMM abuse: renamed remote access tool. AnyDesk by AnyDesk Software GmbH is running as ...svc-update.exe'

    Step "B3  Simulated TeamViewer starts (second vendor within 10 minutes)"
    $fakeTv = Join-Path $Dir 'TeamViewer.exe'
    Copy-Item $Ps $fakeTv -Force
    & $fakeTv -NoProfile -Command "Start-Sleep -Seconds 1" | Out-Null
    Expect 100971 'Simulated TeamViewer from C:\Temp (shares the Microsoft company with step A, so it is not a new vendor)'
}

# ---------------- Cleanup ----------------
Step "Cleaning up"
Start-Sleep -Seconds 2
Get-Process -Name AnyDesk, 'svc-update', TeamViewer -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2
Remove-Item $Dir -Recurse -Force -ErrorAction SilentlyContinue
Write-Host "Removed $Dir"

Write-Host "`nDone. Wait about 1 minute, then in the Wazuh dashboard open Threat Hunting and search:" -ForegroundColor Green
Write-Host "    rule.groups:rmm_detection" -ForegroundColor Yellow
Write-Host "`nYou should see these alerts for agent $env:COMPUTERNAME :"
$Expected | Format-Table -AutoSize | Out-Host
Write-Host "Note: other rmm_detection alerts (for example 100910 'RMM tool started') may also appear. That is expected."
