<#
.SYNOPSIS
  Installs (or updates) Sysmon on a Windows lab VM and makes the Wazuh agent collect its logs.
  Built for testing the Wazuh RMM Abuse Detection Pack.

.WHAT IT DOES
  1. Downloads the latest Sysmon from Microsoft Sysinternals.
  2. Writes a lab config that logs:
       - Event ID 1  Process creation      (every process)
       - Event ID 3  Network connections   (every process except the Wazuh agent)
       - Event ID 22 DNS queries           (every process except the Wazuh agent)
     Everything else is switched off to keep the lab quiet.
  3. Installs Sysmon, or updates the config if Sysmon is already installed.
  4. Adds the Sysmon channel to the Wazuh agent's ossec.conf (backup taken first).
  5. Restarts the Wazuh agent and shows the latest Sysmon events as proof.

.HOW TO RUN
  Right-click PowerShell > Run as administrator, then:
    Set-ExecutionPolicy -Scope Process Bypass -Force
    .\Install-Sysmon-Wazuh.ps1

.NOTE
  This config is for a LAB. Logging every process, connection and DNS query
  is too noisy for production.
#>

$ErrorActionPreference = 'Stop'

# --- 0. Must run as Administrator ------------------------------------------------
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
          [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) { Write-Host "Run this script in PowerShell as Administrator." -ForegroundColor Red; exit 1 }

$SysmonDir   = 'C:\Sysmon'
$ConfigPath  = Join-Path $SysmonDir 'sysmon-rmm-lab.xml'
$OssecConf   = 'C:\Program Files (x86)\ossec-agent\ossec.conf'
$SysmonChan  = 'Microsoft-Windows-Sysmon/Operational'

function Step($t) { Write-Host "`n==> $t" -ForegroundColor Cyan }

# --- 1. Download Sysmon ----------------------------------------------------------
Step "Downloading Sysmon from Microsoft Sysinternals"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
New-Item -ItemType Directory -Force -Path $SysmonDir | Out-Null
$zip = Join-Path $SysmonDir 'Sysmon.zip'
Invoke-WebRequest -Uri 'https://download.sysinternals.com/files/Sysmon.zip' -OutFile $zip -UseBasicParsing
Expand-Archive -Path $zip -DestinationPath $SysmonDir -Force
$exe = if ([Environment]::Is64BitOperatingSystem) { Join-Path $SysmonDir 'Sysmon64.exe' } else { Join-Path $SysmonDir 'Sysmon.exe' }
if (-not (Test-Path $exe)) { throw "Sysmon executable not found after download." }
Write-Host "Sysmon downloaded to $SysmonDir"

# --- 2. Lab config ---------------------------------------------------------------
Step "Writing lab config to $ConfigPath"
$config = @'
<Sysmon schemaversion="4.90">
  <HashAlgorithms>sha256</HashAlgorithms>
  <CheckRevocation/>
  <EventFiltering>

    <!-- Event ID 1: log every process start -->
    <RuleGroup name="ProcessCreate" groupRelation="or">
      <ProcessCreate onmatch="exclude"/>
    </RuleGroup>

    <!-- Event ID 3: log every network connection, except the Wazuh agent itself -->
    <RuleGroup name="NetworkConnect" groupRelation="or">
      <NetworkConnect onmatch="exclude">
        <Image condition="contains">ossec-agent</Image>
      </NetworkConnect>
    </RuleGroup>

    <!-- Event ID 22: log every DNS query, except the Wazuh agent itself -->
    <RuleGroup name="DnsQuery" groupRelation="or">
      <DnsQuery onmatch="exclude">
        <Image condition="contains">ossec-agent</Image>
      </DnsQuery>
    </RuleGroup>

    <!-- Everything else: off (empty include = log nothing) -->
    <RuleGroup groupRelation="or"><ProcessTerminate onmatch="include"/></RuleGroup>
    <RuleGroup groupRelation="or"><FileCreateTime onmatch="include"/></RuleGroup>
    <RuleGroup groupRelation="or"><DriverLoad onmatch="include"/></RuleGroup>
    <RuleGroup groupRelation="or"><ImageLoad onmatch="include"/></RuleGroup>
    <RuleGroup groupRelation="or"><CreateRemoteThread onmatch="include"/></RuleGroup>
    <RuleGroup groupRelation="or"><RawAccessRead onmatch="include"/></RuleGroup>
    <RuleGroup groupRelation="or"><ProcessAccess onmatch="include"/></RuleGroup>
    <RuleGroup groupRelation="or"><FileCreate onmatch="include"/></RuleGroup>
    <RuleGroup groupRelation="or"><RegistryEvent onmatch="include"/></RuleGroup>
    <RuleGroup groupRelation="or"><FileCreateStreamHash onmatch="include"/></RuleGroup>
    <RuleGroup groupRelation="or"><PipeEvent onmatch="include"/></RuleGroup>
    <RuleGroup groupRelation="or"><WmiEvent onmatch="include"/></RuleGroup>
    <RuleGroup groupRelation="or"><FileDelete onmatch="include"/></RuleGroup>
    <RuleGroup groupRelation="or"><ClipboardChange onmatch="include"/></RuleGroup>
    <RuleGroup groupRelation="or"><ProcessTampering onmatch="include"/></RuleGroup>
    <RuleGroup groupRelation="or"><FileDeleteDetected onmatch="include"/></RuleGroup>

  </EventFiltering>
</Sysmon>
'@
Set-Content -Path $ConfigPath -Value $config -Encoding ASCII

# --- 3. Install or update Sysmon -------------------------------------------------
$svc = Get-Service -Name 'Sysmon64','Sysmon' -ErrorAction SilentlyContinue | Select-Object -First 1
if ($svc) {
    Step "Sysmon already installed ($($svc.Name)) - updating config"
    & $exe -c $ConfigPath | Out-Host
} else {
    Step "Installing Sysmon"
    & $exe -accepteula -i $ConfigPath | Out-Host
}
if ($LASTEXITCODE -ne 0) { throw "Sysmon returned exit code $LASTEXITCODE. Check the output above." }

# --- 4. Tell the Wazuh agent to collect Sysmon -----------------------------------
Step "Configuring the Wazuh agent"
if (-not (Test-Path $OssecConf)) { throw "Wazuh agent config not found at $OssecConf. Is the agent installed?" }
$conf = Get-Content -Path $OssecConf -Raw
if ($conf -match [regex]::Escape($SysmonChan)) {
    Write-Host "Sysmon channel already present in ossec.conf - no change needed."
} else {
    $backup = "$OssecConf.bak-$(Get-Date -Format 'yyyyMMdd-HHmmss')"
    Copy-Item $OssecConf $backup
    Write-Host "Backup saved: $backup"
    $block = @"

  <!-- Sysmon (added by Install-Sysmon-Wazuh.ps1) -->
  <localfile>
    <location>$SysmonChan</location>
    <log_format>eventchannel</log_format>
  </localfile>

</ossec_config>
"@
    $idx = $conf.LastIndexOf('</ossec_config>')
    if ($idx -lt 0) { throw "Could not find </ossec_config> in ossec.conf." }
    $conf = $conf.Substring(0, $idx) + $block.TrimStart("`r","`n") + $conf.Substring($idx + '</ossec_config>'.Length)
    Set-Content -Path $OssecConf -Value $conf -Encoding ASCII
    Write-Host "Sysmon channel added to ossec.conf"
}

# --- 5. Restart agent and verify -------------------------------------------------
Step "Restarting the Wazuh agent"
Restart-Service -Name WazuhSvc -Force
Start-Sleep -Seconds 5
$agent = Get-Service -Name WazuhSvc
Write-Host "Wazuh agent status: $($agent.Status)"

Step "Generating a test DNS lookup and reading the newest Sysmon events"
try { Resolve-DnsName example.com -ErrorAction SilentlyContinue | Out-Null } catch {}
Start-Sleep -Seconds 3
Get-WinEvent -LogName $SysmonChan -MaxEvents 5 |
    Select-Object TimeCreated, Id, @{n='Summary';e={ ($_.Message -split "`n")[0] }} |
    Format-Table -AutoSize | Out-Host

Write-Host "`nDone. Sysmon is running and the Wazuh agent is collecting its logs." -ForegroundColor Green
Write-Host "You should see Event IDs 1 (process), 3 (network) and 22 (DNS) above."
