# Wazuh RMM Abuse Detection Pack

**Detect unauthorized remote access tools (AnyDesk, ScreenConnect, TeamViewer and 20 more) on Windows endpoints with Wazuh and Sysmon.**

Attackers increasingly install legitimate remote monitoring and management (RMM) software instead of custom malware. It is signed, trusted by antivirus, and blends in with normal IT work, which makes it a favourite for ransomware operators to keep access, move laterally and run commands (MITRE ATT&CK **T1219 Remote Access Software**).

Wazuh's default ruleset has no coverage for these tools. This pack adds it: tool-launch detection, DNS lookups to RMM services, and high-confidence behaviour rules for renamed binaries, shells spawned by RMM tools and multiple vendors on one machine. An allowlist keeps your organisation's approved RMM tool quiet.

> **Disclaimer:** This is an independent community project. It is not affiliated with, endorsed by, or supported by Wazuh, Inc. "Wazuh" is a trademark of Wazuh, Inc.

---

## Contents

- [How it works](#how-it-works)
- [Detection logic](#detection-logic)
- [Covered tools](#covered-tools)
- [Requirements](#requirements)
- [Installation](#installation)
- [Approving your organisation's RMM tool](#approving-your-organisations-rmm-tool)
- [Testing](#testing)
- [SOC workflow: triaging an alert](#soc-workflow-triaging-an-alert)
- [Limitations](#limitations)
- [Uninstall](#uninstall)
- [Roadmap](#roadmap)

---

## How it works

```
Windows endpoint                         Wazuh manager
┌───────────────────────┐               ┌──────────────────────────────────────────┐
│ AnyDesk.exe starts    │               │ Default Sysmon rules (61603 / 61650)      │
│        │              │               │        │                                 │
│ Sysmon Event 1 / 22   │──── agent ───►│ RMM pack                                 │
│ (process, DNS query)  │               │   behaviour rules   100900 - 100902      │
└───────────────────────┘               │   tool started      100910 - 100931      │
                                        │   DNS lookup        100940 - 100959      │
                                        │   correlation       100970 - 100971      │
                                        │   allowlist         100975 - 100998      │
                                        │        │                                 │
                                        │        ▼                                 │
                                        │ Alert in wazuh-alerts-* (MITRE T1219)    │
                                        └──────────────────────────────────────────┘
```

1. **Sysmon** on the endpoint records process creation (Event ID 1) and DNS queries (Event ID 22).
2. The **Wazuh agent** forwards the `Microsoft-Windows-Sysmon/Operational` channel.
3. Wazuh's default Sysmon rules classify the event (`sysmon_event1`, `sysmon_event_22`).
4. This pack's rules, attached to those groups, decide whether it is RMM activity and how serious it is.

---

## Detection logic

| Rule ID | Level | Name | Fires when | Why it matters |
|---|---|---|---|---|
| 100900 | 12 | Renamed RMM binary (by file name) | The file's internal `OriginalFileName` is an RMM tool, but the file on disk has an unrelated name | Renaming is a deliberate attempt to hide. Legitimate IT rarely does this. Also maps to T1036.003. |
| 100902 | 12 | Renamed RMM binary (by product) | The file's `Product` is an RMM tool (for example `AnyDesk`), but the file on disk has an unrelated name | Covers tools such as AnyDesk that ship without an `OriginalFileName`. Also maps to T1036.003. |
| 100901 | 12 | RMM tool launched a shell | An RMM process starts `cmd`, `powershell`, `pwsh`, `wscript`, `cscript`, `mshta`, `rundll32` or `regsvr32` | Hands-on-keyboard activity through a remote tool. Also maps to T1059. |
| 100910 – 100931 | 8 | RMM tool started | A known RMM executable starts (one rule per vendor) | Baseline visibility: who runs which remote tool, where. |
| 100940 – 100959 | 6 | DNS lookup to an RMM service | A process other than a browser or security agent resolves a vendor's service domain | Catches tools by their network behaviour, even when renamed. Also catches PowerShell downloading an RMM tool. Browsers and security agents (Defender for Endpoint, Defender AV, CrowdStrike, SentinelOne, Elastic, Cortex XDR, Tanium) are excluded, because they resolve domains they observe. |
| 100970 | 12 | Multiple RMM vendors | RMM tools from **two different vendors** (by signed `Company`) start on the same computer within 10 minutes | Attackers often deploy a second tool as backup access. Rare in normal IT. |
| 100971 | 10 | Run from a user-writable folder | An RMM tool runs from Downloads, Desktop, Documents, `AppData\Local\Temp`, `C:\Windows\Temp`, `C:\Users\Public` or `C:\Temp` | Portable or dropped copies, typical of social-engineering and intrusion. Installed tools live in Program Files. |
| 100975 – 100998 | 0 | Allowlist | An approved vendor's "tool started" or "DNS lookup" event | Silences sanctioned tools. Disabled by default. |

**Rule order matters.** Wazuh uses the first matching child rule. The behaviour rules (100900 – 100902) are evaluated before the tool-name rules. Correlation rules (100970, 100971) are children of the tool-started rules, so a single launch produces one alert at the most severe applicable level. Rule 100971 keeps the `rmm_process` group so launches from user folders still count towards the multiple-vendor correlation (100970). Rule 100970 must stay **below** every `rmm_process` rule in the file, because Wazuh links an `if_matched_group` rule only to rules loaded before it.

**Compliance tags:** every rule carries `tsc_CC6.8`, `tsc_CC7.2` (SOC 2), `nist_800_53_SI.4` and `nist_800_53_CM.7`, so alerts appear in Wazuh's compliance dashboards.

---

## Covered tools

| Tool | Process rule | DNS rule | Group |
|---|---|---|---|
| AnyDesk | ✓ | ✓ | `rmm_vendor_anydesk` |
| TeamViewer | ✓ | ✓ | `rmm_vendor_teamviewer` |
| ConnectWise ScreenConnect | ✓ | ✓ | `rmm_vendor_screenconnect` |
| Atera | ✓ | ✓ | `rmm_vendor_atera` |
| Splashtop | ✓ | ✓ | `rmm_vendor_splashtop` |
| RustDesk | ✓ | ✓ | `rmm_vendor_rustdesk` |
| LogMeIn | ✓ | ✓ | `rmm_vendor_logmein` |
| NetSupport Manager | ✓ | ✓ | `rmm_vendor_netsupport` |
| Ammyy Admin | ✓ | ✓ | `rmm_vendor_ammyy` |
| Radmin | ✓ | ✓ | `rmm_vendor_radmin` |
| UltraViewer | ✓ | ✓ | `rmm_vendor_ultraviewer` |
| Supremo | ✓ | ✓ | `rmm_vendor_supremo` |
| AeroAdmin | ✓ | ✓ | `rmm_vendor_aeroadmin` |
| Remote Utilities | ✓ | ✓ | `rmm_vendor_remoteutilities` |
| MeshCentral | ✓ | ✓ | `rmm_vendor_meshcentral` |
| Tactical RMM | ✓ | – | `rmm_vendor_tacticalrmm` |
| NinjaOne | ✓ | ✓ | `rmm_vendor_ninjaone` |
| Action1 | ✓ | ✓ | `rmm_vendor_action1` |
| DWService | ✓ | ✓ | `rmm_vendor_dwservice` |
| Chrome Remote Desktop | ✓ | ✓ | `rmm_vendor_chromeremote` |
| VNC server | ✓ | – | `rmm_vendor_vnc` |
| SimpleHelp | ✓ | – | `rmm_vendor_simplehelp` |
| Zoho Assist | – | ✓ | `rmm_vendor_zohoassist` |

Tools marked – for DNS are usually self-hosted, so there is no fixed vendor domain. Zoho Assist is covered by DNS only.

---

## Requirements

| Component | Version |
|---|---|
| Wazuh manager | 4.14.x (tested on 4.14.10) |
| Wazuh agent | Windows, same major version as the manager |
| Sysmon | v15 or later, logging Event IDs **1** and **22** |
| Agent config | Collecting `Microsoft-Windows-Sysmon/Operational` |

Your Sysmon config must not filter out process creation or DNS queries for these tools. Popular community configs (SwiftOnSecurity, Olaf Hartong's sysmon-modular) log both by default. A lab installer is included: [`tests/Install-Sysmon-Wazuh.ps1`](tests/Install-Sysmon-Wazuh.ps1).

---

## Installation

### 1. Endpoint: Sysmon and the Wazuh agent

If Sysmon is not installed yet, run the included lab script in PowerShell as Administrator:

```powershell
Set-ExecutionPolicy -Scope Process Bypass -Force
.\tests\Install-Sysmon-Wazuh.ps1
```

It installs Sysmon and adds this block to the agent's `ossec.conf` (do it by hand if you already run Sysmon):

```xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

### 2. Manager: the rules

```bash
git clone https://github.com/DShamzaj/wazuh-rmm-abuse-detection.git
cd wazuh-rmm-abuse-detection
sudo bash install.sh
```

The installer copies two files to `/var/ossec/etc/rules/`, validates them with `wazuh-analysisd -t`, rolls back automatically if validation fails, and restarts the manager. Re-running it upgrades the rules and **keeps your existing allowlist**.

Manual install: copy `rules/rmm_abuse_rules.xml` and `rules/rmm_allowlist.xml` to `/var/ossec/etc/rules/`, set owner `wazuh:wazuh` and mode `660`, then `sudo systemctl restart wazuh-manager`.

---

## Approving your organisation's RMM tool

Minimal working example: your IT team uses **TeamViewer**.

Open `/var/ossec/etc/rules/rmm_allowlist.xml`, find the TeamViewer block and remove the comment lines around it:

```xml
<!-- before -->
  <!-- TeamViewer
  <rule id="100976" level="0">
    <if_group>rmm_vendor_teamviewer</if_group>
    <description>Approved RMM tool: TeamViewer (allowlisted)</description>
    <group>rmm_allowed,</group>
  </rule>
  -->

<!-- after -->
  <rule id="100976" level="0">
    <if_group>rmm_vendor_teamviewer</if_group>
    <description>Approved RMM tool: TeamViewer (allowlisted)</description>
    <group>rmm_allowed,</group>
  </rule>
```

Then:

```bash
sudo /var/ossec/bin/wazuh-analysisd -t
sudo systemctl restart wazuh-manager
```

TeamViewer launches and DNS lookups no longer alert. **These still alert, by design**, even for approved tools: a renamed TeamViewer binary (100900), TeamViewer launching a shell (100901) and TeamViewer run from Downloads or Temp (100971).

---

## Testing

`tests/Invoke-RmmSimulation.ps1` triggers the detections safely on a Windows agent. Run it in PowerShell as Administrator:

```powershell
Set-ExecutionPolicy -Scope Process Bypass -Force
.\tests\Invoke-RmmSimulation.ps1                      # safe simulation, no downloads
.\tests\Invoke-RmmSimulation.ps1 -IncludeRealAnyDesk  # also uses the official AnyDesk client
```

| Step | What the script does | Expected rule |
|---|---|---|
| A1 | Copy of `powershell.exe` named `AnyDesk.exe` runs from `C:\Temp` | 100971 |
| A2 | That `AnyDesk.exe` launches `cmd.exe` | 100901 |
| B1 | Official AnyDesk portable runs for 25 s and contacts its relays | 100940 and 100970 (a second vendor after the simulated AnyDesk) |
| B2 | The same AnyDesk renamed to `svc-update.exe` | 100902 (and 100940 for its relay lookups) |
| B3 | Copy of `powershell.exe` named `TeamViewer.exe` | 100971. It is not counted as a new vendor because, as a PowerShell copy, it carries the same `Microsoft` company as step A. A real TeamViewer would raise 100970. |

Part A uses only Windows' own `powershell.exe`, renamed, so nothing is installed and no remote session is possible. Part B downloads AnyDesk from `download.anydesk.com`, verifies its signature, never accepts a connection, and is deleted at the end.

In the Wazuh dashboard, open **Threat Hunting** and search:

```
rule.groups:rmm_detection
```

---

## SOC workflow: triaging an alert

1. **Is the tool approved?** Check your asset or software inventory. If it is approved and the alert is 100910 or 100940, add the vendor to the allowlist.
2. **Who and where?** `win.eventdata.user`, `win.system.computer`, `win.eventdata.image`. Installed tools sit in `Program Files`. A copy in `Downloads` or `Temp` points to a user or attacker download.
3. **How did it start?** `win.eventdata.parentImage` and `win.eventdata.commandLine`. A browser or email client as parent suggests a user download (possible social engineering, such as fake IT-support calls). `cmd`, `powershell` or another RMM tool as parent suggests an attacker.
4. **What did it do?** Search `rule.groups:rmm_shell` and Sysmon events on the same host in the following minutes for shells, new users, credential access or file transfers.
5. **Escalate immediately** for 100900 (renamed), 100901 (shell) and 100970 (multiple vendors). These rarely come from normal IT work. Isolate the host and stop the RMM process. Then check the vendor portal or the tool's own logs for the remote party's ID or IP address.

---

## Limitations

- **Windows only** in v0.1. Linux and macOS RMM agents are on the roadmap.
- **Name-based tool rules (100910 – 100931)** can be bypassed by renaming. Rules 100900 and 100902 catch renamed copies through the file's `OriginalFileName` or `Product` metadata, and the DNS rules still see the tool's traffic. A rebuilt binary with stripped metadata can evade the renamed-binary rules.
- **Windows paths in Wazuh** are stored with doubled backslashes (`C:\\Temp\\...`). All path rules accept one or more backslashes; keep that in mind when writing your own exceptions.
- **DNS rules** depend on Sysmon Event 22. They miss DNS-over-HTTPS, hard-coded IPs and self-hosted servers (MeshCentral, Tactical RMM, SimpleHelp, RustDesk with a private relay).
- **Multiple-vendor correlation (100970)** compares the signed `Company` field. Unsigned tools with an empty `Company` are not counted.
- **First-match rule evaluation:** if another custom or default rule claims the same Sysmon event first, the pack's rule does not fire for that event.
- **Tested** on Wazuh 4.14.10 with Sysmon 15 on Windows 10/11. Tool coverage beyond AnyDesk is based on vendor documentation and public detection research; test reports and pull requests for other tools are welcome.

---

## Uninstall

```bash
sudo bash install.sh --uninstall
```

---

## Roadmap

- Linux and macOS RMM agents (auditd / Endpoint Security)
- Sysmon Event ID 3 network rules for tools with fixed IP ranges
- Service-installation detection (Windows Event 7045) for RMM agents installed as services
- Dashboard: RMM activity by host, vendor and user
- Saudi NCA ECC control mapping, aligned with the [Wazuh NCA ECC compliance pack](https://github.com/DShamzaj/wazuh-nca-ecc-compliance)

---

## License

MIT. See [LICENSE](LICENSE).

## Test results (v1.0.0)

Lab: Wazuh 4.14.10 manager, Windows 11 agent, Sysmon 15.22, Microsoft Defender for Endpoint active. Full run of `Invoke-RmmSimulation.ps1 -IncludeRealAnyDesk`.

| Rule | Scenario | Alerts | Result |
|---|---|---|---|
| 100901 | Simulated AnyDesk launches `cmd.exe` | 1 | Pass |
| 100902 | Real AnyDesk renamed to `svc-update.exe` | 3 | Pass |
| 100940 | AnyDesk relay lookups, including from the renamed copy | 5 | Pass |
| 100970 | Real AnyDesk on a host that already ran another vendor's tool | 3 | Pass |
| 100971 | Remote access tools run from `C:\Temp` | 3 | Pass |
| – | Defender for Endpoint (`MsSense.exe`) DNS lookups | 0 | Pass (no false positives) |

Issues found and fixed during testing: AnyDesk ships without an `OriginalFileName` (added product-based rule 100902), Wazuh stores Windows paths with doubled backslashes (path rules accept one or more), security agents resolve domains they observe (excluded from DNS rules), and `if_matched_group` only links to rules loaded earlier (correlation rule placed last).

---

Built by [Hamza Jameel](https://dshamzaj.github.io), Wazuh Ambassador.
