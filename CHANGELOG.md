# Changelog

## v1.0.0 - 2026-11-10

First public release, verified on Wazuh 4.14.10 with a Windows 11 agent and Sysmon 15.22.

- 47 detection rules covering 23 remote access / RMM tools (MITRE ATT&CK T1219).
- Behaviour rules: renamed binary by `OriginalFileName` (100900) or `Product` (100902), RMM tool launching a shell (100901).
- Tool-started rules (100910 - 100931) and DNS rules (100940 - 100959).
- Correlation: tool run from a user-writable folder (100971), two or more vendors on one host within 10 minutes (100970).
- Allowlist for approved tools (100975 - 100998), disabled by default.
- Installer with config validation and automatic rollback.
- Wazuh dashboard (`dashboards/rmm-abuse-dashboard.ndjson`).
- Safe test script and lab Sysmon installer.

### Fixed during testing
- An allowlist file with every rule commented out failed to load; added a placeholder rule.
- AnyDesk ships without an `OriginalFileName`; added product-based renamed-binary rule 100902.
- Wazuh stores Windows paths with doubled backslashes; path rules now accept one or more.
- Security agents (Defender for Endpoint and others) resolve domains they observe; excluded from DNS rules.
- `if_matched_group` links only to rules loaded earlier; the correlation rule is now placed last and the folder rule counts towards it.
