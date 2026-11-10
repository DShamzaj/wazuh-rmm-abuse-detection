# RMM Abuse Detection dashboard

One file, `rmm-abuse-dashboard.ndjson`, with a ready-made Wazuh dashboard for the RMM Abuse Detection Pack.

## What it shows

| Panel | Purpose |
|---|---|
| Guide | What each alert level means |
| Total alerts, Critical alerts, Affected hosts, Distinct executables | Headline numbers. Critical turns red when above zero. |
| Alerts by detection | Renamed (12), opened shell (12), multi-vendor (12), user folder (10), tool started (8), DNS lookup (6) |
| Tools seen (vendor) | Which RMM vendors were detected (allowlisted tools do not appear) |
| Alerts over time by detection | Timeline, stacked by detection type |
| Hosts | Alert count and highest level per computer |
| Executables and users | Which file ran, and as which user |
| Domains contacted | RMM service domains looked up, and from which host |
| Latest alerts | The raw alerts, newest first |

Default time range: last 24 hours.

## Import (Wazuh 4.14)

1. Open the Wazuh dashboard.
2. Menu (☰) → **Dashboard management** → **Dashboards Management** → **Saved objects**.
3. Click **Import**, choose `rmm-abuse-dashboard.ndjson`, keep **Check for existing objects** selected, and click **Import**.
4. Open Menu (☰) → **Dashboards** (under Explore) → **RMM Abuse Detection**.

## Troubleshooting

- **"Index pattern not found" during import:** select `wazuh-alerts-*` in the dropdown the import dialog shows, then confirm.
- **A panel says a field is invalid or missing** (most likely "Domains contacted" before any DNS alert exists): go to **Dashboards Management → Index patterns → wazuh-alerts-\*** and click the **refresh fields** button (circular arrows), then reload the dashboard.
- **Dashboard is empty:** widen the time range, or run `tests/Invoke-RmmSimulation.ps1` on a Windows agent to generate test alerts.

## Remove

Saved objects → search `RMM` → select all → **Delete**.
