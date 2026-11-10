#!/usr/bin/env bash
# Wazuh RMM Abuse Detection Pack - installer for the Wazuh MANAGER
# Usage (from the repository folder):  sudo bash install.sh
# Uninstall:                            sudo bash install.sh --uninstall
set -euo pipefail

RULES_DIR=/var/ossec/etc/rules
FILES=(rmm_abuse_rules.xml rmm_allowlist.xml)
HERE="$(cd "$(dirname "$0")" && pwd)"
STAMP=$(date +%Y%m%d-%H%M%S)
BACKUP="/var/ossec/etc/rmm-pack-backup-$STAMP"

say()  { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
ok()   { printf '\033[1;32m%s\033[0m\n' "$*"; }
fail() { printf '\033[1;31m%s\033[0m\n' "$*"; exit 1; }

[ "$(id -u)" -eq 0 ] || fail "Run with sudo:  sudo bash install.sh"
[ -d "$RULES_DIR" ]  || fail "No Wazuh manager found ($RULES_DIR missing). Run this on the Wazuh manager."

if [ "${1:-}" = "--uninstall" ]; then
  say "Removing the RMM pack"
  for f in "${FILES[@]}"; do rm -f "$RULES_DIR/$f" && echo "removed $RULES_DIR/$f"; done
  /var/ossec/bin/wazuh-analysisd -t || fail "Config test failed after removal. Check the output above."
  systemctl restart wazuh-manager && ok "Uninstalled. Wazuh manager restarted."
  exit 0
fi

say "Checking Wazuh version"
/var/ossec/bin/wazuh-control info | grep -E 'VERSION' || true

say "Backing up any existing pack files to $BACKUP"
mkdir -p "$BACKUP"
for f in "${FILES[@]}"; do
  [ -f "$RULES_DIR/$f" ] && cp -p "$RULES_DIR/$f" "$BACKUP/" && echo "backed up $f"
done
# Keep the user's approved tools if they already edited the allowlist
if [ -f "$RULES_DIR/rmm_allowlist.xml" ]; then
  KEEP_ALLOWLIST=1; echo "Existing rmm_allowlist.xml found - keeping your approved tools."
else
  KEEP_ALLOWLIST=0
fi

say "Installing rules into $RULES_DIR"
install -m 660 -o wazuh -g wazuh "$HERE/rules/rmm_abuse_rules.xml" "$RULES_DIR/"
[ "$KEEP_ALLOWLIST" -eq 1 ] || install -m 660 -o wazuh -g wazuh "$HERE/rules/rmm_allowlist.xml" "$RULES_DIR/"

say "Testing the configuration (wazuh-analysisd -t)"
if ! /var/ossec/bin/wazuh-analysisd -t; then
  printf '\033[1;31mConfig test FAILED - rolling back.\033[0m\n'
  for f in "${FILES[@]}"; do
    if [ -f "$BACKUP/$f" ]; then cp -p "$BACKUP/$f" "$RULES_DIR/"; else rm -f "$RULES_DIR/$f"; fi
  done
  fail "Rolled back. Nothing was changed. Send the error above to the maintainer."
fi

say "Restarting the Wazuh manager"
systemctl restart wazuh-manager
sleep 3
systemctl is-active --quiet wazuh-manager || fail "wazuh-manager did not start. Check: journalctl -u wazuh-manager -n 50"

ok "
RMM Abuse Detection Pack installed.
  Rules:     $RULES_DIR/rmm_abuse_rules.xml   (IDs 100900-100971)
  Allowlist: $RULES_DIR/rmm_allowlist.xml     (IDs 100975-100997)
  Backup:    $BACKUP

Next: run tests/Invoke-RmmSimulation.ps1 on a Windows agent, then search the
Wazuh dashboard for:  rule.groups:rmm_detection"
