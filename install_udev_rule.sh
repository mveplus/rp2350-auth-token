#!/usr/bin/env bash
set -euo pipefail

RULE_SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/udev/99-rp2350-token.rules"
RULE_DST="/etc/udev/rules.d/99-rp2350-token.rules"

if [[ ! -f "$RULE_SRC" ]]; then
  echo "Missing rule file: $RULE_SRC" >&2
  exit 1
fi

echo "Installing $RULE_SRC -> $RULE_DST"
sudo install -m 0644 "$RULE_SRC" "$RULE_DST"
sudo udevadm control --reload-rules
sudo udevadm trigger

echo "Done. Replug the token and test: python3 test_hid.py"
