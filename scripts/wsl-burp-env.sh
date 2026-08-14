#!/usr/bin/env bash
# Source from WSL:  source /mnt/c/Users/ynot_/OneDrive/Desktop/Company\ Data/SquidSec/projects/burp-ai-bridge/scripts/wsl-burp-env.sh
set -euo pipefail

ENDPOINT="${HOME}/.squidsec/burp-ai-bridge.json"
if [[ ! -f "$ENDPOINT" ]]; then
  WINHOME="/mnt/c/Users/${USER}"
  if [[ -f "${WINHOME}/.squidsec/burp-ai-bridge.json" ]]; then
    ENDPOINT="${WINHOME}/.squidsec/burp-ai-bridge.json"
  elif [[ -f "$HOME/.squidsec/burp-ai-bridge.json" ]]; then
    ENDPOINT="$HOME/.squidsec/burp-ai-bridge.json"
  fi
fi

if [[ ! -f "$ENDPOINT" ]]; then
  echo "No burp-ai-bridge.json found. Load the extension in Burp first, or enable WSL listen and Apply." >&2
  return 1 2>/dev/null || exit 1
fi

token=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("token",""))' "$ENDPOINT")
port=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("port",9877))' "$ENDPOINT")

export BURP_BRIDGE_TOKEN="$token"
export BURP_BRIDGE_BASE="http://127.0.0.1:${port}"
if ! curl -fsS --connect-timeout 2 "${BURP_BRIDGE_BASE}/health" >/dev/null 2>&1; then
  WINIP=$(grep nameserver /etc/resolv.conf | awk '{print $2}' | head -1)
  export BURP_BRIDGE_BASE="http://${WINIP}:${port}"
fi

echo "BURP_BRIDGE_BASE=$BURP_BRIDGE_BASE"
echo "token set from $ENDPOINT"
