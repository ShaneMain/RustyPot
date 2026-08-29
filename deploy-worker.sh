#!/usr/bin/env bash
# Update the edge Worker's code without touching its routes or secrets.
#
# Why not `wrangler deploy`: wrangler wants a wrangler.toml describing the whole
# Worker, and anything that file omits — routes, bindings — it is liable to
# rewrite. This Worker routes ALL traffic for the zone, including the real app,
# so a deploy that drops the HONEYPOT_BACKEND/APP_BACKEND bindings or unbinds
# the route takes the site down rather than just the honeypot. The script-upload
# API replaces only the code, and `keep_bindings` retains the existing secrets.
#
# Requires a token with: Account > Workers Scripts > Edit.
# Mint at https://dash.cloudflare.com/profile/api-tokens
#
#   CF_API_TOKEN=… ./deploy-worker.sh              # lists script names, exits
#   CF_API_TOKEN=… WORKER_NAME=… ./deploy-worker.sh  # deploys
set -euo pipefail

ACCOUNT_ID="${CF_ACCOUNT_ID:-cd8991bedbdb9bfcbfa763692b1b1e71}"
SCRIPT="$(dirname "$0")/cloudflare-worker.js"
API="https://api.cloudflare.com/client/v4/accounts/${ACCOUNT_ID}/workers/scripts"

: "${CF_API_TOKEN:?set CF_API_TOKEN (needs Workers Scripts: Edit)}"
[ -f "$SCRIPT" ] || { echo "missing $SCRIPT" >&2; exit 1; }

auth=(-H "Authorization: Bearer ${CF_API_TOKEN}")

if [ -z "${WORKER_NAME:-}" ]; then
  echo "WORKER_NAME not set. Scripts on this account:" >&2
  curl -sS "${auth[@]}" "$API" \
    | python3 -c 'import json,sys; d=json.load(sys.stdin); e=d.get("errors") or []; print("  API error:", e[0].get("message")) if e else [print("  -", s["id"]) for s in (d.get("result") or [])]' >&2
  echo >&2
  echo "Re-run with WORKER_NAME=<one of the above>." >&2
  echo "Pick the script bound to the zone's route — it is the one serving fillerkiller.app." >&2
  exit 2
fi

# keep_bindings preserves HONEYPOT_BACKEND / APP_BACKEND, which exist only on
# the deployed Worker and are not recoverable from this repo.
metadata='{"main_module":"cloudflare-worker.js","compatibility_date":"2026-08-01","keep_bindings":["secret_text","plain_text"]}'

echo "Deploying $(basename "$SCRIPT") -> ${WORKER_NAME}"
resp=$(curl -sS -X PUT "${auth[@]}" "${API}/${WORKER_NAME}" \
  -F "metadata=${metadata};type=application/json" \
  -F "cloudflare-worker.js=@${SCRIPT};type=application/javascript+module")

python3 - "$resp" <<'PY'
import json, sys
d = json.loads(sys.argv[1])
if d.get("success"):
    print("  deployed:", (d.get("result") or {}).get("id"))
else:
    print("  FAILED:", d.get("errors"))
    sys.exit(1)
PY

echo
echo "Verify the header is gone (may take a few seconds to propagate):"
echo "  curl -sI https://fillerkiller.app/wp-login.php | grep -i x-cloud-trace-context"
echo "No output = deployed correctly."
