#!/usr/bin/env bash
#
# Orchestrates the IdP (cmd/auth) + cmd/backend test client for the browser-driven
# OIDC flow described in SCENARIO.md. The servers run until you press Ctrl-C.
#
#   bash e2e/backend_flow/run.sh
#
# This script does NOT drive the browser — that part is executed against the
# Playwright MCP browser by an agent following SCENARIO.md, so no npm/Playwright
# dependency is installed into the repo.
#
# The IdP runs against an ephemeral file store (mktemp), registering my_client2
# as a public PKCE client to match cmd/backend. Nothing persists: the test user
# and its tokens are discarded on exit, so your tmp/ is never touched.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SECRET="$ROOT/cmd/auth/.secret"
IDP_PORT=9876
APP_PORT=3000
MAILPIT_WEB=http://localhost:8025
MAILPIT_SMTP_PORT=1025

command -v openssl >/dev/null || { echo "openssl is required" >&2; exit 1; }
for f in private_key.pem public_key.pem; do
  [ -f "$SECRET/$f" ] || { echo "missing $SECRET/$f — generate keys per README Quick Start" >&2; exit 1; }
done
for p in $IDP_PORT $APP_PORT; do
  if lsof -nP -iTCP:$p -sTCP:LISTEN >/dev/null 2>&1; then
    echo "port :$p is busy — stop whatever is using it first (cmd/backend hardcodes :$IDP_PORT and :$APP_PORT)" >&2
    exit 1
  fi
done

WORK="$(mktemp -d)"
ENVF="$WORK/.env"
cat > "$ENVF" <<EOF
PORT=:$IDP_PORT
PRIVATE_KEY_PATH=$SECRET/private_key.pem
PUBLIC_KEY_PATH=$SECRET/public_key.pem
JWT_KID=local
JWT_ISSUER=http://localhost:$IDP_PORT
REPOSITORY_USED=file
FILE_DIR=$WORK
USER_FILE_PATH=user.json
OAUTH_CLIENT_ID=my_client2
OAUTH_CLIENT_REDIRECT_URIS=http://localhost:$APP_PORT/callback
COOKIE_SECURE=false
EMAIL_ENCRYPTION_KEY=$(openssl rand -base64 32)
EMAIL_BLIND_INDEX_KEY=$(openssl rand -base64 32)
EOF

# Wire the IdP's password-reset emails to Mailpit if it's up; otherwise the IdP
# falls back to the log email sender (token printed to idp.log) and the
# forgot-password steps in SCENARIO.md can't be driven through the inbox.
if curl -sf "$MAILPIT_WEB/api/v1/info" >/dev/null 2>&1; then
  cat >> "$ENVF" <<EOF
SMTP_HOST=localhost
SMTP_PORT=$MAILPIT_SMTP_PORT
SMTP_FROM=noreply@auth.local
APP_BASE_URL=http://localhost:$APP_PORT
EOF
  MAILPIT_STATUS="$MAILPIT_WEB (reset emails land here)"
  echo "[*] Mailpit detected at $MAILPIT_WEB — reset emails delivered to its inbox"
else
  MAILPIT_STATUS="disabled (log email sender — reset token goes to idp.log)"
  echo "[*] Mailpit not reachable at $MAILPIT_WEB — using log email sender (reset token goes to $WORK/idp.log)"
fi

pids=()
cleanup() {
  trap - EXIT INT TERM   # disarm so cleanup runs once
  echo
  echo "[*] stopping servers and discarding ephemeral store…"
  for pid in "${pids[@]}"; do kill "$pid" 2>/dev/null || true; done
  rm -rf "$WORK"
}
trap cleanup EXIT INT TERM

# Build first so each background PID is the real server (go run leaves a child).
echo "[*] building binaries…"
( cd "$ROOT" && go build -o "$WORK/idp" ./cmd/auth && go build -o "$WORK/app" ./cmd/backend )

wait_ready() { # url, name
  for _ in $(seq 1 30); do curl -sf "$1" >/dev/null 2>&1 && return 0; sleep 1; done
  echo "$2 failed to become ready" >&2; return 1
}

echo "[*] starting IdP on :$IDP_PORT (store: $WORK)"
ENV_PATH="$ENVF" "$WORK/idp" >"$WORK/idp.log" 2>&1 &
pids+=($!)
wait_ready "http://localhost:$IDP_PORT/.well-known/openid-configuration" "IdP" || { cat "$WORK/idp.log"; exit 1; }

echo "[*] starting cmd/backend on :$APP_PORT"
"$WORK/app" >"$WORK/app.log" 2>&1 &
pids+=($!)
wait_ready "http://localhost:$APP_PORT/" "cmd/backend" || { cat "$WORK/app.log"; exit 1; }

cat <<MSG

  ✅ Ready.
     IdP:         http://localhost:$IDP_PORT
     Test client: http://localhost:$APP_PORT
     Client:      my_client2 (public, PKCE)   store: $WORK (ephemeral)
     Mailpit:     $MAILPIT_STATUS

  Now drive the browser steps in e2e/backend_flow/SCENARIO.md via the
  Playwright MCP browser. Press Ctrl-C here to stop and clean up.

MSG
wait
