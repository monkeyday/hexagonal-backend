#!/usr/bin/env bash
set -uo pipefail

BASE_URL="${BASE_URL:-http://127.0.0.1:9876}"
CLIENT_ID="my_client"
CLIENT_SECRET="${CLIENT_SECRET:-super-secret-e2e-client-secret}"
REDIRECT_URI="http://localhost:3000/callback"
POST_LOGOUT_URI="http://localhost:3000"
EMAIL="test_$(date +%s)_$$@example.com"
PASSWORD="Secret!234"

GREEN='\033[0;32m'
RED='\033[0;31m'
CYAN='\033[0;36m'
YELLOW='\033[0;33m'
NC='\033[0m'

PASS=0
FAIL=0

# Initialize variables that may be set conditionally
ACCESS_TOKEN=""
REFRESH_TOKEN=""
ID_TOKEN=""
OLD_RT=""
CODE=""
LOCATION=""
CSRF_TOKEN=""
NEW_AT=""
NEW_RT=""
STATE=""
NONCE=""
SERVER_PID=""

COOKIE_JAR=$(mktemp)
trap 'if [ -n "$SERVER_PID" ]; then kill "$SERVER_PID" 2>/dev/null || true; fi; rm -f "$COOKIE_JAR"' EXIT

require_cmd() {
  command -v "$1" >/dev/null 2>&1 || { echo "$1 is required" >&2; exit 127; }
}

require_cmd curl
require_cmd jq

pass()    { echo -e "${GREEN}✓ $1${NC}"; PASS=$((PASS+1)); }
fail()    { echo -e "${RED}✗ $1${NC}";  FAIL=$((FAIL+1)); }
section() { echo -e "\n${CYAN}── $1 ──${NC}"; }
info()    { echo -e "  ${YELLOW}→ $1${NC}"; }

START_SERVER="${START_SERVER:-0}"
if [ "$START_SERVER" = "1" ]; then
  require_cmd go
  go run ./cmd/auth/main.go &
  SERVER_PID=$!
  info "started auth server (pid $SERVER_PID) — waiting for readiness"
fi

# Verify HTTP status code.
check_status() {
  local label="$1" expected="$2" got="$3"
  if [ "$got" = "$expected" ]; then
    pass "$label"
  else
    fail "$label (HTTP $got, want $expected)"
  fi
}

# Verify JSON response has no err_code (omitempty means absence = success).
check_json() {
  local label="$1" body="$2"
  local err_code
  err_code=$(printf '%s' "$body" |
    jq -er 'if type == "object" then (.err_code // 0) else 0 end' 2>/dev/null ||
    echo "-1")
  if [ "$err_code" = "0" ]; then
    pass "$label"
  else
    fail "$label"
    echo "  $body"
  fi
}

# Verify a JSON field is present and non-empty; pass optional expected value to assert equality.
check_field() {
  local label="$1" body="$2" field="$3" expected="${4:-}"
  local result
  result=$(printf '%s' "$body" | jq -r \
    --arg field "$field" \
    --arg expected "$expected" '
      if type != "object" then "error"
      elif (has($field) | not) or .[$field] == null then "missing"
      elif .[$field] == "" or .[$field] == [] then "empty"
      elif $expected != "" and ((.[$field] | tostring | ascii_downcase) != $expected)
        then "want \($expected) got \(.[$field] | tostring)"
      else "ok"
      end
    ' 2>/dev/null || echo "error")
  if [ "$result" = "ok" ]; then
    pass "$label: '$field'"
  else
    fail "$label: '$field' ($result)"
  fi
}

# Extract a single JSON field value.
json_field() {
  local body="$1" field="$2"
  printf '%s' "$body" | jq -r --arg field "$field" '.[$field] // empty' 2>/dev/null || true
}

# Run curl, return status on line 1 and body on remaining lines.
# Captures stderr and prints it when status is 000.
do_req() {
  local tmpfile errfile
  tmpfile=$(mktemp)
  errfile=$(mktemp)
  local status
  status=$(curl -sS --max-time 10 -o "$tmpfile" -w "%{http_code}" "$@" 2>"$errfile") || status="000"
  if [ "$status" = "000" ]; then
    echo -e "  ${YELLOW}curl error: $(cat "$errfile")${NC}" >&2
  fi
  printf '%s\n%s' "$status" "$(cat "$tmpfile")"
  rm -f "$tmpfile" "$errfile"
}

# Split do_req output into STATUS and BODY globals.
split_resp() {
  local resp="$1"
  STATUS=$(echo "$resp" | head -1)
  BODY=$(echo "$resp" | tail -n +2)
}

# Decode a percent-encoded URL component.
url_decode() {
  local value="${1//+/ }"
  printf '%b' "${value//%/\\x}"
}

# ── Server readiness ──────────────────────────────────────────────────────────

section "Server readiness"
READY_ATTEMPTS=$([ "$START_SERVER" = "1" ] && echo 30 || echo 10)
for i in $(seq 1 "$READY_ATTEMPTS"); do
  if curl -sf --max-time 2 "$BASE_URL/.well-known/openid-configuration" >/dev/null 2>&1; then
    pass "server reachable at $BASE_URL"
    break
  fi
  [ "$i" -eq "$READY_ATTEMPTS" ] && { fail "server not reachable after ${READY_ATTEMPTS}s"; exit 1; }
  sleep 1
done
info "test user: $EMAIL"

# ── Discovery & JWKS ──────────────────────────────────────────────────────────

section "OIDC Discovery"
split_resp "$(do_req "$BASE_URL/.well-known/openid-configuration")"
check_status "GET /.well-known/openid-configuration" "200" "$STATUS"
check_json   "discovery response" "$BODY"
check_field  "discovery" "$BODY" "issuer"
check_field  "discovery" "$BODY" "authorization_endpoint"
check_field  "discovery" "$BODY" "jwks_uri"

section "OIDC JWKS"
split_resp "$(do_req "$BASE_URL/.well-known/jwks.json")"
check_status "GET /.well-known/jwks.json" "200" "$STATUS"
check_json   "JWKS response" "$BODY"
check_field  "JWKS" "$BODY" "keys"

# ── Sign up ───────────────────────────────────────────────────────────────────

section "Sign up"
split_resp "$(do_req "$BASE_URL/sign-up" -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=testuser&nickname=Test&email=$EMAIL&password=$PASSWORD")"
check_status "POST /sign-up" "200" "$STATUS"
check_json   "sign-up response" "$BODY"

# ── Password grant ────────────────────────────────────────────────────────────

section "Password grant"
split_resp "$(do_req "$BASE_URL/token" -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password&email=$EMAIL&password=$PASSWORD&expire_secs=3600")"
check_status "POST /token (password)" "200" "$STATUS"
check_json   "token response" "$BODY"
check_field  "token" "$BODY" "access_token"
check_field  "token" "$BODY" "refresh_token"

ACCESS_TOKEN=$(json_field "$BODY" access_token)
REFRESH_TOKEN=$(json_field "$BODY" refresh_token)
info "access_token:  [${#ACCESS_TOKEN} chars]"
info "refresh_token: [${#REFRESH_TOKEN} chars]"

# ── OIDC code flow ────────────────────────────────────────────────────────────

section "OIDC code flow — GET /authorize"
STATE=$(dd if=/dev/urandom bs=16 count=1 2>/dev/null | base64 | tr -d '=\n' | tr '+/' '-_')
NONCE=$(dd if=/dev/urandom bs=16 count=1 2>/dev/null | base64 | tr -d '=\n' | tr '+/' '-_')
# PKCE (mandatory for public clients): S256 challenge over a random verifier
CODE_VERIFIER=$(dd if=/dev/urandom bs=32 count=1 2>/dev/null | base64 | tr -d '=\n' | tr '+/' '-_')
CODE_CHALLENGE=$(printf '%s' "$CODE_VERIFIER" | openssl dgst -sha256 -binary | base64 | tr -d '=\n' | tr '+/' '-_')
AUTHORIZE_RESP=$(curl -si -c "$COOKIE_JAR" --max-redirs 0 --max-time 10 \
  "$BASE_URL/authorize?response_type=code&client_id=$CLIENT_ID&redirect_uri=$REDIRECT_URI&scope=openid+email+profile&state=$STATE&nonce=$NONCE&code_challenge=$CODE_CHALLENGE&code_challenge_method=S256" 2>/dev/null)
AUTH_STATUS=$(echo "$AUTHORIZE_RESP" | head -1 | awk '{print $2}')
check_status "GET /authorize → 302" "302" "$AUTH_STATUS"

section "OIDC code flow — GET /sign-in (extract CSRF)"
SIGNIN_HTML=$(curl -sf -b "$COOKIE_JAR" --max-time 10 "$BASE_URL/sign-in" 2>/dev/null || true)
CSRF_TAG=$(printf '%s\n' "$SIGNIN_HTML" |
  tr '\n' ' ' |
  grep -oE '<input[^>]*name="csrf_token"[^>]*>' |
  head -n 1)
CSRF_TOKEN=$(printf '%s\n' "$CSRF_TAG" |
  sed -nE 's/.*value="([^"]*)".*/\1/p')
if [ -n "$CSRF_TOKEN" ]; then
  pass "GET /sign-in (CSRF extracted)"
  info "csrf: [${#CSRF_TOKEN} chars]"
else
  fail "GET /sign-in (CSRF token not found in HTML)"
fi

section "OIDC code flow — POST /sign-in"
SIGNIN_RESP=$(curl -si -b "$COOKIE_JAR" --max-redirs 0 --max-time 10 \
  -X POST "$BASE_URL/sign-in" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "email=$EMAIL&password=$PASSWORD&csrf_token=$CSRF_TOKEN" 2>/dev/null)
SIGNIN_STATUS=$(echo "$SIGNIN_RESP" | head -1 | awk '{print $2}')
LOCATION=$(echo "$SIGNIN_RESP" | grep -i '^location:' | tr -d '\r' | sed 's/^[Ll]ocation: //')
check_status "POST /sign-in → 303" "303" "$SIGNIN_STATUS"

QUERY="${LOCATION#*\?}"
QUERY="${QUERY%%#*}"
CODE_RAW=$(printf '%s\n' "$QUERY" |
  tr '&' '\n' |
  sed -nE 's/^code=//p' |
  head -n 1)
CODE=$(url_decode "$CODE_RAW")
if [ -n "$CODE" ]; then
  info "auth code: [${#CODE} chars]"
else
  fail "no auth code in Location header"
fi
STATE_RESP=$(url_decode "$(printf '%s\n' "$QUERY" | tr '&' '\n' | sed -nE 's/^state=//p' | head -n 1)")
if [ "$STATE_RESP" = "$STATE" ]; then
  pass "state matches"
else
  fail "state mismatch (want $STATE, got $STATE_RESP)"
fi

section "OIDC code flow — exchange code"
if [ -n "$CODE" ]; then
  split_resp "$(do_req "$BASE_URL/token" -X POST \
    -u "$CLIENT_ID:$CLIENT_SECRET" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "grant_type=authorization_code&code=$CODE&client_id=$CLIENT_ID&redirect_uri=$REDIRECT_URI&code_verifier=$CODE_VERIFIER")"
  check_status "POST /token (exchange code)" "200" "$STATUS"
  check_json   "exchange code response" "$BODY"
  check_field  "exchange code" "$BODY" "access_token"
  check_field  "exchange code" "$BODY" "id_token"
  check_field  "exchange code" "$BODY" "refresh_token"
  NEW_AT=$(json_field "$BODY" access_token)
  NEW_RT=$(json_field "$BODY" refresh_token)
  ID_TOKEN=$(json_field "$BODY" id_token)
  [ -n "$NEW_AT" ] && ACCESS_TOKEN="$NEW_AT"
  [ -n "$NEW_RT" ] && REFRESH_TOKEN="$NEW_RT"
  if [ -n "$ID_TOKEN" ]; then
    JWT_PAYLOAD=$(printf '%s' "$ID_TOKEN" | cut -d'.' -f2)
    case $((${#JWT_PAYLOAD} % 4)) in
      2) JWT_PAYLOAD="${JWT_PAYLOAD}==" ;;
      3) JWT_PAYLOAD="${JWT_PAYLOAD}=" ;;
    esac
    JWT_CLAIMS=$(printf '%s' "$JWT_PAYLOAD" | tr -- '-_' '+/' | base64 -d 2>/dev/null || true)
    NONCE_IN_TOKEN=$(printf '%s' "$JWT_CLAIMS" | jq -r '.nonce // empty' 2>/dev/null || true)
    if [ "$NONCE_IN_TOKEN" = "$NONCE" ]; then
      pass "nonce in ID token matches"
    else
      fail "nonce mismatch in ID token (want $NONCE, got $NONCE_IN_TOKEN)"
    fi
  fi
else
  fail "POST /token (exchange code) — skipped, no code"
fi

# ── Refresh token ─────────────────────────────────────────────────────────────

section "Refresh token"
if [ -n "$REFRESH_TOKEN" ]; then
  OLD_RT="$REFRESH_TOKEN"
  split_resp "$(do_req "$BASE_URL/token" -X POST \
    -u "$CLIENT_ID:$CLIENT_SECRET" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "grant_type=refresh_token&client_id=$CLIENT_ID&refresh_token=$REFRESH_TOKEN")"
  check_status "POST /token (refresh)" "200" "$STATUS"
  check_json   "refresh response" "$BODY"
  NEW_AT=$(json_field "$BODY" access_token)
  NEW_RT=$(json_field "$BODY" refresh_token)
  [ -n "$NEW_AT" ] && ACCESS_TOKEN="$NEW_AT"
  if [ -n "$NEW_RT" ]; then
    if [ "$NEW_RT" != "$OLD_RT" ]; then
      pass "refresh token rotated"
    else
      fail "refresh token not rotated (same value returned)"
    fi
    REFRESH_TOKEN="$NEW_RT"
  else
    fail "refresh response missing refresh_token"
  fi
else
  fail "POST /token (refresh) — skipped, no refresh token"
fi

# ── Authenticated endpoints ───────────────────────────────────────────────────

if [ -z "$ACCESS_TOKEN" ]; then
  echo -e "\n${RED}No access token — skipping authenticated requests${NC}"
  FAIL=$((FAIL+1))
else

section "Userinfo (GET /userinfo)"
split_resp "$(do_req "$BASE_URL/userinfo" -H "Authorization: Bearer $ACCESS_TOKEN")"
check_status "GET /userinfo" "200" "$STATUS"
check_json   "userinfo response" "$BODY"
check_field  "userinfo" "$BODY" "sub"

section "Profile (GET /oidc/me)"
split_resp "$(do_req "$BASE_URL/oidc/me" -H "Authorization: Bearer $ACCESS_TOKEN")"
check_status "GET /oidc/me" "200" "$STATUS"
check_json   "profile response" "$BODY"

section "Introspect (POST /oidc/introspect)"
split_resp "$(do_req "$BASE_URL/oidc/introspect" -X POST \
  -u "$CLIENT_ID:$CLIENT_SECRET" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "token=$ACCESS_TOKEN&token_type_hint=access_token")"
check_status "POST /oidc/introspect" "200" "$STATUS"
check_json   "introspect response" "$BODY"
check_field  "introspect" "$BODY" "active" "true"

section "Update profile (POST /api/v3/update-profile)"
split_resp "$(do_req "$BASE_URL/api/v3/update-profile" -X POST \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "nickname=Updated")"
check_status "POST /api/v3/update-profile" "200" "$STATUS"
check_json   "update profile response" "$BODY"

section "Revoke token (POST /oidc/revoke)"
split_resp "$(do_req "$BASE_URL/oidc/revoke" -X POST \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "token=$ACCESS_TOKEN&token_type_hint=access_token")"
check_status "POST /oidc/revoke" "200" "$STATUS"
check_json   "revoke response" "$BODY"

section "Verify revocation (GET /oidc/me with revoked token)"
split_resp "$(do_req "$BASE_URL/oidc/me" -H "Authorization: Bearer $ACCESS_TOKEN")"
check_status "GET /oidc/me after revoke → 401" "401" "$STATUS"

section "Logout (GET /oidc/logout)"
LOGOUT_RESP=$(curl -si --max-redirs 0 --max-time 10 \
  "$BASE_URL/oidc/logout?id_token_hint=$ID_TOKEN&post_logout_redirect_uri=$POST_LOGOUT_URI&state=xyz" 2>/dev/null)
LOGOUT_STATUS=$(echo "$LOGOUT_RESP" | head -1 | awk '{print $2}')
check_status "GET /oidc/logout → 302" "302" "$LOGOUT_STATUS"

fi

# ── Forgot password & reset (requires Mailpit) ────────────────────────────────
# Drives the real email round-trip: request a reset, read the link back out of
# Mailpit, reset the password, then prove server-side that the OLD password no
# longer works and the NEW one does. Skips (without failing) when Mailpit is not
# reachable, so the suite still runs locally without an SMTP sink.

section "Forgot password & reset"
MAILPIT_URL="${MAILPIT_URL:-http://127.0.0.1:8025}"
RESET_TOKEN=""
NEW_PASSWORD="Reset!345"
if ! curl -sf --max-time 2 "$MAILPIT_URL/api/v1/info" >/dev/null 2>&1; then
  info "Mailpit not reachable at $MAILPIT_URL — skipping (set SMTP_* + run Mailpit to enable)"
else
  # Clear the inbox so /message/latest is unambiguously our reset mail.
  curl -s --max-time 5 -X DELETE "$MAILPIT_URL/api/v1/messages" >/dev/null 2>&1 || true

  split_resp "$(do_req "$BASE_URL/forgot-password" -X POST \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "email=$EMAIL")"
  check_status "POST /forgot-password (generic 200)" "200" "$STATUS"

  for i in $(seq 1 15); do
    LATEST=$(curl -sf --max-time 5 "$MAILPIT_URL/api/v1/message/latest" 2>/dev/null || true)
    RESET_TOKEN=$(printf '%s' "$LATEST" | jq -r '.Text // ""' 2>/dev/null |
      grep -oE 'reset-password\?token=[A-Za-z0-9._-]+' | head -n1 | sed 's/.*token=//')
    [ -n "$RESET_TOKEN" ] && break
    sleep 1
  done
  if [ -n "$RESET_TOKEN" ]; then
    pass "reset email delivered to Mailpit (token extracted)"
    info "reset token: [${#RESET_TOKEN} chars]"
  else
    fail "reset email not found in Mailpit"
  fi

  if [ -n "$RESET_TOKEN" ]; then
    split_resp "$(do_req "$BASE_URL/reset-password" -X POST \
      -H "Content-Type: application/x-www-form-urlencoded" \
      -d "token=$RESET_TOKEN&password=$NEW_PASSWORD")"
    check_status "POST /reset-password" "200" "$STATUS"
  fi

  # Server-state cross-check — the assertion that can't pass on an echo.
  split_resp "$(do_req "$BASE_URL/token" -X POST \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "grant_type=password&email=$EMAIL&password=$PASSWORD&expire_secs=3600")"
  if [ "$STATUS" != "200" ]; then
    pass "old password rejected after reset (HTTP $STATUS)"
  else
    fail "old password still works after reset"
  fi

  split_resp "$(do_req "$BASE_URL/token" -X POST \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "grant_type=password&email=$EMAIL&password=$NEW_PASSWORD&expire_secs=3600")"
  check_status "POST /token (password) with new password" "200" "$STATUS"
  check_json   "new-password token response" "$BODY"
  check_field  "new-password token" "$BODY" "access_token"
fi

# ── Metrics ───────────────────────────────────────────────────────────────────

section "Metrics"
METRICS_URL="${METRICS_URL:-http://127.0.0.1:9878}"
split_resp "$(do_req "$BASE_URL/debug/vars")"
check_status "GET /debug/vars (public) → 404" "404" "$STATUS"
split_resp "$(do_req "$METRICS_URL/debug/vars")"
check_status "GET /debug/vars (internal metrics listener)" "200" "$STATUS"

# ── Summary ───────────────────────────────────────────────────────────────────

echo ""
echo -e "${CYAN}────────────────────────────────${NC}"
echo -e "  ${GREEN}✓ $PASS passed${NC}   ${RED}✗ $FAIL failed${NC}"
echo -e "${CYAN}────────────────────────────────${NC}"
[ "$FAIL" -eq 0 ]
