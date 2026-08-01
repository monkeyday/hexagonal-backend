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
S_AT=""
S_RT=""
PRE_RESET_AT=""
PRE_RESET_RT=""
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

# Mint an independent session via the password grant, into S_AT / S_RT. Used by
# the revocation-semantics checks so each case owns its own grant and cannot
# disturb the main flow's tokens.
mint_session() {
  local pw="${1:-$PASSWORD}" resp body
  resp=$(do_req "$BASE_URL/token" -X POST \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "grant_type=password&email=$EMAIL&password=$pw&expire_secs=3600")
  body=$(echo "$resp" | tail -n +2)
  S_AT=$(json_field "$body" access_token)
  S_RT=$(json_field "$body" refresh_token)
}

# Echo the `active` value RFC 7662 reports for a token ("true"/"false"/"").
introspect_active() {
  local resp
  resp=$(do_req "$BASE_URL/oidc/introspect" -X POST \
    -u "$CLIENT_ID:$CLIENT_SECRET" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "token=$1&token_type_hint=access_token")
  # Not `.active // empty`: jq's // treats false the same as null, which would
  # swallow exactly the value these checks exist to observe.
  printf '%s' "$(echo "$resp" | tail -n +2)" |
    jq -r 'if has("active") then (.active | tostring) else "" end' 2>/dev/null || true
}

# Assert introspection's verdict on a token.
check_active() {
  local label="$1" token="$2" want="$3" got
  got=$(introspect_active "$token")
  if [ "$got" = "$want" ]; then
    pass "$label (active=$got)"
  else
    fail "$label (active=${got:-<empty>}, want $want)"
  fi
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

# ── RFC 6749 error contract ─────────────────────────────────────────────────────
# Negative paths for the RFC 6749 error model: the token endpoint returns a §5.2
# JSON body ({"error": ...}); /authorize returns a §4.1.2.1 error redirect once
# the client + redirect_uri are valid.

section "RFC 6749 errors — token endpoint (§5.2 body)"
split_resp "$(do_req "$BASE_URL/token" -X POST \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials")"
check_status "POST /token (unsupported grant) → 400" "400" "$STATUS"
check_field  "token error" "$BODY" "error" "unsupported_grant_type"

section "RFC 6749 errors — authorize error redirect (§4.1.2.1)"
AUTHZ_ERR_RESP=$(curl -si --max-redirs 0 --max-time 10 \
  "$BASE_URL/authorize?response_type=token&client_id=$CLIENT_ID&redirect_uri=$REDIRECT_URI&scope=openid+email+profile&state=xyz" 2>/dev/null)
AUTHZ_ERR_STATUS=$(echo "$AUTHZ_ERR_RESP" | head -1 | awk '{print $2}')
AUTHZ_ERR_LOC=$(echo "$AUTHZ_ERR_RESP" | grep -i '^location:' | tr -d '\r' | sed 's/^[Ll]ocation: //')
check_status "GET /authorize (bad response_type) → 302" "302" "$AUTHZ_ERR_STATUS"
if printf '%s' "$AUTHZ_ERR_LOC" | grep -q 'error=unsupported_response_type'; then
  pass "authorize error redirect carries error=unsupported_response_type"
else
  fail "authorize error redirect missing error param (Location: $AUTHZ_ERR_LOC)"
fi

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
  # Client auth runs before the code is consumed (exchange_code.go:53-66), so
  # neither wrong-secret probe burns $CODE — the real exchange follows below and
  # its 200 is what proves the code survived. Do not reorder.
  # Unreachable from smoke: that client is public, so Authenticate never fails.
  split_resp "$(do_req "$BASE_URL/token" -X POST \
    -u "$CLIENT_ID:wrong-secret" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "grant_type=authorization_code&code=$CODE&client_id=$CLIENT_ID&redirect_uri=$REDIRECT_URI&code_verifier=$CODE_VERIFIER")"
  check_status "POST /token (wrong client secret) → 401" "401" "$STATUS"
  check_field  "invalid_client error" "$BODY" "error" "invalid_client"

  # RFC 6749 §5.2: a 401 rejecting credentials sent in the Authorization header
  # must carry a WWW-Authenticate challenge (http_responder.go:190). Sent as a
  # second, identical probe because do_req writes the body out with -o/-w and
  # discards headers — the challenge is only readable from a raw -i response.
  INVALID_CLIENT_RESP=$(curl -si --max-time 10 -X POST \
    -u "$CLIENT_ID:wrong-secret" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "grant_type=authorization_code&code=$CODE&client_id=$CLIENT_ID&redirect_uri=$REDIRECT_URI&code_verifier=$CODE_VERIFIER" \
    "$BASE_URL/token" 2>/dev/null)
  if printf '%s' "$INVALID_CLIENT_RESP" | grep -qi '^www-authenticate:.*realm="oauth2"'; then
    pass "invalid_client carries WWW-Authenticate: Basic realm=\"oauth2\""
  else
    # Report the status line too: an empty one means curl never reached the
    # server, which is a transport failure rather than a missing header.
    fail "invalid_client missing WWW-Authenticate challenge (status line: $(printf '%s' "$INVALID_CLIENT_RESP" | head -1 | tr -d '\r'))"
  fi

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

# ── Revocation semantics ──────────────────────────────────────────────────────
# Introspection re-implements the revocation checks the auth middleware runs
# (query/introspect_token.go), so a token rejected at /oidc/me must also report
# active:false here — otherwise the two paths have silently diverged. Each case
# below mints its own session, leaving the main flow's tokens alone.

section "Introspect reports a revoked token inactive (RFC 7662)"
check_active "jti-revoked token" "$ACCESS_TOKEN" "false"

section "Revoking a refresh token ends the whole grant (RFC 7009 §2.1)"
mint_session
if [ -n "$S_AT" ] && [ -n "$S_RT" ]; then
  GRANT_AT="$S_AT"
  split_resp "$(do_req "$BASE_URL/oidc/revoke" -X POST \
    -H "Authorization: Bearer $S_AT" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "token=$S_RT")"
  check_status "POST /oidc/revoke (refresh token)" "200" "$STATUS"

  split_resp "$(do_req "$BASE_URL/oidc/me" -H "Authorization: Bearer $GRANT_AT")"
  check_status "sibling access token rejected after grant revoke → 401" "401" "$STATUS"
  check_active "grant-revoked sibling access token" "$GRANT_AT" "false"
else
  fail "grant revoke — skipped, could not mint a session"
fi

section "Revoking an access token leaves its grant alive (docs/auth.yaml §revoke)"
mint_session
if [ -n "$S_AT" ] && [ -n "$S_RT" ]; then
  KEEP_RT="$S_RT"
  split_resp "$(do_req "$BASE_URL/oidc/revoke" -X POST \
    -H "Authorization: Bearer $S_AT" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "token=$S_AT&token_type_hint=access_token")"
  check_status "POST /oidc/revoke (access token)" "200" "$STATUS"

  # The inverse of the cascade above: blacklisting one jti must not take the
  # session with it, or every access-token revoke would silently log the user out.
  split_resp "$(do_req "$BASE_URL/token" -X POST \
    -u "$CLIENT_ID:$CLIENT_SECRET" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "grant_type=refresh_token&client_id=$CLIENT_ID&refresh_token=$KEEP_RT")"
  check_status "sibling refresh token still rotates → 200" "200" "$STATUS"
else
  fail "access-token revoke — skipped, could not mint a session"
fi

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

  # A session established before the reset, to prove the reset ends it. Minted
  # here rather than reused from earlier: the main flow's tokens were already
  # revoked above, which would make the assertion pass for the wrong reason.
  mint_session
  PRE_RESET_AT="$S_AT"
  PRE_RESET_RT="$S_RT"

  if [ -n "$RESET_TOKEN" ]; then
    # SetPassword rejects before ClearPasswordResetToken (reset_password.go:51,57)
    # and mutates nothing on failure, so the token stays usable for the real reset
    # below. Unreachable from smoke: a real reset token needs Mailpit.
    split_resp "$(do_req "$BASE_URL/reset-password" -X POST \
      -H "Content-Type: application/x-www-form-urlencoded" \
      -d "token=$RESET_TOKEN&password=weak")"
    check_status "POST /reset-password (weak password) → 400" "400" "$STATUS"
    check_field  "weak password" "$BODY" "err_code" "10017"

    split_resp "$(do_req "$BASE_URL/reset-password" -X POST \
      -H "Content-Type: application/x-www-form-urlencoded" \
      -d "token=$RESET_TOKEN&password=$NEW_PASSWORD")"
    check_status "POST /reset-password" "200" "$STATUS"
  fi

  # A password reset ends every session the user holds — including the stateless
  # access tokens already issued, which outlive the refresh-token sweep.
  if [ -n "$PRE_RESET_AT" ]; then
    split_resp "$(do_req "$BASE_URL/oidc/me" -H "Authorization: Bearer $PRE_RESET_AT")"
    check_status "pre-reset access token rejected → 401" "401" "$STATUS"
    check_active "pre-reset access token" "$PRE_RESET_AT" "false"

    split_resp "$(do_req "$BASE_URL/token" -X POST \
      -u "$CLIENT_ID:$CLIENT_SECRET" \
      -H "Content-Type: application/x-www-form-urlencoded" \
      -d "grant_type=refresh_token&client_id=$CLIENT_ID&refresh_token=$PRE_RESET_RT")"
    if [ "$STATUS" != "200" ]; then
      pass "pre-reset refresh token rejected after reset (HTTP $STATUS)"
    else
      fail "pre-reset refresh token still rotates after reset"
    fi
  else
    fail "password-reset invalidation — skipped, could not mint a pre-reset session"
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

  # The user-level marker and `iat` both carry Unix *seconds*, so within the second
  # the reset landed in there is no way to tell whether a token was signed before
  # or after it. That second fails closed — the comparison is inclusive on purpose
  # (`iat <= invalidatedAt`, revocation_checker.go:53) — so a token minted inside
  # it is rejected by design. Wait past that second before asserting the positive
  # case; without this the check below flakes rather than failing honestly.
  sleep 1

  split_resp "$(do_req "$BASE_URL/token" -X POST \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "grant_type=password&email=$EMAIL&password=$NEW_PASSWORD&expire_secs=3600")"
  check_status "POST /token (password) with new password" "200" "$STATUS"
  check_json   "new-password token response" "$BODY"
  check_field  "new-password token" "$BODY" "access_token"

  # Minting a token is not the same as it working: the invalidation must apply to
  # what existed before the reset and nothing after it.
  # Both captured before the next request overwrites BODY.
  NEW_AT=$(json_field "$BODY" access_token)
  NEW_RT=$(json_field "$BODY" refresh_token)
  if [ -n "$NEW_AT" ]; then
    split_resp "$(do_req "$BASE_URL/oidc/me" -H "Authorization: Bearer $NEW_AT")"
    check_status "post-reset access token accepted → 200" "200" "$STATUS"
    check_active "post-reset access token" "$NEW_AT" "true"

    # The refresh half too: the user-level marker must not outlive the reset for
    # the new session's chain either.
    split_resp "$(do_req "$BASE_URL/token" -X POST \
      -u "$CLIENT_ID:$CLIENT_SECRET" \
      -H "Content-Type: application/x-www-form-urlencoded" \
      -d "grant_type=refresh_token&client_id=$CLIENT_ID&refresh_token=$NEW_RT")"
    check_status "post-reset refresh token rotates → 200" "200" "$STATUS"
  else
    fail "post-reset token usable — skipped, no access token returned"
  fi
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
