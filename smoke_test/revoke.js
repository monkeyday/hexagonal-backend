/**
 * Smoke test — POST /oidc/revoke
 *
 * Run:  k6 run smoke_test/revoke.js
 */
import http, { expectedStatuses } from 'k6/http';
import { check } from 'k6';
import { smokeOptions, BASE_URL, ensureUser, getTokens } from './helpers.js';

export const options = smokeOptions;

const JSON_HEADERS = { 'Content-Type': 'application/json' };

export function setup() {
  ensureUser();
  return getTokens();
}

export default function (tokens) {
  const bearerHeaders = {
    ...JSON_HEADERS,
    Authorization: `Bearer ${tokens.access_token}`,
  };

  // ── Revoke refresh token (no hint) ───────────────────────────────────────────
  const revokeRefresh = http.post(
    `${BASE_URL}/oidc/revoke`,
    JSON.stringify({ token: tokens.refresh_token }),
    { headers: bearerHeaders },
  );
  check(revokeRefresh, {
    'revoke refresh token: status 200': (r) => r.status === 200,
  });

  // ── Revoke with explicit hint ────────────────────────────────────────────────
  // Get fresh tokens since the previous revoke invalidated them.
  ensureUser();
  const fresh = getTokens();
  const freshHeaders = {
    ...JSON_HEADERS,
    Authorization: `Bearer ${fresh.access_token}`,
  };

  const revokeAccess = http.post(
    `${BASE_URL}/oidc/revoke`,
    JSON.stringify({ token: fresh.access_token, token_type_hint: 'access_token' }),
    { headers: freshHeaders },
  );
  check(revokeAccess, {
    'revoke access token (hint): status 200': (r) => r.status === 200,
  });

  // ── Unknown token — RFC 7009 §2.2: must not return error ────────────────────
  const unknown = http.post(
    `${BASE_URL}/oidc/revoke`,
    JSON.stringify({ token: 'no-such-token' }),
    { headers: { ...JSON_HEADERS, Authorization: `Bearer ${tokens.access_token}` } },
  );
  check(unknown, {
    'unknown token: status 200': (r) => r.status === 200,
  });

  // ── Missing token field — expects 400 ───────────────────────────────────────
  const missing = http.post(
    `${BASE_URL}/oidc/revoke`,
    JSON.stringify({}),
    { headers: bearerHeaders, responseCallback: expectedStatuses(400) },
  );
  check(missing, {
    'missing token: status 400': (r) => r.status === 400,
  });
}
