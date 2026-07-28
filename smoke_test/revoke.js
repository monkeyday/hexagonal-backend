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

  // RFC 7009 §2.1: revoking a refresh token ends the whole grant, so the access
  // token issued alongside it stops verifying as well.
  const cascaded = http.get(`${BASE_URL}/oidc/me`, {
    headers: bearerHeaders,
    responseCallback: expectedStatuses(401),
  });
  check(cascaded, {
    'revoke cascades to the sibling access token: status 401': (r) => r.status === 401,
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

  // Both bearers used so far have been revoked — one by its grant's cascade,
  // one directly — so the remaining calls need a live token of their own.
  ensureUser();
  const live = getTokens();
  const liveHeaders = {
    ...JSON_HEADERS,
    Authorization: `Bearer ${live.access_token}`,
  };

  // ── Unknown token — RFC 7009 §2.2: must not return error ────────────────────
  const unknown = http.post(
    `${BASE_URL}/oidc/revoke`,
    JSON.stringify({ token: 'no-such-token' }),
    { headers: liveHeaders },
  );
  check(unknown, {
    'unknown token: status 200': (r) => r.status === 200,
  });

  // ── Missing token field — expects 400 ───────────────────────────────────────
  const missing = http.post(
    `${BASE_URL}/oidc/revoke`,
    JSON.stringify({}),
    { headers: liveHeaders, responseCallback: expectedStatuses(400) },
  );
  check(missing, {
    'missing token: status 400': (r) => r.status === 400,
  });
}
