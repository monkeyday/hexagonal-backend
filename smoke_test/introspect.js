/**
 * Smoke test — POST /oidc/introspect
 *
 * RFC 7662 §2.1: introspection requires an authenticated confidential client.
 * The smoke client is public, so every caller here must be rejected with 401 —
 * a bearer access token is end-user authentication, not client authentication.
 * The positive path (active/inactive responses for a confidential client) is
 * covered by the Go unit tests.
 *
 * Run:  k6 run smoke_test/introspect.js
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
  // ── Bearer token only — not client authentication ───────────────────────────
  const bearerOnly = http.post(
    `${BASE_URL}/oidc/introspect`,
    JSON.stringify({ token: tokens.access_token }),
    {
      headers: { ...JSON_HEADERS, Authorization: `Bearer ${tokens.access_token}` },
      responseCallback: expectedStatuses(401),
    },
  );
  check(bearerOnly, { 'bearer-only introspect: status 401': (r) => r.status === 401 });

  // ── No credentials at all ────────────────────────────────────────────────────
  const anonymous = http.post(
    `${BASE_URL}/oidc/introspect`,
    JSON.stringify({ token: tokens.access_token }),
    { headers: JSON_HEADERS, responseCallback: expectedStatuses(401) },
  );
  check(anonymous, { 'anonymous introspect: status 401': (r) => r.status === 401 });

  // ── Bare public client_id — identification, not authentication ──────────────
  const publicClient = http.post(
    `${BASE_URL}/oidc/introspect`,
    JSON.stringify({ token: tokens.access_token, client_id: 'smoke-client' }),
    { headers: JSON_HEADERS, responseCallback: expectedStatuses(401) },
  );
  check(publicClient, { 'public client_id introspect: status 401': (r) => r.status === 401 });
}
