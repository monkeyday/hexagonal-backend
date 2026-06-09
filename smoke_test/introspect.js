/**
 * Smoke test — POST /oidc/introspect
 *
 * Run:  k6 run smoke_test/introspect.js
 */
import http from 'k6/http';
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

  // ── Active access token ──────────────────────────────────────────────────────
  const activeJWT = http.post(
    `${BASE_URL}/oidc/introspect`,
    JSON.stringify({ token: tokens.access_token }),
    { headers: bearerHeaders },
  );
  check(activeJWT, {
    'access token: status 200':    (r) => r.status === 200,
    'access token: active=true':   (r) => r.json('active') === true,
    'access token: has sub':       (r) => !!r.json('sub'),
    'access token: has iss':       (r) => !!r.json('iss'),
    'access token: has exp':       (r) => r.json('exp') > 0,
    'access token: token_type':    (r) => r.json('token_type') === 'Bearer',
  });

  // ── Active refresh token (opaque, hint required) ─────────────────────────────
  const activeOpaque = http.post(
    `${BASE_URL}/oidc/introspect`,
    JSON.stringify({ token: tokens.refresh_token, token_type_hint: 'refresh_token' }),
    { headers: bearerHeaders },
  );
  check(activeOpaque, {
    'refresh token: status 200':  (r) => r.status === 200,
    'refresh token: active=true': (r) => r.json('active') === true,
  });

  // ── Revoked / unknown token — should return active=false ────────────────────
  const inactive = http.post(
    `${BASE_URL}/oidc/introspect`,
    JSON.stringify({ token: 'revoked-or-unknown-token' }),
    { headers: bearerHeaders },
  );
  check(inactive, {
    'inactive token: status 200':   (r) => r.status === 200,
    'inactive token: active=false': (r) => r.json('active') === false,
    'inactive token: no sub leak':  (r) => !r.json('sub'),
  });
}
