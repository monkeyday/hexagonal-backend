/**
 * Smoke test — Keycloak-compatible alias routes
 *
 * Verifies that each alias responds equivalently to its canonical counterpart.
 * Detailed assertion depth lives in the canonical test files; these checks
 * confirm the aliases are wired and reachable.
 *
 * Aliases (see README §Keycloak-compatible aliases):
 *   GET  /protocol/openid-connect/auth      → /authorize
 *   POST /protocol/openid-connect/token     → /token
 *   GET  /protocol/openid-connect/certs     → /.well-known/jwks.json
 *   GET  /protocol/openid-connect/userinfo  → /userinfo
 *
 * Run:  k6 run smoke_test/keycloak_aliases.js
 */
import http, { expectedStatuses } from 'k6/http';
import { check, group } from 'k6';
import { smokeOptions, BASE_URL, EMAIL, PASSWORD, REDIRECT_URI, ensureUser, getTokens, startAuthFlow } from './helpers.js';

export const options = smokeOptions;

const JSON_HEADERS = { 'Content-Type': 'application/json' };
const FORM_HEADERS = { 'Content-Type': 'application/x-www-form-urlencoded' };

export function setup() {
  ensureUser();
  return getTokens();
}

export default function (tokens) {
  // ── GET /protocol/openid-connect/auth ────────────────────────────────────────
  // Equivalent to GET /authorize — should accept valid params and return sign-in page.
  group('GET /protocol/openid-connect/auth', () => {
    const res = http.get(
      `${BASE_URL}/protocol/openid-connect/auth?response_type=code&client_id=smoke-client` +
      `&redirect_uri=${encodeURIComponent(REDIRECT_URI)}&scope=openid%20email`,
    );
    check(res, {
      'status 200':      (r) => r.status === 200,
      'returns HTML':    (r) => (r.headers['Content-Type'] || '').includes('text/html'),
      'has csrf_token':  (r) => (r.body || '').includes('name="csrf_token"'),
    });
  });

  // ── POST /protocol/openid-connect/token — password grant ─────────────────────
  // Equivalent to POST /token — should issue tokens.
  group('POST /protocol/openid-connect/token', () => {
    const res = http.post(
      `${BASE_URL}/protocol/openid-connect/token`,
      JSON.stringify({ grant_type: 'password', email: EMAIL, password: PASSWORD }),
      { headers: JSON_HEADERS },
    );
    check(res, {
      'status 200':        (r) => r.status === 200,
      'has access_token':  (r) => !!r.json('access_token'),
      'has id_token':      (r) => !!r.json('id_token'),
      'has refresh_token': (r) => !!r.json('refresh_token'),
    });
  });

  // ── POST /protocol/openid-connect/token — authorization_code grant ───────────
  group('POST /protocol/openid-connect/token — authorization_code', () => {
    const { csrfToken } = startAuthFlow(null, 'smoke-nonce');
    if (!csrfToken) {
      console.warn('authorization_code alias skipped: startAuthFlow failed');
      return;
    }

    const signIn = http.post(
      `${BASE_URL}/sign-in`,
      { email: EMAIL, password: PASSWORD, csrf_token: csrfToken },
      { headers: FORM_HEADERS, redirects: 0 },
    );
    const match = (signIn.headers['Location'] || '').match(/[?&]code=([^&]+)/);
    if (!match) {
      console.warn(`authorization_code alias skipped: sign-in status=${signIn.status}`);
      return;
    }

    const res = http.post(
      `${BASE_URL}/protocol/openid-connect/token`,
      JSON.stringify({
        grant_type:   'authorization_code',
        code:         decodeURIComponent(match[1]),
        client_id:    'smoke-client',
        redirect_uri: REDIRECT_URI,
      }),
      { headers: JSON_HEADERS },
    );
    check(res, {
      'status 200':        (r) => r.status === 200,
      'has access_token':  (r) => !!r.json('access_token'),
      'has id_token':      (r) => !!r.json('id_token'),
    });
  });

  // ── GET /protocol/openid-connect/certs ───────────────────────────────────────
  // Equivalent to GET /.well-known/jwks.json — should return the JWKS.
  group('GET /protocol/openid-connect/certs', () => {
    const res = http.get(`${BASE_URL}/protocol/openid-connect/certs`);
    check(res, {
      'status 200':       (r) => r.status === 200,
      'has keys array':   (r) => Array.isArray(r.json('keys')),
      'at least one key': (r) => (r.json('keys') || []).length > 0,
      'key kty is RSA':   (r) => ((r.json('keys') || [{}])[0].kty) === 'RSA',
    });
  });

  // ── GET /protocol/openid-connect/userinfo ────────────────────────────────────
  // Equivalent to GET /userinfo — should return profile claims.
  group('GET /protocol/openid-connect/userinfo', () => {
    const res = http.get(
      `${BASE_URL}/protocol/openid-connect/userinfo`,
      { headers: { Authorization: `Bearer ${tokens.access_token}` } },
    );
    check(res, {
      'status 200': (r) => r.status === 200,
      'has sub':    (r) => !!r.json('sub'),
    });

    const unauth = http.get(
      `${BASE_URL}/protocol/openid-connect/userinfo`,
      { responseCallback: expectedStatuses(401) },
    );
    check(unauth, { 'no token: status 401': (r) => r.status === 401 });
  });
}
