/**
 * Smoke test — full suite (all endpoints in a single k6 run)
 *
 * Run:  k6 run smoke_test/all.js
 *   or: k6 run -e BASE_URL=http://staging:9876 smoke_test/all.js
 */
import http, { expectedStatuses } from 'k6/http';
import { check, group } from 'k6';
import { smokeOptions, BASE_URL, EMAIL, PASSWORD, REDIRECT_URI, ensureUser, getTokens, startAuthFlow } from './helpers.js';

export const options = smokeOptions;

const JSON_HEADERS    = { 'Content-Type': 'application/json' };
const FORM_HEADERS    = { 'Content-Type': 'application/x-www-form-urlencoded' };
const POST_LOGOUT_URI = 'https://app.example.com/logged-out';

export function setup() {
  ensureUser();
  return getTokens();
}

export default function (tokens) {
  const bearerHeaders    = { Authorization: `Bearer ${tokens.access_token}` };
  const jsonBearerHeaders = { ...JSON_HEADERS, Authorization: `Bearer ${tokens.access_token}` };

  // ── GET /sign-in + POST /sign-in ─────────────────────────────────────────────
  group('POST /sign-in', () => {
    const state = 'smoke-state';
    const { page, csrfToken } = startAuthFlow(state, 'smoke-nonce');
    check(page, {
      'GET /sign-in status 200':     (r) => r.status === 200,
      'GET /sign-in returns HTML':   (r) => (r.headers['Content-Type'] || '').includes('text/html'),
      'GET /sign-in has csrf_token': (r) => (r.body || '').includes('name="csrf_token"'),
    });

    const res = http.post(
      `${BASE_URL}/sign-in`,
      { email: EMAIL, password: PASSWORD, csrf_token: csrfToken },
      { headers: FORM_HEADERS, redirects: 0 },
    );
    check(res, {
      'status 303':          (r) => r.status === 303,
      'Location has code=':  (r) => (r.headers['Location'] || '').includes('code='),
      'Location has state=': (r) => (r.headers['Location'] || '').includes(`state=${state}`),
    });
  });

  // ── GET /sign-up ──────────────────────────────────────────────────────────────
  group('GET /sign-up', () => {
    const res = http.get(`${BASE_URL}/sign-up`);
    check(res, {
      'status 200':   (r) => r.status === 200,
      'returns HTML': (r) => r.headers['Content-Type'].includes('text/html'),
    });
  });

  // ── POST /sign-up ─────────────────────────────────────────────────────────────
  group('POST /sign-up', () => {
    const email = `smoke_all_${Date.now()}@example.com`;
    const res = http.post(
      `${BASE_URL}/sign-up`,
      { username: 'smokeall', nickname: 'Smoke All', email, password: 'SmokeTest1!' },
      { headers: FORM_HEADERS },
    );
    check(res, {
      'status 200':       (r) => r.status === 200,
      'body has email':   (r) => r.json('email') === email,
    });

    // duplicate email → 409
    const dup = http.post(
      `${BASE_URL}/sign-up`,
      { username: 'smokeall', nickname: 'Smoke All', email, password: 'SmokeTest1!' },
      { headers: FORM_HEADERS, responseCallback: expectedStatuses(409) },
    );
    check(dup, { 'duplicate email: status 409': (r) => r.status === 409 });
  });

  // ── GET /authorize ───────────────────────────────────────────────────────────
  group('GET /authorize', () => {
    const valid = http.get(
      `${BASE_URL}/authorize?response_type=code&client_id=smoke-client` +
      `&redirect_uri=${encodeURIComponent(REDIRECT_URI)}&scope=openid%20email`,
    );
    check(valid, { 'valid: status 200': (r) => r.status === 200 });

    const bad = http.get(`${BASE_URL}/authorize?response_type=token`,
      { responseCallback: expectedStatuses(400) },
    );
    check(bad, {
      'bad response_type: status 400': (r) => r.status === 400,
      'bad response_type: err_code':   (r) => r.json('err_code') === 10013,
    });
  });

  // ── POST /token — password grant ─────────────────────────────────────────────
  group('POST /token — password', () => {
    const res = http.post(
      `${BASE_URL}/token`,
      JSON.stringify({ grant_type: 'password', email: EMAIL, password: PASSWORD }),
      { headers: JSON_HEADERS },
    );
    check(res, {
      'status 200':           (r) => r.status === 200,
      'has access_token':     (r) => !!r.json('access_token'),
      'has refresh_token':    (r) => !!r.json('refresh_token'),
      'has id_token':         (r) => !!r.json('id_token'),
      'token_type is Bearer': (r) => r.json('token_type') === 'Bearer',
    });
  });

  // ── POST /token — refresh_token grant ────────────────────────────────────────
  group('POST /token — refresh_token', () => {
    const fresh = getTokens();
    const res = http.post(
      `${BASE_URL}/token`,
      JSON.stringify({
        grant_type: 'refresh_token', client_id: 'smoke-client',
        refresh_token: fresh.refresh_token,
      }),
      { headers: JSON_HEADERS },
    );
    check(res, {
      'status 200':        (r) => r.status === 200,
      'has access_token':  (r) => !!r.json('access_token'),
      'has refresh_token': (r) => !!r.json('refresh_token'),
    });
  });

  // ── POST /token — authorization_code grant ───────────────────────────────────
  group('POST /token — authorization_code', () => {
    const { csrfToken } = startAuthFlow(null, 'smoke-nonce');
    if (!csrfToken) {
      console.warn('authorization_code grant skipped: startAuthFlow failed');
      return;
    }

    const signIn = http.post(
      `${BASE_URL}/sign-in`,
      { email: EMAIL, password: PASSWORD, csrf_token: csrfToken },
      { headers: FORM_HEADERS, redirects: 0 },
    );
    const match = (signIn.headers['Location'] || '').match(/[?&]code=([^&]+)/);
    if (!match) {
      console.warn(`authorization_code grant skipped: sign-in status=${signIn.status}`);
      return;
    }

    const res = http.post(
      `${BASE_URL}/token`,
      JSON.stringify({
        grant_type: 'authorization_code', code: decodeURIComponent(match[1]),
        client_id: 'smoke-client', redirect_uri: REDIRECT_URI,
      }),
      { headers: JSON_HEADERS },
    );
    check(res, {
      'status 200':        (r) => r.status === 200,
      'has access_token':  (r) => !!r.json('access_token'),
      'has id_token':      (r) => !!r.json('id_token'),
    });
  });

  // ── GET /userinfo ─────────────────────────────────────────────────────────────
  group('GET /userinfo', () => {
    const res = http.get(`${BASE_URL}/userinfo`, { headers: bearerHeaders });
    check(res, {
      'status 200':    (r) => r.status === 200,
      'has sub':       (r) => !!r.json('sub'),
      'email matches': (r) => r.json('email') === EMAIL,
    });

    const unauth = http.get(`${BASE_URL}/userinfo`, { responseCallback: expectedStatuses(401) });
    check(unauth, { 'no token: status 401': (r) => r.status === 401 });
  });

  // ── GET /oidc/me ──────────────────────────────────────────────────────────────
  group('GET /oidc/me', () => {
    const res = http.get(`${BASE_URL}/oidc/me`, { headers: bearerHeaders });
    check(res, {
      'status 200': (r) => r.status === 200,
      'has sub':    (r) => !!r.json('sub'),
    });
  });

  // ── GET /.well-known/openid-configuration ────────────────────────────────────
  group('GET /.well-known/openid-configuration', () => {
    const res = http.get(`${BASE_URL}/.well-known/openid-configuration`);
    check(res, {
      'status 200':       (r) => r.status === 200,
      'has issuer':       (r) => !!r.json('issuer'),
      'has token_endpoint': (r) => !!r.json('token_endpoint'),
      'has jwks_uri':     (r) => !!r.json('jwks_uri'),
    });
  });

  // ── GET /.well-known/jwks.json ───────────────────────────────────────────────
  group('GET /.well-known/jwks.json', () => {
    const res = http.get(`${BASE_URL}/.well-known/jwks.json`);
    check(res, {
      'status 200':       (r) => r.status === 200,
      'has keys':         (r) => (r.json('keys') || []).length > 0,
      'key has kty RSA':  (r) => (r.json('keys') || [{}])[0].kty === 'RSA',
    });
  });

  // ── POST /oidc/revoke ─────────────────────────────────────────────────────────
  group('POST /oidc/revoke', () => {
    const fresh = getTokens();
    const rh = { ...JSON_HEADERS, Authorization: `Bearer ${fresh.access_token}` };

    const revoke = http.post(
      `${BASE_URL}/oidc/revoke`,
      JSON.stringify({ token: fresh.refresh_token }),
      { headers: rh },
    );
    check(revoke, { 'revoke: status 200': (r) => r.status === 200 });

    const unknown = http.post(
      `${BASE_URL}/oidc/revoke`,
      JSON.stringify({ token: 'no-such-token' }),
      { headers: rh },
    );
    check(unknown, { 'unknown token: status 200': (r) => r.status === 200 });

    const missing = http.post(
      `${BASE_URL}/oidc/revoke`,
      JSON.stringify({}),
      { headers: rh, responseCallback: expectedStatuses(400) },
    );
    check(missing, { 'missing token: status 400': (r) => r.status === 400 });
  });

  // ── POST /oidc/introspect ─────────────────────────────────────────────────────
  group('POST /oidc/introspect', () => {
    const fresh = getTokens();
    const ih = { ...JSON_HEADERS, Authorization: `Bearer ${fresh.access_token}` };

    const active = http.post(
      `${BASE_URL}/oidc/introspect`,
      JSON.stringify({ token: fresh.access_token }),
      { headers: ih },
    );
    check(active, {
      'active: status 200':  (r) => r.status === 200,
      'active: active=true': (r) => r.json('active') === true,
      'active: has sub':     (r) => !!r.json('sub'),
    });

    const inactive = http.post(
      `${BASE_URL}/oidc/introspect`,
      JSON.stringify({ token: 'revoked-token' }),
      { headers: ih },
    );
    check(inactive, {
      'inactive: status 200':   (r) => r.status === 200,
      'inactive: active=false': (r) => r.json('active') === false,
    });
  });

  // ── GET /oidc/logout ──────────────────────────────────────────────────────────
  group('GET /oidc/logout', () => {
    const fresh = getTokens();

    const withRedirect = http.get(
      `${BASE_URL}/oidc/logout` +
      `?id_token_hint=${encodeURIComponent(fresh.id_token)}` +
      `&post_logout_redirect_uri=${encodeURIComponent(POST_LOGOUT_URI)}`,
      { redirects: 0 },
    );
    check(withRedirect, {
      'with redirect: status 302':    (r) => r.status === 302,
      'with redirect: Location set':  (r) => (r.headers['Location'] || '').startsWith(POST_LOGOUT_URI),
    });

    const noRedirect = http.get(`${BASE_URL}/oidc/logout`, { redirects: 0 });
    check(noRedirect, { 'no redirect URI: status 200': (r) => r.status === 200 });
  });

  // ── POST /api/v3/update-profile ───────────────────────────────────────────────
  group('POST /api/v3/update-profile', () => {
    const fresh = getTokens();
    const fh = { ...FORM_HEADERS, Authorization: `Bearer ${fresh.access_token}` };

    const update = http.post(
      `${BASE_URL}/api/v3/update-profile`,
      { nickname: 'UpdatedSmoke' },
      { headers: fh },
    );
    check(update, {
      'update: status 200':       (r) => r.status === 200,
      'update: nickname updated': (r) => r.json('nickname') === 'UpdatedSmoke',
    });

    const badToken = http.post(
      `${BASE_URL}/api/v3/update-profile`,
      { nickname: 'X' },
      { headers: { ...FORM_HEADERS, Authorization: 'Bearer wrong-token' }, responseCallback: expectedStatuses(401) },
    );
    check(badToken, { 'wrong token: status 401': (r) => r.status === 401 });
  });

  // ── POST /forgot-password ────────────────────────────────────────────────────
  group('POST /forgot-password', () => {
    // Always 200 regardless of whether the email exists (avoids account enumeration).
    const known = http.post(
      `${BASE_URL}/forgot-password`,
      JSON.stringify({ email: EMAIL }),
      { headers: JSON_HEADERS },
    );
    check(known, { 'known email: status 200': (r) => r.status === 200 });

    const unknown = http.post(
      `${BASE_URL}/forgot-password`,
      JSON.stringify({ email: 'nobody@example.com' }),
      { headers: JSON_HEADERS },
    );
    check(unknown, { 'unknown email: status 200': (r) => r.status === 200 });

    const missing = http.post(
      `${BASE_URL}/forgot-password`,
      JSON.stringify({}),
      { headers: JSON_HEADERS, responseCallback: expectedStatuses(400) },
    );
    check(missing, { 'missing email: status 400': (r) => r.status === 400 });
  });

  // ── POST /reset-password ──────────────────────────────────────────────────────
  group('POST /reset-password', () => {
    // Invalid token → 404
    const invalid = http.post(
      `${BASE_URL}/reset-password`,
      JSON.stringify({ token: 'no-such-token', password: 'NewPass1!' }),
      { headers: JSON_HEADERS, responseCallback: expectedStatuses(404) },
    );
    check(invalid, { 'invalid token: status 404': (r) => r.status === 404 });

    // Missing fields → 400
    const missing = http.post(
      `${BASE_URL}/reset-password`,
      JSON.stringify({}),
      { headers: JSON_HEADERS, responseCallback: expectedStatuses(400) },
    );
    check(missing, { 'missing fields: status 400': (r) => r.status === 400 });
  });

  // ── GET /debug/vars ───────────────────────────────────────────────────────────
  group('GET /debug/vars', () => {
    const res = http.get(`${BASE_URL}/debug/vars`);
    check(res, {
      'status 200':                          (r) => r.status === 200,
      'has auth_tokens_issued_total':        (r) => r.json('auth_tokens_issued_total') !== undefined,
      'has auth_failed_logins_total':        (r) => r.json('auth_failed_logins_total') !== undefined,
      'has auth_token_revocations_total':    (r) => r.json('auth_token_revocations_total') !== undefined,
    });
  });
}
