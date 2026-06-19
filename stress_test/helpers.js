/**
 * Shared helpers for the k6 stress/load suite.
 *
 * Unlike smoke_test/helpers.js (1 VU, 1 iteration, one shared user), the load
 * suite runs many concurrent VUs. Two server behaviours make a *shared* user
 * unsafe under concurrency, so every VU owns a unique identity:
 *
 *   - refresh-token rotation + reuse detection (finding #6) is account-scoped:
 *     concurrent rotations of one account's token poison each other.
 *   - per-account lockout (finding #8) trips on concurrent failed logins.
 *
 * The server under test must run with rate limiting disabled
 * (RATE_LIMIT_PER_MIN=0); otherwise the single load-generator IP is throttled.
 */
import http, { expectedStatuses } from 'k6/http';
import { check } from 'k6';
import crypto from 'k6/crypto';
import encoding from 'k6/encoding';

export const BASE_URL = __ENV.BASE_URL || 'http://localhost:9876';
export const REDIRECT_URI = __ENV.REDIRECT_URI || 'https://app.example.com/callback';
export const CLIENT_ID = __ENV.CLIENT_ID || 'smoke-client';

// Shared password for every generated load user.
export const PASSWORD = __ENV.PASSWORD || 'LoadTest1!';

export const JSON_HEADERS = { 'Content-Type': 'application/json' };
export const FORM_HEADERS = { 'Content-Type': 'application/x-www-form-urlencoded' };

/** Unique, stable identity for the current VU. */
export function vuEmail() {
  return `load_user_${__VU}@example.com`;
}

/**
 * Build per-endpoint latency + failure thresholds.
 * Pass endpoint tag names; requests tagged `{ endpoint: name }` are measured
 * independently. Example: perEndpointThresholds(['userinfo', 'refresh']).
 */
export function perEndpointThresholds(endpoints, p95 = 800) {
  const t = { http_req_failed: ['rate<0.01'] };
  for (const name of endpoints) {
    t[`http_req_duration{endpoint:${name}}`] = [`p(95)<${p95}`];
  }
  return t;
}

/**
 * Register the current VU's user via POST /sign-up. Idempotent: 409 (already
 * exists) is treated as success so VUs can call this once in their first
 * iteration. Throws on any other status.
 */
export function ensureUser(email = vuEmail()) {
  const res = http.post(
    `${BASE_URL}/sign-up`,
    { username: `load${__VU}`, nickname: 'Load', email, password: PASSWORD },
    {
      headers: FORM_HEADERS,
      responseCallback: expectedStatuses(200, 409),
      tags: { endpoint: 'sign_up' },
    },
  );
  if (res.status !== 200 && res.status !== 409) {
    throw new Error(`ensureUser(${email}): unexpected status ${res.status}: ${res.body}`);
  }
  return res;
}

/**
 * Obtain tokens via the password grant (client-less; refresh token is unbound).
 * Returns { access_token, refresh_token, id_token }.
 */
export function getTokens(email = vuEmail()) {
  const res = http.post(
    `${BASE_URL}/token`,
    JSON.stringify({ grant_type: 'password', email, password: PASSWORD }),
    { headers: JSON_HEADERS, tags: { endpoint: 'password' } },
  );
  check(res, { 'getTokens: status 200': (r) => r.status === 200 });
  return JSON.parse(res.body || '{}');
}

/**
 * Rotate a refresh token. Returns the raw http response so callers can both
 * read the new token and assert on status. Tagged `endpoint: refresh`.
 */
export function rotate(refreshToken) {
  return http.post(
    `${BASE_URL}/token`,
    JSON.stringify({ grant_type: 'refresh_token', client_id: CLIENT_ID, refresh_token: refreshToken }),
    { headers: JSON_HEADERS, tags: { endpoint: 'refresh' } },
  );
}

/** PKCE (S256) pair: random verifier + derived challenge. */
export function pkcePair() {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';
  let verifier = '';
  for (let i = 0; i < 43; i++) verifier += chars[Math.floor(Math.random() * chars.length)];
  const challenge = encoding.b64encode(crypto.sha256(verifier, 'binary'), 'rawurl');
  return { verifier, challenge };
}

/**
 * Establish an OIDC session and scrape the csrf_token for POST /sign-in.
 * GET /authorize sets auth_session and 302s to /sign-in; k6 follows it.
 * Returns { csrfToken, codeVerifier }.
 */
export function startAuthFlow(nonce) {
  const { verifier, challenge } = pkcePair();
  let qs = `response_type=code&client_id=${CLIENT_ID}` +
    `&redirect_uri=${encodeURIComponent(REDIRECT_URI)}&scope=openid%20email` +
    `&code_challenge=${challenge}&code_challenge_method=S256`;
  if (nonce) qs += `&nonce=${encodeURIComponent(nonce)}`;

  const page = http.get(`${BASE_URL}/authorize?${qs}`, { tags: { endpoint: 'authorize' } });
  const match = (page.body || '').match(/name="csrf_token"\s+value="([^"]+)"/);
  return { csrfToken: match ? match[1] : '', codeVerifier: verifier };
}
