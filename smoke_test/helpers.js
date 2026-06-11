import http, { expectedStatuses } from 'k6/http';
import { check } from 'k6';
import crypto from 'k6/crypto';
import encoding from 'k6/encoding';

export const BASE_URL    = __ENV.BASE_URL || 'http://localhost:9876';
export const REDIRECT_URI = 'https://app.example.com/callback';

// Credentials used by tests that need a real user.
// Override via: k6 run -e EMAIL=... -e PASSWORD=... <script>
export const EMAIL    = __ENV.EMAIL    || 'smoke@example.com';
export const PASSWORD = __ENV.PASSWORD || 'SmokeTest1!';

const CLIENT_ID = 'smoke-client';

/**
 * PKCE (mandatory for public clients): random verifier + S256 challenge.
 */
export function pkcePair() {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';
  let verifier = '';
  for (let i = 0; i < 43; i++) verifier += chars[Math.floor(Math.random() * chars.length)];
  const challenge = encoding.b64encode(crypto.sha256(verifier, 'binary'), 'rawurl');
  return { verifier, challenge };
}

/** Query-string fragment carrying a fresh PKCE challenge for GET /authorize checks. */
export function pkceParams() {
  return `&code_challenge=${pkcePair().challenge}&code_challenge_method=S256`;
}

/**
 * Register the smoke-test user via POST /sign-up.
 * Returns the parsed response body.
 * Ignores 409 (already exists) so tests can call this safely in setup().
 */
export function ensureUser() {
  const res = http.post(
    `${BASE_URL}/sign-up`,
    { username: 'smokeuser', nickname: 'Smoke', email: EMAIL, password: PASSWORD },
    {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      responseCallback: expectedStatuses(200, 409),
    },
  );
  if (res.status !== 200 && res.status !== 409) {
    throw new Error(`ensureUser: unexpected status ${res.status}: ${res.body}`);
  }
  return res;
}

/**
 * Obtain tokens via the password grant.
 * Returns { access_token, refresh_token, id_token }.
 */
export function getTokens() {
  const res = http.post(
    `${BASE_URL}/token`,
    JSON.stringify({ grant_type: 'password', email: EMAIL, password: PASSWORD }),
    { headers: { 'Content-Type': 'application/json' } },
  );
  check(res, { 'getTokens: status 200': (r) => r.status === 200 });
  return JSON.parse(res.body);
}

/**
 * Establish an OIDC session and return the csrf_token needed for POST /sign-in.
 * GET /authorize creates the session (Set-Cookie: auth_session) and issues a 302
 * to GET /sign-in; k6 follows the redirect automatically, sending the cookie.
 * The csrf_token is scraped from the hidden input in the returned HTML.
 */
export function startAuthFlow(state, nonce) {
  const { verifier, challenge } = pkcePair();
  let qs = `response_type=code&client_id=${CLIENT_ID}` +
    `&redirect_uri=${encodeURIComponent(REDIRECT_URI)}&scope=openid%20email` +
    `&code_challenge=${challenge}&code_challenge_method=S256`;
  if (state) qs += `&state=${encodeURIComponent(state)}`;
  if (nonce) qs += `&nonce=${encodeURIComponent(nonce)}`;

  const page = http.get(`${BASE_URL}/authorize?${qs}`);
  const match = (page.body || '').match(/name="csrf_token"\s+value="([^"]+)"/);
  return { page, csrfToken: match ? match[1] : '', codeVerifier: verifier };
}

/** Smoke-test options: single VU, single iteration. */
export const smokeOptions = {
  vus: 1,
  iterations: 1,
  thresholds: {
    http_req_failed:   ['rate<0.01'],
    http_req_duration: ['p(95)<2000'],
  },
};
