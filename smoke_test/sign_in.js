/**
 * Smoke test — GET /sign-in  +  POST /sign-in
 *
 * Run:  k6 run smoke_test/sign_in.js
 */
import http from 'k6/http';
import { check } from 'k6';
import { smokeOptions, BASE_URL, EMAIL, PASSWORD, REDIRECT_URI, ensureUser, startAuthFlow } from './helpers.js';

export const options = smokeOptions;

export function setup() {
  ensureUser();
}

export default function () {
  const state = 'smoke-state-xyz';
  const nonce = 'smoke-nonce';

  // ── GET /authorize → GET /sign-in — establish session ───────────────────────
  // GET /authorize sets the auth_session cookie and issues a 302 to /sign-in.
  // k6 follows the redirect automatically (carrying the cookie), returning the
  // sign-in HTML page which contains a hidden csrf_token input.
  const { page, csrfToken } = startAuthFlow(state, nonce);
  check(page, {
    'GET /sign-in status 200':         (r) => r.status === 200,
    'GET /sign-in returns HTML':       (r) => (r.headers['Content-Type'] || '').includes('text/html'),
    'GET /sign-in has csrf_token':     (r) => (r.body || '').includes('name="csrf_token"'),
  });

  // ── POST /sign-in — submit credentials with csrf_token ──────────────────────
  // auth_session cookie is sent automatically by k6's cookie jar.
  const post = http.post(
    `${BASE_URL}/sign-in`,
    { email: EMAIL, password: PASSWORD, csrf_token: csrfToken },
    {
      headers:   { 'Content-Type': 'application/x-www-form-urlencoded' },
      redirects: 0,
    },
  );

  check(post, {
    'POST /sign-in status 303':                    (r) => r.status === 303,
    'POST /sign-in Location contains code=':       (r) => (r.headers['Location'] || '').includes('code='),
    'POST /sign-in Location contains state=':      (r) => (r.headers['Location'] || '').includes(`state=${state}`),
    'POST /sign-in Location starts with callback': (r) => (r.headers['Location'] || '').startsWith(REDIRECT_URI),
  });
}
