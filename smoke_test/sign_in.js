/**
 * Smoke test — GET /sign-in  +  POST /sign-in
 *
 * Run:  k6 run smoke_test/sign_in.js
 */
import http, { expectedStatuses } from 'k6/http';
import { check } from 'k6';
import { smokeOptions, BASE_URL, EMAIL, PASSWORD, REDIRECT_URI, ensureUser, startAuthFlow } from './helpers.js';

export const options = smokeOptions;

export function setup() {
  ensureUser();
}

export default function () {
  const state = 'smoke-state-xyz';
  const nonce = 'smoke-nonce';

  // ── POST /sign-in with a wrong password — expects 401 ───────────────────────
  // Deliberately first. Each startAuthFlow mints a new session and overwrites the
  // auth_session cookie in k6's per-VU jar, while the csrf_token is scraped from
  // the page — so whichever flow starts last owns the cookie, and an earlier
  // flow's csrf_token no longer matches it. The session is looked up by cookie
  // and CSRF-checked before credentials (create_auth_code.go:45-56), so running
  // this after the happy path's startAuthFlow would fail the happy path with a
  // 400 invalid session instead of the 303 it asserts.
  //
  // Ordering it first also keeps the lockout argument true: the account counter
  // this bumps is reset by the successful sign-in below (create_auth_code.go:137),
  // one failure is well under MaxFailedLoginAttempts (5, user.go:19), and the
  // shared smoke user therefore cannot be locked out of the other scenario files.
  const wrong = startAuthFlow(state, nonce);
  const wrongPost = http.post(
    `${BASE_URL}/sign-in`,
    { email: EMAIL, password: `${PASSWORD}-wrong`, csrf_token: wrong.csrfToken },
    {
      headers:          { 'Content-Type': 'application/x-www-form-urlencoded' },
      redirects:        0,
      responseCallback: expectedStatuses(401),
    },
  );

  check(wrongPost, {
    'wrong password: status 401': (r) => r.status === 401,
    // POST /sign-in is not in the OAuth2 error-format group (router.go:61 sits
    // outside tokenHandlers), so the body is the generic responder shape.
    'wrong password: generic credentials message': (r) => r.json('msg') === 'invalid email or password',
    'wrong password: err_code 10005':              (r) => r.json('err_code') === 10005,
    // No code may be minted: a 303 back to the callback would mean a failed
    // sign-in still produced an authorization code.
    'wrong password: no redirect': (r) => !(r.headers['Location'] || r.headers['location']),
  });

  // ── GET /authorize → GET /sign-in — establish session ───────────────────────
  // GET /authorize sets the auth_session cookie and issues a 302 to /sign-in.
  // k6 follows the redirect automatically (carrying the cookie), returning the
  // sign-in HTML page which contains a hidden csrf_token input. This is the last
  // flow started, so the jar's cookie and this csrf_token belong to each other.
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
