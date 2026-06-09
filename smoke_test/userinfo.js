/**
 * Smoke test — GET /userinfo  +  GET /oidc/me
 *
 * Run:  k6 run smoke_test/userinfo.js
 */
import http, { expectedStatuses } from 'k6/http';
import { check } from 'k6';
import { smokeOptions, BASE_URL, EMAIL, ensureUser, getTokens } from './helpers.js';

export const options = smokeOptions;

export function setup() {
  ensureUser();
  return getTokens();
}

export default function (tokens) {
  const headers = { Authorization: `Bearer ${tokens.access_token}` };

  // ── GET /userinfo ────────────────────────────────────────────────────────────
  const userinfo = http.get(`${BASE_URL}/userinfo`, { headers });
  check(userinfo, {
    '/userinfo: status 200':         (r) => r.status === 200,
    '/userinfo: has sub':            (r) => !!r.json('sub'),
    '/userinfo: email matches':      (r) => r.json('email') === EMAIL,
    '/userinfo: email_verified':     (r) => r.json('email_verified') === true,
    '/userinfo: has preferred_username': (r) => !!r.json('preferred_username'),
  });

  // ── GET /oidc/me — alias ─────────────────────────────────────────────────────
  const me = http.get(`${BASE_URL}/oidc/me`, { headers });
  check(me, {
    '/oidc/me: status 200':    (r) => r.status === 200,
    '/oidc/me: has sub':       (r) => !!r.json('sub'),
    '/oidc/me: email matches': (r) => r.json('email') === EMAIL,
  });

  // ── Missing token — expects 401 ──────────────────────────────────────────────
  const unauth = http.get(`${BASE_URL}/userinfo`, { responseCallback: expectedStatuses(401) });
  check(unauth, {
    'no token: status 401':  (r) => r.status === 401,
    'no token: err_code':    (r) => r.json('err_code') === 10002,
  });
}
