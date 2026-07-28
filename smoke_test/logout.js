/**
 * Smoke test — GET /oidc/logout
 *
 * Run:  k6 run smoke_test/logout.js
 */
import http, { expectedStatuses } from 'k6/http';
import { check } from 'k6';
import { smokeOptions, BASE_URL, ensureUser, getTokens } from './helpers.js';

export const options = smokeOptions;

const POST_LOGOUT_URI = 'https://app.example.com/logged-out';

export function setup() {
  ensureUser();
  return getTokens();
}

export default function (tokens) {
  // ── With id_token_hint and redirect URI — expects 302 ───────────────────────
  const withHint = http.get(
    `${BASE_URL}/oidc/logout` +
    `?id_token_hint=${encodeURIComponent(tokens.id_token)}` +
    `&post_logout_redirect_uri=${encodeURIComponent(POST_LOGOUT_URI)}`,
    { redirects: 0 },
  );
  check(withHint, {
    'with hint: status 302':              (r) => r.status === 302,
    'with hint: Location is redirect URI': (r) =>
      (r.headers['Location'] || '').startsWith(POST_LOGOUT_URI),
  });

  // ── Without id_token_hint, with redirect URI ─────────────────────────────────
  const noHint = http.get(
    `${BASE_URL}/oidc/logout?post_logout_redirect_uri=${encodeURIComponent(POST_LOGOUT_URI)}`,
    { redirects: 0 },
  );
  check(noHint, {
    'no hint: status 302':               (r) => r.status === 302,
    'no hint: Location is redirect URI': (r) =>
      (r.headers['Location'] || '').startsWith(POST_LOGOUT_URI),
  });

  // ── Without redirect URI — expects 200 ──────────────────────────────────────
  const noURI = http.get(`${BASE_URL}/oidc/logout`, { redirects: 0 });
  check(noURI, {
    'no redirect URI: status 200': (r) => r.status === 200,
  });

  // ── Per-session revocation ──────────────────────────────────────────────────
  // The calls above carry no bearer, so they never reach the revocation path:
  // id_token_hint alone must not end a session (CSRF). With a bearer, logout
  // ends exactly the session that token belongs to (grant-linkage.md §1).
  const ended = getTokens();
  const kept  = getTokens();

  const authed = http.get(
    `${BASE_URL}/oidc/logout?post_logout_redirect_uri=${encodeURIComponent(POST_LOGOUT_URI)}`,
    { redirects: 0, headers: { Authorization: `Bearer ${ended.access_token}` } },
  );
  check(authed, { 'authenticated logout: status 302': (r) => r.status === 302 });

  const endedMe = http.get(`${BASE_URL}/oidc/me`, {
    headers: { Authorization: `Bearer ${ended.access_token}` },
    responseCallback: expectedStatuses(401),
  });
  check(endedMe, { 'logout ends its own session: status 401': (r) => r.status === 401 });

  const keptMe = http.get(`${BASE_URL}/oidc/me`, {
    headers: { Authorization: `Bearer ${kept.access_token}` },
  });
  check(keptMe, { 'logout leaves other sessions signed in: status 200': (r) => r.status === 200 });

  const endedRefresh = http.post(
    `${BASE_URL}/token`,
    JSON.stringify({
      grant_type:    'refresh_token',
      client_id:     'smoke-client',
      refresh_token: ended.refresh_token,
    }),
    {
      headers: { 'Content-Type': 'application/json' },
      responseCallback: expectedStatuses(400, 401),
    },
  );
  check(endedRefresh, {
    'logout revokes its grant refresh token: 4xx': (r) => r.status === 400 || r.status === 401,
  });
}
