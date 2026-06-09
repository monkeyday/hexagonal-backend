/**
 * Smoke test — GET /oidc/logout
 *
 * Run:  k6 run smoke_test/logout.js
 */
import http from 'k6/http';
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
}
