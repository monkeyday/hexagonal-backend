/**
 * Smoke test — GET and POST /oidc/logout
 *
 * Run:  k6 run smoke_test/logout.js
 */
import http, { expectedStatuses } from 'k6/http';
import { check } from 'k6';
import { smokeOptions, BASE_URL, ensureUser, getTokens } from './helpers.js';

export const options = smokeOptions;

const POST_LOGOUT_URI = 'https://app.example.com/logged-out';

/** True when the response carries a Set-Cookie that expires refresh_token. */
function clearsRefreshCookie(res) {
  const header = res.headers['Set-Cookie'] || res.headers['set-cookie'] || '';
  return header.includes('refresh_token=') && header.includes('Max-Age=0');
}

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
    // LogoutResponse.Cookies() clears refresh_token with MaxAge -1
    // (define/response.go:85-87); net/http renders a negative MaxAge as
    // "Max-Age=0", not "Max-Age=-1". Asserted on the redirect branch as well as
    // the 200 below because docs/auth.yaml documents the clear on both.
    'with hint: clears refresh_token cookie': (r) => clearsRefreshCookie(r),
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
    'no redirect URI: status 200':                  (r) => r.status === 200,
    'no redirect URI: clears refresh_token cookie': (r) => clearsRefreshCookie(r),
  });

  // None of the calls above carried a bearer, so none of them may have revoked
  // anything — id_token_hint rides along on cross-site GET navigations, and
  // honouring it would let an attacker log a victim out (logout.go:53-63).
  const survived = http.get(`${BASE_URL}/oidc/me`, {
    headers: { Authorization: `Bearer ${tokens.access_token}` },
  });
  check(survived, {
    'bearer-less logout revokes nothing: status 200': (r) => r.status === 200,
  });

  // Both halves, for the same reason the kept-session check below needs both: a
  // regression that swept the refresh rows without writing a grant marker would
  // leave the access token above answering 200 while the session was gone.
  const survivedRefresh = http.post(
    `${BASE_URL}/token`,
    JSON.stringify({
      grant_type:    'refresh_token',
      client_id:     'smoke-client',
      refresh_token: tokens.refresh_token,
    }),
    { headers: { 'Content-Type': 'application/json' } },
  );
  check(survivedRefresh, {
    'bearer-less logout leaves the refresh token usable: status 200': (r) => r.status === 200,
  });

  // ── Per-session revocation ──────────────────────────────────────────────────
  // With a bearer, logout ends exactly the session that token belongs to
  // (grant-linkage.md §1).
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

  // The assertion that actually distinguishes per-session from user-wide
  // revocation. A regression to RevokeAllForUser would revoke *both* sessions'
  // refresh tokens while leaving this stateless access token valid until exp,
  // so the check above would still pass — only this one fails.
  const keptRefresh = http.post(
    `${BASE_URL}/token`,
    JSON.stringify({
      grant_type:    'refresh_token',
      client_id:     'smoke-client',
      refresh_token: kept.refresh_token,
    }),
    { headers: { 'Content-Type': 'application/json' } },
  );
  check(keptRefresh, {
    'logout leaves the other session refreshable: status 200': (r) => r.status === 200,
  });

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

  // ── POST /oidc/logout ───────────────────────────────────────────────────────
  // Same handler chain as the GET (router.go), so this asserts the route is
  // wired to the logout command rather than merely registered: it must take the
  // redirect URI from a form-encoded body and end the bearer's own session.
  // RP-Initiated Logout 1.0 §2 permits either method.
  const posted = getTokens();

  const postLogout = http.post(
    `${BASE_URL}/oidc/logout`,
    { post_logout_redirect_uri: POST_LOGOUT_URI },
    {
      redirects: 0,
      headers: { Authorization: `Bearer ${posted.access_token}` },
    },
  );
  // 303, not the GET's 302: HTTPResponder.redirectStatus returns See Other for
  // POST (http_responder.go:88-93) so the follow-up is a GET.
  check(postLogout, {
    'POST logout: status 303':               (r) => r.status === 303,
    'POST logout: Location is redirect URI': (r) =>
      (r.headers['Location'] || '').startsWith(POST_LOGOUT_URI),
  });

  const postedMe = http.get(`${BASE_URL}/oidc/me`, {
    headers: { Authorization: `Bearer ${posted.access_token}` },
    responseCallback: expectedStatuses(401),
  });
  check(postedMe, {
    'POST logout ends its own session: status 401': (r) => r.status === 401,
  });
}
