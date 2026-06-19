/**
 * Reusable per-VU actions for the stress suite.
 *
 * Each action operates on a per-VU `session` (see newSession) that lazily mints
 * and caches credentials, so a VU can mix actions across iterations without
 * re-authenticating every time. Actions own their own checks and request tags,
 * keeping the scenario scripts (single-action and mixed) thin.
 */
import http, { expectedStatuses } from 'k6/http';
import { check } from 'k6';
import {
  BASE_URL, REDIRECT_URI, CLIENT_ID, PASSWORD, FORM_HEADERS,
  ensureUser, getTokens, rotate, vuEmail, startAuthFlow,
} from './helpers.js';

/** Per-VU mutable session holding lazily-minted credentials. */
export function newSession() {
  return { registered: false, accessToken: null, refreshToken: null };
}

function ensureRegistered(s) {
  if (!s.registered) {
    ensureUser();
    s.registered = true;
  }
}

/** One authenticated GET /userinfo; re-mints the access token on 401. */
export function doUserinfo(s) {
  ensureRegistered(s);
  if (!s.accessToken) {
    s.accessToken = getTokens().access_token || null;
    if (!s.accessToken) return;
  }
  const res = http.get(`${BASE_URL}/userinfo`, {
    headers: { Authorization: `Bearer ${s.accessToken}` },
    tags: { endpoint: 'userinfo' },
  });
  if (res.status === 401) {
    s.accessToken = null; // expired/revoked; re-mint next call
    return;
  }
  check(res, {
    'userinfo: status 200': (r) => r.status === 200,
    'userinfo: has sub': (r) => !!r.json('sub'),
    'userinfo: email matches': (r) => r.json('email') === vuEmail(),
  });
}

/**
 * Rotate the session's refresh token forward (no destructive reuse check).
 * Returns { ok, consumed } so callers (token_refresh.js) can additionally
 * assert reuse rejection on the consumed token.
 */
export function doRefresh(s) {
  ensureRegistered(s);
  if (!s.refreshToken) {
    s.refreshToken = getTokens().refresh_token || null;
    if (!s.refreshToken) return { ok: false, consumed: null };
  }
  const consumed = s.refreshToken;
  const res = rotate(consumed);
  const ok = check(res, {
    'rotate: status 200': (r) => r.status === 200,
    'rotate: new refresh_token': (r) => !!r.json('refresh_token'),
    'rotate: token actually rotated': (r) => r.json('refresh_token') !== consumed,
  });
  if (!ok) {
    s.refreshToken = null; // chain broken; re-mint next call
    return { ok: false, consumed };
  }
  s.refreshToken = res.json('refresh_token');
  return { ok: true, consumed };
}

/**
 * Replaying a consumed refresh token must be rejected (finding #6). The 4xx is
 * expected, so it is excluded from http_req_failed and measured separately.
 * Revokes the whole token family, so the caller should drop its cached token.
 */
export function assertReuseRejected(consumed) {
  const res = http.post(
    `${BASE_URL}/token`,
    JSON.stringify({ grant_type: 'refresh_token', client_id: CLIENT_ID, refresh_token: consumed }),
    {
      headers: { 'Content-Type': 'application/json' },
      tags: { endpoint: 'refresh_reuse' },
      responseCallback: expectedStatuses(400, 401),
    },
  );
  check(res, { 'reuse: rejected (4xx)': (r) => r.status === 400 || r.status === 401 });
}

/** Full browser login: /authorize -> CSRF -> /sign-in -> /token (auth code). */
export function doLogin(s) {
  ensureRegistered(s);
  const { csrfToken, codeVerifier } = startAuthFlow(`nonce-${__VU}-${__ITER}`);
  if (!check(null, { 'authorize: csrf_token scraped': () => !!csrfToken })) return;

  const signIn = http.post(
    `${BASE_URL}/sign-in`,
    { email: vuEmail(), password: PASSWORD, csrf_token: csrfToken },
    { headers: FORM_HEADERS, redirects: 0, tags: { endpoint: 'sign_in' } },
  );
  const location = signIn.headers['Location'] || signIn.headers['location'] || '';
  const codeMatch = location.match(/[?&]code=([^&]+)/);
  const signedIn = check(signIn, {
    'sign_in: status 303': (r) => r.status === 303,
    'sign_in: location has code': () => !!codeMatch,
  });
  if (!signedIn || !codeMatch) return;

  const res = http.post(
    `${BASE_URL}/token`,
    {
      grant_type: 'authorization_code',
      code: decodeURIComponent(codeMatch[1]),
      client_id: CLIENT_ID,
      redirect_uri: REDIRECT_URI,
      code_verifier: codeVerifier,
    },
    { headers: FORM_HEADERS, tags: { endpoint: 'token_code' } },
  );
  check(res, {
    'token_code: status 200': (r) => r.status === 200,
    'token_code: has access_token': (r) => !!r.json('access_token'),
    'token_code: has id_token': (r) => !!r.json('id_token'),
  });
}

/** Cheap unauthenticated read of the discovery document. */
export function doDiscovery() {
  const res = http.get(`${BASE_URL}/.well-known/openid-configuration`, {
    tags: { endpoint: 'discovery' },
  });
  check(res, {
    'discovery: status 200': (r) => r.status === 200,
    'discovery: has issuer': (r) => !!r.json('issuer'),
  });
}

// Traffic mix for mixed/spike/soak: ~60% userinfo, 20% refresh, 10% login,
// 10% discovery. Tags accumulate per endpoint so each path is measurable.
export function doMixedIteration(s) {
  const r = Math.random();
  if (r < 0.6) doUserinfo(s);
  else if (r < 0.8) doRefresh(s);
  else if (r < 0.9) doLogin(s);
  else doDiscovery();
}

/** Endpoint tags exercised by the mixed workload (flat threshold, e.g. spike). */
export const MIXED_ENDPOINTS = ['userinfo', 'refresh', 'token_code', 'discovery'];

// Per-endpoint p95 guardrails (ms) for the steady mixed workload, ~6x the
// baseline p95 (see stress_test/README.md). Generous on purpose: these catch
// gross regressions, not tight SLOs, and tolerate slower hardware until a
// production-representative baseline is established.
export const MIXED_THRESHOLDS = { userinfo: 150, refresh: 300, token_code: 300, discovery: 150 };
