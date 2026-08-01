/**
 * Smoke test — POST /token (all three grant types)
 *
 *   grant_type=password           credential-based issuance
 *   grant_type=authorization_code exchange auth code for tokens
 *   grant_type=refresh_token      rotate tokens
 *
 * Run:  k6 run smoke_test/token.js
 */
import http, { expectedStatuses } from 'k6/http';
import { check, group } from 'k6';
import { smokeOptions, BASE_URL, EMAIL, PASSWORD, REDIRECT_URI, ensureUser, startAuthFlow } from './helpers.js';

export const options = smokeOptions;

const JSON_HEADERS = { 'Content-Type': 'application/json' };
const FORM_HEADERS = { 'Content-Type': 'application/x-www-form-urlencoded' };

export function setup() {
  ensureUser();
}

/**
 * Run the browser leg of the auth-code flow and return a fresh, unused code.
 * Each negative exchange below needs its own: consumeAuthCode runs before any
 * validation (exchange_code.go:66), so a rejected exchange still burns the code.
 * Returns null when the flow could not be completed.
 */
function obtainAuthCode() {
  const { csrfToken, codeVerifier } = startAuthFlow(null, 'smoke-nonce');
  if (!csrfToken) return null;

  const signIn = http.post(
    `${BASE_URL}/sign-in`,
    { email: EMAIL, password: PASSWORD, csrf_token: csrfToken },
    { headers: FORM_HEADERS, redirects: 0 },
  );

  const location = signIn.headers['Location'] || signIn.headers['location'] || '';
  const match    = location.match(/[?&]code=([^&]+)/);
  if (!match) {
    console.warn(`obtainAuthCode failed: sign-in status=${signIn.status} location=${location}`);
    return null;
  }
  return { code: decodeURIComponent(match[1]), codeVerifier, signIn };
}

export default function () {
  // ── grant_type=password ──────────────────────────────────────────────────────
  let accessToken  = '';
  let refreshToken = '';

  group('password grant', () => {
    const res = http.post(
      `${BASE_URL}/token`,
      JSON.stringify({ grant_type: 'password', email: EMAIL, password: PASSWORD }),
      { headers: JSON_HEADERS },
    );

    check(res, {
      'status 200':              (r) => r.status === 200,
      'has access_token':        (r) => !!r.json('access_token'),
      'has refresh_token':       (r) => !!r.json('refresh_token'),
      'has id_token':            (r) => !!r.json('id_token'),
      'token_type is Bearer':    (r) => r.json('token_type') === 'Bearer',
    });

    accessToken  = res.json('access_token')  || '';
    refreshToken = res.json('refresh_token') || '';
  });

  // ── grant_type=refresh_token ─────────────────────────────────────────────────
  group('refresh_token grant', () => {
    if (!refreshToken) {
      console.warn('refresh_token grant skipped: no token from password grant');
      return;
    }

    const res = http.post(
      `${BASE_URL}/token`,
      JSON.stringify({
        grant_type:    'refresh_token',
        client_id:     'smoke-client',
        refresh_token: refreshToken,
      }),
      { headers: JSON_HEADERS },
    );

    check(res, {
      'status 200':           (r) => r.status === 200,
      'has access_token':     (r) => !!r.json('access_token'),
      'has refresh_token':    (r) => !!r.json('refresh_token'),
      'token_type is Bearer': (r) => r.json('token_type') === 'Bearer',
    });
  });

  // ── grant_type=authorization_code ────────────────────────────────────────────
  group('authorization_code grant', () => {
    // Establish OIDC session, then POST /sign-in with the scraped csrf_token.
    const issued = obtainAuthCode();
    if (!issued) {
      console.warn('authorization_code grant skipped: could not obtain an auth code');
      return;
    }
    const { code, codeVerifier, signIn } = issued;

    check(signIn, {
      'POST /sign-in: status 303':          (r) => r.status === 303,
      'POST /sign-in: has Location header': (r) => !!(r.headers['Location'] || r.headers['location']),
    });

    const res = http.post(
      `${BASE_URL}/token`,
      {
        grant_type:    'authorization_code',
        code:          code,
        client_id:     'smoke-client',
        redirect_uri:  REDIRECT_URI,
        code_verifier: codeVerifier,
      },
      { headers: FORM_HEADERS },
    );

    check(res, {
      'status 200':           (r) => r.status === 200,
      'has access_token':     (r) => !!r.json('access_token'),
      'has refresh_token':    (r) => !!r.json('refresh_token'),
      'has id_token':         (r) => !!r.json('id_token'),
      'token_type is Bearer': (r) => r.json('token_type') === 'Bearer',
      'scope matches':        (r) => (r.json('scope') || '').includes('openid'),
    });
  });

  // ── PKCE: wrong code_verifier — expects 400 invalid_grant ────────────────────
  group('authorization_code grant with a wrong PKCE verifier', () => {
    const issued = obtainAuthCode();
    if (!issued) {
      console.warn('wrong PKCE verifier skipped: could not obtain an auth code');
      return;
    }

    const res = http.post(
      `${BASE_URL}/token`,
      {
        grant_type:    'authorization_code',
        code:          issued.code,
        client_id:     'smoke-client',
        redirect_uri:  REDIRECT_URI,
        code_verifier: `${issued.codeVerifier}-tampered`,
      },
      { headers: FORM_HEADERS, responseCallback: expectedStatuses(400) },
    );

    check(res, {
      'wrong verifier: status 400':                (r) => r.status === 400,
      'wrong verifier: RFC 6749 error invalid_grant': (r) => r.json('error') === 'invalid_grant',
      'wrong verifier: no tokens issued':          (r) => !r.json('access_token'),
    });
  });

  // ── Mismatched redirect_uri — expects 400 invalid_grant ──────────────────────
  group('authorization_code grant with a mismatched redirect_uri', () => {
    const issued = obtainAuthCode();
    if (!issued) {
      console.warn('mismatched redirect_uri skipped: could not obtain an auth code');
      return;
    }

    // Exact-match against the URI the code was issued for
    // (auth_code.go:79-81), not against the client's registered set.
    const res = http.post(
      `${BASE_URL}/token`,
      {
        grant_type:    'authorization_code',
        code:          issued.code,
        client_id:     'smoke-client',
        redirect_uri:  `${REDIRECT_URI}/elsewhere`,
        code_verifier: issued.codeVerifier,
      },
      { headers: FORM_HEADERS, responseCallback: expectedStatuses(400) },
    );

    check(res, {
      'redirect_uri mismatch: status 400':                (r) => r.status === 400,
      'redirect_uri mismatch: RFC 6749 error invalid_grant': (r) => r.json('error') === 'invalid_grant',
      'redirect_uri mismatch: no tokens issued':          (r) => !r.json('access_token'),
    });
  });

  // ── unsupported grant_type — expects 400 ─────────────────────────────────────
  group('unsupported grant_type', () => {
    const res = http.post(
      `${BASE_URL}/token`,
      JSON.stringify({ grant_type: 'client_credentials' }),
      { headers: JSON_HEADERS, responseCallback: expectedStatuses(400) },
    );
    check(res, {
      'status 400':                       (r) => r.status === 400,
      'RFC 6749 error unsupported_grant_type': (r) => r.json('error') === 'unsupported_grant_type',
    });
  });
}
