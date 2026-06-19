/**
 * Stress test — full browser login path under concurrency.
 *
 *   GET  /authorize   establish OIDC session, scrape csrf_token   (tag: authorize)
 *   POST /sign-in     authenticate, receive 303 with ?code=...    (tag: sign_in)
 *   POST /token       exchange code + PKCE verifier for tokens     (tag: token_code)
 *
 * Each VU owns a unique user. Requires rate limiting disabled
 * (RATE_LIMIT_PER_MIN=0) and per-account lockout headroom — only valid
 * credentials are used, so lockout is not exercised.
 *
 * Run:  k6 run stress_test/auth_code_flow.js
 *       k6 run -e VUS=30 -e DURATION=2m stress_test/auth_code_flow.js
 */
import http from 'k6/http';
import { check } from 'k6';
import {
  BASE_URL, REDIRECT_URI, CLIENT_ID, PASSWORD, FORM_HEADERS,
  ensureUser, vuEmail, startAuthFlow, perEndpointThresholds,
} from './helpers.js';

const VUS = Number(__ENV.VUS || 20);
const DURATION = __ENV.DURATION || '1m';

export const options = {
  scenarios: {
    auth_code: {
      executor: 'ramping-vus',
      startVUs: 0,
      stages: [
        { duration: '15s', target: VUS },
        { duration: DURATION, target: VUS },
        { duration: '10s', target: 0 },
      ],
      gracefulRampDown: '5s',
    },
  },
  thresholds: perEndpointThresholds(['authorize', 'sign_in', 'token_code'], 1000),
};

// Per-VU state (k6 init context is per-VU).
let registered = false;

export default function () {
  if (!registered) {
    ensureUser();
    registered = true;
  }

  const { csrfToken, codeVerifier } = startAuthFlow(`nonce-${__VU}-${__ITER}`);
  if (!check(null, { 'authorize: csrf_token scraped': () => !!csrfToken })) {
    return;
  }

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
