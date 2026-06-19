/**
 * Stress test — high-frequency authenticated read (GET /userinfo).
 *
 * Each VU mints an access token once, then hammers /userinfo. If the token
 * expires (401) the VU re-mints, so the scenario stays valid under soak.
 *
 * Requires the server to run with rate limiting disabled: RATE_LIMIT_PER_MIN=0.
 *
 * Run:  k6 run stress_test/userinfo.js
 *       k6 run -e VUS=100 -e DURATION=2m stress_test/userinfo.js
 */
import http from 'k6/http';
import { check } from 'k6';
import { BASE_URL, ensureUser, getTokens, vuEmail, perEndpointThresholds } from './helpers.js';

const VUS = Number(__ENV.VUS || 50);
const DURATION = __ENV.DURATION || '1m';

export const options = {
  scenarios: {
    userinfo: {
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
  // userinfo is a cheap read; hold it to a tighter p95 than write paths.
  thresholds: perEndpointThresholds(['userinfo'], 300),
};

// Per-VU state (k6 init context is per-VU).
let registered = false;
let accessToken = null;

export default function () {
  if (!registered) {
    ensureUser();
    registered = true;
  }
  if (!accessToken) {
    accessToken = getTokens().access_token || null;
    if (!accessToken) return; // password grant failed; tracked by its own metric
  }

  const res = http.get(`${BASE_URL}/userinfo`, {
    headers: { Authorization: `Bearer ${accessToken}` },
    tags: { endpoint: 'userinfo' },
  });

  if (res.status === 401) {
    accessToken = null; // expired/revoked; re-mint next iteration
    return;
  }

  check(res, {
    'userinfo: status 200': (r) => r.status === 200,
    'userinfo: has sub': (r) => !!r.json('sub'),
    'userinfo: email matches': (r) => r.json('email') === vuEmail(),
  });
}
