/**
 * Stress test — refresh-token rotation under concurrency.
 *
 * Each VU owns a unique user and its own refresh-token chain (shared chains
 * poison each other via reuse detection). Per iteration a VU rotates its
 * current token forward; every REUSE_EVERY-th iteration it additionally
 * replays the just-consumed token to assert reuse detection rejects it
 * (finding #6). That replay revokes the whole family, so the VU re-mints a
 * fresh chain via the password grant on its next iteration.
 *
 * Requires the server to run with rate limiting disabled: RATE_LIMIT_PER_MIN=0.
 *
 * Run:  k6 run -e RATE_LIMIT_OFF=1 stress_test/token_refresh.js
 *       k6 run -e VUS=50 -e DURATION=2m stress_test/token_refresh.js
 */
import http, { expectedStatuses } from 'k6/http';
import { check } from 'k6';
import {
  BASE_URL, CLIENT_ID, JSON_HEADERS,
  ensureUser, getTokens, rotate, perEndpointThresholds,
} from './helpers.js';

const VUS = Number(__ENV.VUS || 20);
const DURATION = __ENV.DURATION || '1m';
// How often a VU performs the (destructive) reuse-detection assertion.
const REUSE_EVERY = Number(__ENV.REUSE_EVERY || 5);

export const options = {
  scenarios: {
    refresh: {
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
  thresholds: perEndpointThresholds(['password', 'refresh', 'refresh_reuse'], 800),
};

// Per-VU state (k6 init context is per-VU).
let registered = false;
let current = null; // current valid refresh token, or null to force a re-mint
let iter = 0;

export default function () {
  if (!registered) {
    ensureUser();
    registered = true;
  }
  if (!current) {
    current = getTokens().refresh_token || null;
    if (!current) return; // password grant failed; checked via its own threshold
  }
  iter++;

  const consumed = current;
  const res = rotate(consumed);
  const ok = check(res, {
    'rotate: status 200': (r) => r.status === 200,
    'rotate: new refresh_token': (r) => !!r.json('refresh_token'),
    'rotate: token actually rotated': (r) => r.json('refresh_token') !== consumed,
  });
  if (!ok) {
    current = null; // chain is broken; re-mint next iteration
    return;
  }
  current = res.json('refresh_token');

  if (iter % REUSE_EVERY === 0) {
    assertReuseRejected(consumed);
    current = null; // family revoked by the reuse attempt; re-mint next iteration
  }
}

// Replaying an already-consumed refresh token must be rejected. The 4xx is the
// expected outcome, so we mark it via responseCallback to keep it out of
// http_req_failed, and measure its latency under the refresh_reuse tag.
function assertReuseRejected(consumed) {
  const res = http.post(
    `${BASE_URL}/token`,
    JSON.stringify({ grant_type: 'refresh_token', client_id: CLIENT_ID, refresh_token: consumed }),
    {
      headers: JSON_HEADERS,
      tags: { endpoint: 'refresh_reuse' },
      responseCallback: expectedStatuses(400, 401),
    },
  );
  check(res, { 'reuse: rejected (4xx)': (r) => r.status === 400 || r.status === 401 });
}
