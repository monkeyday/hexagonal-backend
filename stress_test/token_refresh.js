/**
 * Stress test — refresh-token rotation under concurrency.
 *
 * Each VU owns a unique user and its own refresh-token chain (shared chains
 * poison each other via reuse detection). Per iteration a VU rotates its
 * current token forward; every REUSE_EVERY-th iteration it additionally
 * replays the just-consumed token to assert reuse detection rejects it
 * (finding #6). That replay revokes the whole family, so the VU re-mints a
 * fresh chain on its next iteration.
 *
 * Requires the server to run with rate limiting disabled: RATE_LIMIT_PER_MIN=0.
 *
 * Run:  k6 run stress_test/token_refresh.js
 *       k6 run -e VUS=50 -e DURATION=2m stress_test/token_refresh.js
 */
import { rampingScenario, perEndpointThresholds } from './helpers.js';
import { newSession, doRefresh, assertReuseRejected } from './actions.js';

const VUS = Number(__ENV.VUS || 20);
const DURATION = __ENV.DURATION || '1m';
// How often a VU performs the (destructive) reuse-detection assertion.
const REUSE_EVERY = Number(__ENV.REUSE_EVERY || 5);

export const options = {
  scenarios: { refresh: rampingScenario(VUS, DURATION) },
  thresholds: perEndpointThresholds({ password: 500, refresh: 300, refresh_reuse: 300 }),
};

const session = newSession();
let iter = 0;

export default function () {
  iter++;
  const { ok, consumed } = doRefresh(session);
  if (ok && iter % REUSE_EVERY === 0) {
    assertReuseRejected(consumed);
    session.refreshToken = null; // family revoked; re-mint next iteration
  }
}
