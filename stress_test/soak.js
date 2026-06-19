/**
 * Stress test — soak: sustained moderate load for leak detection.
 *
 * Holds a constant VU count on the mixed workload for a long duration. Watch
 * for creeping latency, rising error rate, or growing memory/goroutines on the
 * internal metrics endpoint (/debug/vars via METRICS_ADDR) over the run — those
 * indicate a leak rather than a capacity limit.
 *
 * Requires the server to run with rate limiting disabled: RATE_LIMIT_PER_MIN=0.
 *
 * Run:  k6 run stress_test/soak.js
 *       k6 run -e VUS=40 -e DURATION=30m stress_test/soak.js
 */
import { perEndpointThresholds } from './helpers.js';
import { newSession, doMixedIteration, MIXED_THRESHOLDS } from './actions.js';

const VUS = Number(__ENV.VUS || 30);
const DURATION = __ENV.DURATION || '15m';

export const options = {
  scenarios: {
    soak: {
      executor: 'constant-vus',
      vus: VUS,
      duration: DURATION,
    },
  },
  thresholds: perEndpointThresholds(MIXED_THRESHOLDS),
};

const session = newSession();

export default function () {
  doMixedIteration(session);
}
