/**
 * Stress test — spike: sudden surge then recovery, on the mixed workload.
 *
 * Warms at BASELINE VUs, jumps sharply to SPIKE, holds, then drops back to
 * BASELINE to observe recovery. Watches for errors and latency blow-up during
 * the surge and confirms the server settles afterward.
 *
 * Requires the server to run with rate limiting disabled: RATE_LIMIT_PER_MIN=0.
 *
 * Run:  k6 run stress_test/spike.js
 *       k6 run -e BASELINE=20 -e SPIKE=300 stress_test/spike.js
 */
import { perEndpointThresholds } from './helpers.js';
import { newSession, doMixedIteration, MIXED_ENDPOINTS } from './actions.js';

const BASELINE = Number(__ENV.BASELINE || 20);
const SPIKE = Number(__ENV.SPIKE || 200);

export const options = {
  scenarios: {
    spike: {
      executor: 'ramping-vus',
      startVUs: 0,
      stages: [
        { duration: '15s', target: BASELINE }, // warm up
        { duration: '10s', target: SPIKE },    // sudden surge
        { duration: '30s', target: SPIKE },    // hold the spike
        { duration: '10s', target: BASELINE }, // drop back
        { duration: '30s', target: BASELINE }, // observe recovery
        { duration: '5s', target: 0 },
      ],
      gracefulRampDown: '5s',
    },
  },
  // Looser p95 than steady-state: a spike is expected to degrade latency, but
  // requests must still mostly succeed.
  thresholds: { ...perEndpointThresholds(MIXED_ENDPOINTS, 3000), http_req_failed: ['rate<0.05'] },
};

const session = newSession();

export default function () {
  doMixedIteration(session);
}
