/**
 * Stress test — realistic traffic mix.
 *
 * Each iteration a VU performs one weighted action: ~60% userinfo, 20% refresh
 * rotation, 10% full login, 10% discovery (see doMixedIteration). This
 * approximates steady production traffic dominated by authenticated reads.
 *
 * Requires the server to run with rate limiting disabled: RATE_LIMIT_PER_MIN=0.
 *
 * Run:  k6 run stress_test/mixed.js
 *       k6 run -e VUS=80 -e DURATION=3m stress_test/mixed.js
 */
import { rampingScenario, perEndpointThresholds } from './helpers.js';
import { newSession, doMixedIteration, MIXED_ENDPOINTS } from './actions.js';

const VUS = Number(__ENV.VUS || 50);
const DURATION = __ENV.DURATION || '2m';

export const options = {
  scenarios: { mixed: rampingScenario(VUS, DURATION) },
  thresholds: perEndpointThresholds(MIXED_ENDPOINTS, 1000),
};

const session = newSession();

export default function () {
  doMixedIteration(session);
}
