/**
 * Stress test — high-frequency authenticated read (GET /userinfo).
 *
 * Each VU mints an access token once, then hammers /userinfo, re-minting on a
 * 401 so the scenario stays valid under soak.
 *
 * Requires the server to run with rate limiting disabled: RATE_LIMIT_PER_MIN=0.
 *
 * Run:  k6 run stress_test/userinfo.js
 *       k6 run -e VUS=100 -e DURATION=2m stress_test/userinfo.js
 */
import { rampingScenario, perEndpointThresholds } from './helpers.js';
import { newSession, doUserinfo } from './actions.js';

const VUS = Number(__ENV.VUS || 50);
const DURATION = __ENV.DURATION || '1m';

export const options = {
  scenarios: { userinfo: rampingScenario(VUS, DURATION) },
  // userinfo is a cheap read; hold it to a tighter p95 than write paths.
  thresholds: perEndpointThresholds(['userinfo'], 300),
};

const session = newSession();

export default function () {
  doUserinfo(session);
}
