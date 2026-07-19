/**
 * Stress test — full browser login path under concurrency.
 *
 *   GET  /authorize   establish OIDC session, scrape csrf_token   (tag: authorize)
 *   POST /sign-in     authenticate, receive 303 with ?code=...    (tag: sign_in)
 *   POST /token       exchange code + PKCE verifier for tokens     (tag: token_code)
 *
 * Each VU owns a unique user. Requires rate limiting disabled
 * (RATE_LIMIT_PER_MIN=0); only valid credentials are used, so per-account
 * lockout is not exercised.
 *
 * Run:  k6 run stress_test/auth_code_flow.js
 *       k6 run -e VUS=30 -e DURATION=2m stress_test/auth_code_flow.js
 */
import { rampingScenario, perEndpointThresholds } from './helpers.js';
import { newSession, doLogin } from './actions.js';

const VUS = Number(__ENV.VUS || 20);
const DURATION = __ENV.DURATION || '1m';

export const options = {
  scenarios: { auth_code: rampingScenario(VUS, DURATION) },
  thresholds: perEndpointThresholds({ authorize: 300, sign_in: 500, token_code: 300 }),
};

const session = newSession();

export default function () {
  doLogin(session);
}
