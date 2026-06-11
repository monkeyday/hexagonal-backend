/**
 * Smoke test — GET /debug/vars
 *
 * Run:  k6 run smoke_test/debug_vars.js
 */
import http, { expectedStatuses } from 'k6/http';
import { check } from 'k6';
import { smokeOptions, BASE_URL, METRICS_URL } from './helpers.js';

export const options = smokeOptions;

const EXPECTED_COUNTERS = [
  'auth_failed_logins_total',
  'auth_tokens_issued_total',
  'auth_token_revocations_total',
];

export default function () {
  // The public listener must not expose expvar (cmdline, memstats).
  const pub = http.get(`${BASE_URL}/debug/vars`, { responseCallback: expectedStatuses(404) });
  check(pub, { 'public /debug/vars: status 404': (r) => r.status === 404 });

  const res = http.get(`${METRICS_URL}/debug/vars`);

  check(res, {
    'status 200':       (r) => r.status === 200,
    'content is JSON':  (r) => r.headers['Content-Type'].includes('application/json'),
  });

  const body = res.json() || {};
  for (const counter of EXPECTED_COUNTERS) {
    check(body, {
      [`has counter ${counter}`]: (b) => b[counter] !== undefined,
    });
  }
}
