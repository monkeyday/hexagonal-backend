/**
 * Smoke test — GET /authorize
 *
 * Run:  k6 run smoke_test/authorize.js
 */
import http, { expectedStatuses } from 'k6/http';
import { check } from 'k6';
import { smokeOptions, BASE_URL } from './helpers.js';

export const options = smokeOptions;

export default function () {
  // ── Valid request — response_type=code ──────────────────────────────────────
  const valid = http.get(
    `${BASE_URL}/authorize?response_type=code&client_id=smoke-client` +
    `&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback` +
    `&scope=openid%20email&state=smoke-state&nonce=smoke-nonce`,
  );
  check(valid, {
    'valid request: status 200': (r) => r.status === 200,
  });

  // ── Unsupported response_type — expects 400 ──────────────────────────────────
  const unsupported = http.get(
    `${BASE_URL}/authorize?response_type=token&client_id=smoke-client` +
    `&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcallback&scope=openid%20email`,
    { responseCallback: expectedStatuses(400) },
  );
  check(unsupported, {
    'unsupported response_type: status 400': (r) => r.status === 400,
    'unsupported response_type: err_code':   (r) => r.json('err_code') === 10013,
  });

  // ── Missing response_type — expects 400 ─────────────────────────────────────
  const missing = http.get(`${BASE_URL}/authorize`,
    { responseCallback: expectedStatuses(400) },
  );
  check(missing, {
    'missing response_type: status 400': (r) => r.status === 400,
  });
}
