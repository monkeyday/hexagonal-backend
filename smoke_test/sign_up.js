/**
 * Smoke test — GET /sign-up  +  POST /sign-up
 *
 * Run:  k6 run smoke_test/sign_up.js
 */
import http from 'k6/http';
import { check } from 'k6';
import { smokeOptions, BASE_URL } from './helpers.js';

export const options = smokeOptions;

// Use a unique email per run so the test is idempotent on a fresh server.
const email = `smoke_signup_${Date.now()}@example.com`;

export default function () {
  // ── GET /sign-up — HTML sign-up page ─────────────────────────────────────────
  const page = http.get(`${BASE_URL}/sign-up`);
  check(page, {
    'GET /sign-up status 200':   (r) => r.status === 200,
    'GET /sign-up returns HTML': (r) => (r.headers['Content-Type'] || '').includes('text/html'),
  });

  // ── POST /sign-up — register a new user ──────────────────────────────────────
  const res = http.post(
    `${BASE_URL}/sign-up`,
    {
      username: 'smokeuser',
      nickname: 'Smoke User',
      email:    email,
      password: 'SmokeTest1!',
    },
    { headers: { 'Content-Type': 'application/x-www-form-urlencoded' } },
  );

  check(res, {
    'status 200':          (r) => r.status === 200,
    'body has email':      (r) => r.json('email') === email,
    'body has username':   (r) => r.json('username') === 'smokeuser',
    'body has nickname':   (r) => r.json('nickname') === 'Smoke User',
  });
}
