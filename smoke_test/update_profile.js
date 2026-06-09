/**
 * Smoke test — POST /api/v3/update-profile
 *
 * Run:  k6 run smoke_test/update_profile.js
 */
import http, { expectedStatuses } from 'k6/http';
import { check } from 'k6';
import { smokeOptions, BASE_URL, ensureUser, getTokens } from './helpers.js';

export const options = smokeOptions;

const FORM_HEADERS = { 'Content-Type': 'application/x-www-form-urlencoded' };

export function setup() {
  ensureUser();
  return getTokens();
}

export default function (tokens) {
  const authHeaders = { ...FORM_HEADERS, Authorization: `Bearer ${tokens.access_token}` };

  // ── Update nickname ──────────────────────────────────────────────────────────
  const updateNick = http.post(
    `${BASE_URL}/api/v3/update-profile`,
    { nickname: 'UpdatedSmoke' },
    { headers: authHeaders },
  );
  check(updateNick, {
    'update nickname: status 200':       (r) => r.status === 200,
    'update nickname: nickname updated': (r) => r.json('nickname') === 'UpdatedSmoke',
    'update nickname: has user_id':      (r) => !!r.json('user_id'),
    'update nickname: has email':        (r) => !!r.json('email'),
  });

  // Restore nickname
  http.post(
    `${BASE_URL}/api/v3/update-profile`,
    { nickname: 'Smoke' },
    { headers: authHeaders },
  );

  // ── Wrong access token — expects 401 ────────────────────────────────────────
  const badToken = http.post(
    `${BASE_URL}/api/v3/update-profile`,
    { nickname: 'X' },
    {
      headers: { ...FORM_HEADERS, Authorization: 'Bearer wrong-token' },
      responseCallback: expectedStatuses(401),
    },
  );
  check(badToken, {
    'wrong token: status 401': (r) => r.status === 401,
  });
}
