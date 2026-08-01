/**
 * Smoke test — POST /api/v3/update-profile
 *
 * Run:  k6 run smoke_test/update_profile.js
 */
import http, { expectedStatuses } from 'k6/http';
import { check } from 'k6';
import { smokeOptions, BASE_URL, EMAIL, PASSWORD, ensureUser, getTokens } from './helpers.js';

export const options = smokeOptions;

const FORM_HEADERS = { 'Content-Type': 'application/x-www-form-urlencoded' };
const JSON_HEADERS = { 'Content-Type': 'application/json' };

// Second account, used only to claim an email that is already taken.
const CONFLICT_EMAIL = 'smoke-conflict@example.com';

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

  // ── Email already taken — expects 409 ───────────────────────────────────────
  // Deliberately asserted from the throwaway account onto the smoke user's
  // address, not the other way round: if this ever stopped conflicting, the
  // write lands on the throwaway account instead of renaming the shared smoke
  // user out from under every later scenario file.
  const signUpOther = http.post(
    `${BASE_URL}/sign-up`,
    { username: 'smokeconflict', nickname: 'Conflict', email: CONFLICT_EMAIL, password: PASSWORD },
    { headers: FORM_HEADERS, responseCallback: expectedStatuses(200, 409) },
  );
  check(signUpOther, {
    'conflict account registered: status 200 or 409': (r) => r.status === 200 || r.status === 409,
  });

  const otherTokens = http.post(
    `${BASE_URL}/token`,
    JSON.stringify({ grant_type: 'password', email: CONFLICT_EMAIL, password: PASSWORD }),
    { headers: JSON_HEADERS },
  );
  check(otherTokens, {
    'conflict account tokens: status 200': (r) => r.status === 200,
  });

  const duplicate = http.post(
    `${BASE_URL}/api/v3/update-profile`,
    { email: EMAIL },
    {
      headers: {
        ...FORM_HEADERS,
        Authorization: `Bearer ${otherTokens.json('access_token') || ''}`,
      },
      responseCallback: expectedStatuses(409),
    },
  );
  check(duplicate, {
    'duplicate email: status 409':     (r) => r.status === 409,
    'duplicate email: err_code 10009': (r) => r.json('err_code') === 10009,
  });
}
