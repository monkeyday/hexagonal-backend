/**
 * Smoke test — GET /.well-known/jwks.json
 *
 * Run:  k6 run smoke_test/jwks.js
 */
import http from 'k6/http';
import { check } from 'k6';
import { smokeOptions, BASE_URL } from './helpers.js';

export const options = smokeOptions;

export default function () {
  const res = http.get(`${BASE_URL}/.well-known/jwks.json`);

  check(res, {
    'status 200':          (r) => r.status === 200,
    'has keys array':      (r) => Array.isArray(r.json('keys')),
    'at least one key':    (r) => (r.json('keys') || []).length > 0,
  });

  const keys = res.json('keys') || [];
  if (keys.length > 0) {
    const key = keys[0];
    check(key, {
      'key has kty':  (k) => !!k.kty,
      'key has kid':  (k) => !!k.kid,
      'key has alg':  (k) => !!k.alg,
      'key has use':  (k) => !!k.use,
      'key has n':    (k) => !!k.n,
      'key has e':    (k) => !!k.e,
      'kty is RSA':   (k) => k.kty === 'RSA',
    });
  }
}
