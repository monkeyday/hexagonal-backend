/**
 * Smoke test — GET /.well-known/openid-configuration
 *
 * Run:  k6 run smoke_test/discovery.js
 */
import http from 'k6/http';
import { check } from 'k6';
import { smokeOptions, BASE_URL } from './helpers.js';

export const options = smokeOptions;

const REQUIRED_FIELDS = [
  'issuer',
  'authorization_endpoint',
  'token_endpoint',
  'userinfo_endpoint',
  'jwks_uri',
  'revocation_endpoint',
  'end_session_endpoint',
  'introspection_endpoint',
  'response_types_supported',
  'subject_types_supported',
  'id_token_signing_alg_values_supported',
  'scopes_supported',
  'grant_types_supported',
];

export default function () {
  const res = http.get(`${BASE_URL}/.well-known/openid-configuration`);

  check(res, { 'status 200': (r) => r.status === 200 });

  const doc = res.json() || {};
  for (const field of REQUIRED_FIELDS) {
    check(doc, {
      [`has ${field}`]: (d) => d[field] !== undefined && d[field] !== null,
    });
  }

  check(doc, {
    'response_types_supported includes code':   (d) => (d.response_types_supported || []).includes('code'),
    'grant_types_supported includes password':  (d) => (d.grant_types_supported || []).includes('password'),
    'scopes_supported includes openid':         (d) => (d.scopes_supported || []).includes('openid'),
    'id_token_signing_alg includes RS256':      (d) => (d.id_token_signing_alg_values_supported || []).includes('RS256'),
  });
}
