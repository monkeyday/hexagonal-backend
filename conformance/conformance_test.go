package conformance

import (
	"crypto/rsa"
	"encoding/base64"
	"math/big"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

func TestOIDCConformance(t *testing.T) {
	h := newHarness(t)
	h.signUp(t)

	t.Run("discovery advertises required metadata consistent with behaviour", func(t *testing.T) {
		res := h.get(t, "/.well-known/openid-configuration")
		if res.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want 200", res.StatusCode)
		}
		doc := decodeJSON(t, res)

		if doc["issuer"] != h.issuer {
			t.Errorf("issuer = %v, want %s", doc["issuer"], h.issuer)
		}
		for k, want := range map[string]string{
			"authorization_endpoint": h.issuer + "/authorize",
			"token_endpoint":         h.issuer + "/token",
			"userinfo_endpoint":      h.issuer + "/userinfo",
		} {
			if doc[k] != want {
				t.Errorf("%s = %v, want %s", k, doc[k], want)
			}
		}
		if doc["jwks_uri"] == nil || doc["jwks_uri"] == "" {
			t.Error("jwks_uri missing")
		}
		assertContains(t, doc, "response_types_supported", "code")
		assertContains(t, doc, "code_challenge_methods_supported", "S256")
		assertContains(t, doc, "id_token_signing_alg_values_supported", "RS256")
		assertContains(t, doc, "scopes_supported", "openid")
		assertContains(t, doc, "grant_types_supported", "authorization_code")
		assertContains(t, doc, "grant_types_supported", "refresh_token")
	})

	t.Run("JWKS is a single well-formed RS256 signing key", func(t *testing.T) {
		jwk := h.firstJWK(t)
		if jwk["kty"] != "RSA" {
			t.Errorf("kty = %v, want RSA", jwk["kty"])
		}
		if jwk["use"] != "sig" {
			t.Errorf("use = %v, want sig", jwk["use"])
		}
		if jwk["alg"] != "RS256" {
			t.Errorf("alg = %v, want RS256", jwk["alg"])
		}
		if jwk["kid"] != testKid {
			t.Errorf("kid = %v, want %s", jwk["kid"], testKid)
		}
		// RFC 7518 §6.3.1: 65537 encodes minimally as "AQAB".
		if jwk["e"] != "AQAB" {
			t.Errorf("e = %v, want AQAB", jwk["e"])
		}
		if n, _ := jwk["n"].(string); n == "" {
			t.Error("modulus n missing")
		}
	})

	t.Run("authorization_code + PKCE issues a verifiable id_token", func(t *testing.T) {
		tokens, nonce := h.authCodeTokens(t)

		if tokens["token_type"] != "Bearer" {
			t.Errorf("token_type = %v, want Bearer", tokens["token_type"])
		}
		if s, _ := tokens["access_token"].(string); s == "" {
			t.Error("access_token missing")
		}
		if s, _ := tokens["refresh_token"].(string); s == "" {
			t.Error("refresh_token missing")
		}
		if n, _ := tokens["expires_in"].(float64); n <= 0 {
			t.Errorf("expires_in = %v, want > 0", tokens["expires_in"])
		}

		idToken, _ := tokens["id_token"].(string)
		if idToken == "" {
			t.Fatal("id_token missing")
		}
		claims := h.verifyIDToken(t, idToken)

		if claims["iss"] != h.issuer {
			t.Errorf("id_token iss = %v, want %s", claims["iss"], h.issuer)
		}
		if claims["aud"] != testClientID {
			t.Errorf("id_token aud = %v, want %s", claims["aud"], testClientID)
		}
		if claims["nonce"] != nonce {
			t.Errorf("id_token nonce = %v, want %s", claims["nonce"], nonce)
		}
		if s, _ := claims["sub"].(string); s == "" {
			t.Error("id_token sub missing")
		}
		if exp, _ := claims["exp"].(float64); int64(exp) <= time.Now().Unix() {
			t.Errorf("id_token exp = %v, want in the future", claims["exp"])
		}
	})

	t.Run("userinfo requires a bearer token and echoes the id_token subject", func(t *testing.T) {
		tokens, _ := h.authCodeTokens(t)
		accessToken, _ := tokens["access_token"].(string)
		idSub := h.verifyIDToken(t, tokens["id_token"].(string))["sub"]

		// No token → 401 with a Bearer challenge.
		noTok := h.get(t, "/userinfo")
		noTok.Body.Close()
		if noTok.StatusCode != http.StatusUnauthorized {
			t.Errorf("userinfo without token status = %d, want 401", noTok.StatusCode)
		}
		if ch := noTok.Header.Get("WWW-Authenticate"); ch == "" {
			t.Error("401 userinfo must carry a WWW-Authenticate challenge")
		}

		// With token → 200 and sub matches the id_token.
		info := h.getAuth(t, "/userinfo", accessToken)
		if info.StatusCode != http.StatusOK {
			t.Fatalf("userinfo status = %d, want 200", info.StatusCode)
		}
		if got := decodeJSON(t, info)["sub"]; got != idSub {
			t.Errorf("userinfo sub = %v, want %v (id_token sub)", got, idSub)
		}
	})

	t.Run("authorization code is single-use", func(t *testing.T) {
		code, verifier, _ := h.obtainAuthCode(t)

		first := h.exchangeCode(t, code, verifier)
		first.Body.Close()
		if first.StatusCode != http.StatusOK {
			t.Fatalf("first exchange status = %d, want 200", first.StatusCode)
		}

		replay := h.exchangeCode(t, code, verifier)
		if replay.StatusCode == http.StatusOK {
			t.Fatal("replaying an authorization code must be rejected")
		}
		if got := decodeJSON(t, replay)["error"]; got != "invalid_grant" {
			t.Errorf("replay error = %v, want invalid_grant", got)
		}
	})

	t.Run("token endpoint returns RFC 6749 error bodies", func(t *testing.T) {
		// Unsupported grant_type.
		bad := h.postForm(t, "/token", url.Values{"grant_type": {"client_credentials"}})
		if bad.StatusCode != http.StatusBadRequest {
			t.Fatalf("unsupported grant status = %d, want 400", bad.StatusCode)
		}
		if got := decodeJSON(t, bad)["error"]; got != "unsupported_grant_type" {
			t.Errorf("error = %v, want unsupported_grant_type", got)
		}

		// Invalid authorization code.
		invalid := h.postForm(t, "/token", url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {"nope"},
			"redirect_uri":  {testRedirectURI},
			"client_id":     {testClientID},
			"code_verifier": {"whatever-verifier-value-padding-padding-1234"},
		})
		if got := decodeJSON(t, invalid)["error"]; got != "invalid_grant" {
			t.Errorf("invalid code error = %v, want invalid_grant", got)
		}
	})

	t.Run("authorize errors redirect per RFC 6749 §4.1.2.1", func(t *testing.T) {
		// Unsupported response_type with a registered client → redirect with error.
		res := h.get(t, "/authorize?"+url.Values{
			"response_type": {"token"},
			"client_id":     {testClientID},
			"redirect_uri":  {testRedirectURI},
			"scope":         {testScope},
			"state":         {"abc"},
		}.Encode())
		res.Body.Close()
		if res.StatusCode != http.StatusFound {
			t.Fatalf("status = %d, want 302", res.StatusCode)
		}
		loc, _ := url.Parse(res.Header.Get("Location"))
		if loc.Query().Get("error") != "unsupported_response_type" {
			t.Errorf("error = %q, want unsupported_response_type", loc.Query().Get("error"))
		}
		if loc.Query().Get("state") != "abc" {
			t.Errorf("state = %q, want abc", loc.Query().Get("state"))
		}

		// Public client without PKCE → redirect with invalid_request.
		noPKCE := h.get(t, "/authorize?"+url.Values{
			"response_type": {"code"},
			"client_id":     {testClientID},
			"redirect_uri":  {testRedirectURI},
			"scope":         {testScope},
		}.Encode())
		noPKCE.Body.Close()
		loc2, _ := url.Parse(noPKCE.Header.Get("Location"))
		if loc2.Query().Get("error") != "invalid_request" {
			t.Errorf("missing-PKCE error = %q, want invalid_request", loc2.Query().Get("error"))
		}
	})
}

// ── assertion + crypto helpers ───────────────────────────────────────────────

func assertContains(t *testing.T, doc map[string]any, key, want string) {
	t.Helper()
	raw, ok := doc[key].([]any)
	if !ok {
		t.Errorf("%s missing or not an array", key)
		return
	}
	for _, v := range raw {
		if v == want {
			return
		}
	}
	t.Errorf("%s = %v, want it to include %q", key, raw, want)
}

func (h *harness) firstJWK(t *testing.T) map[string]any {
	t.Helper()
	res := h.get(t, "/.well-known/jwks.json")
	if res.StatusCode != http.StatusOK {
		t.Fatalf("jwks status = %d, want 200", res.StatusCode)
	}
	doc := decodeJSON(t, res)
	keys, ok := doc["keys"].([]any)
	if !ok || len(keys) != 1 {
		t.Fatalf("keys = %v, want exactly one", doc["keys"])
	}
	jwk, _ := keys[0].(map[string]any)
	return jwk
}

func (h *harness) getAuth(t *testing.T, path, token string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, h.srv.URL+path, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	res, err := h.client.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	return res
}

// verifyIDToken validates the id_token's RS256 signature against the published
// JWKS and returns its claims. A token that fails verification fails the test.
func (h *harness) verifyIDToken(t *testing.T, idToken string) jwt.MapClaims {
	t.Helper()
	pub := h.jwksPublicKey(t)
	claims := jwt.MapClaims{}
	_, err := jwt.ParseWithClaims(idToken, claims, func(tok *jwt.Token) (any, error) {
		if _, ok := tok.Method.(*jwt.SigningMethodRSA); !ok {
			t.Fatalf("id_token alg = %v, want RSA", tok.Header["alg"])
		}
		if tok.Header["kid"] != testKid {
			t.Fatalf("id_token kid = %v, want %s", tok.Header["kid"], testKid)
		}
		return pub, nil
	})
	if err != nil {
		t.Fatalf("id_token failed verification against JWKS: %v", err)
	}
	return claims
}

func (h *harness) jwksPublicKey(t *testing.T) *rsa.PublicKey {
	t.Helper()
	jwk := h.firstJWK(t)
	nBytes, err := base64.RawURLEncoding.DecodeString(jwk["n"].(string))
	if err != nil {
		t.Fatalf("decode n: %v", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(jwk["e"].(string))
	if err != nil {
		t.Fatalf("decode e: %v", err)
	}
	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: int(new(big.Int).SetBytes(eBytes).Int64()),
	}
}
