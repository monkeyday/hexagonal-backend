// Package conformance hosts an in-process OIDC conformance suite. It boots the
// real auth module over an httptest server (file + in-memory adapters, real RSA
// keys) and asserts the provider obeys OIDC Core and the relevant RFCs.
package conformance

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"html/template"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sc/assets"
	coreuow "sc/core/uow"
	infracache "sc/infrastructure/cache"
	infrajwt "sc/infrastructure/jwt"
	filerepo "sc/infrastructure/repository/file"
	"sc/modules/auth"
	adapterout "sc/modules/auth/adapter/out"
	"sc/modules/auth/application/define"
	"sc/modules/auth/domain/entity"

	"sc/core/crypto"
	"sc/handler/web/middleware"

	"github.com/gin-gonic/gin"
)

const (
	testClientID    = "conformance-client"
	testRedirectURI = "https://app.example.com/callback"
	testKid         = "conformance-kid"
	testUserEmail   = "conformance@example.com"
	testUserPass    = "Passw0rd123!"
	testScope       = "openid email"
)

// harness is a running in-process provider plus the handles tests need to drive
// and inspect it.
type harness struct {
	srv    *httptest.Server
	client *http.Client
	cache  *infracache.MemoryCache
	issuer string
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	gin.SetMode(gin.TestMode)

	// Bind first so the issuer can be the real server URL before anything that
	// embeds it (discovery metadata, id_token iss) is constructed.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	issuer := "http://" + ln.Addr().String()

	cache := infracache.NewMemoryCache()
	t.Cleanup(cache.Close)

	engine := buildEngine(t, issuer, cache)
	srv := &httptest.Server{Listener: ln, Config: &http.Server{Handler: engine}}
	srv.Start()
	t.Cleanup(srv.Close)

	return &harness{
		srv:   srv,
		cache: cache,
		// Never follow redirects: the auth-code and error flows are asserted via
		// the Location header.
		client: &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		issuer: issuer,
	}
}

func buildEngine(t *testing.T, issuer string, cache *infracache.MemoryCache) *gin.Engine {
	t.Helper()

	jwtSvc := newJWTService(t, issuer)
	cipher, err := crypto.NewCipher(make([]byte, 32), []byte("blind-index-key"))
	if err != nil {
		t.Fatalf("cipher: %v", err)
	}

	dir := t.TempDir()
	userStore, err := filerepo.NewFileStore(dir, "users.json")
	if err != nil {
		t.Fatalf("user store: %v", err)
	}
	userRepo, err := adapterout.NewUserRepository(userStore, cipher)
	if err != nil {
		t.Fatalf("user repo: %v", err)
	}
	rtStore, err := filerepo.NewFileStore(dir, "refresh.json")
	if err != nil {
		t.Fatalf("refresh store: %v", err)
	}
	rtRepo, err := adapterout.NewFileRefreshTokenRepository(rtStore)
	if err != nil {
		t.Fatalf("refresh repo: %v", err)
	}

	client, err := entity.NewClient(entity.ClientArgs{
		ID:           testClientID,
		AuthMethod:   entity.ClientAuthNone,
		RedirectURIs: []string{testRedirectURI},
		AllowedGrants: []entity.GrantType{
			entity.GrantAuthorizationCode, entity.GrantRefreshToken, entity.GrantPassword,
		},
	})
	if err != nil {
		t.Fatalf("client: %v", err)
	}

	mod := auth.NewModule(define.Dependencies{
		Cache:            cache,
		UoW:              &coreuow.NoopUnitOfWork{},
		JWTSvc:           adapterout.NewJWTServiceAdapter(jwtSvc),
		UserRepo:         userRepo,
		RefreshTokenRepo: rtRepo,
		EmailSender:      adapterout.NewLogEmailSender(),
		ClientRegistry:   adapterout.NewConfigClientRegistry(client),
		ScopeAllowlist:   entity.SupportedScopes,
	})

	engine := gin.New()
	engine.Use(gin.Recovery())
	engine.Use(middleware.SecurityHeaders())
	engine.Use(middleware.CookieSecure(false))
	as := &assets.EmbedAssets{}
	engine.SetHTMLTemplate(template.Must(template.ParseFS(as.GetTemplates(), "*.html")))
	mod.RegisterRoutes(engine)
	return engine
}

func newJWTService(t *testing.T, issuer string) *infrajwt.JWTService {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	dir := t.TempDir()
	privPath := filepath.Join(dir, "private.pem")
	pubPath := filepath.Join(dir, "public.pem")

	privPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := os.WriteFile(privPath, privPEM, 0o600); err != nil {
		t.Fatalf("write private key: %v", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})
	if err := os.WriteFile(pubPath, pubPEM, 0o600); err != nil {
		t.Fatalf("write public key: %v", err)
	}

	svc, err := infrajwt.NewJWTService(infrajwt.Config{
		PrivateKeyPath: privPath,
		PublicKeyPath:  pubPath,
		Issuer:         issuer,
		Kid:            testKid,
	})
	if err != nil {
		t.Fatalf("jwt service: %v", err)
	}
	t.Cleanup(svc.Close)
	return svc
}

// ── HTTP helpers ────────────────────────────────────────────────────────────

func (h *harness) get(t *testing.T, path string) *http.Response {
	t.Helper()
	res, err := h.client.Get(h.srv.URL + path)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	return res
}

func (h *harness) postForm(t *testing.T, path string, form url.Values, cookies ...*http.Cookie) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, h.srv.URL+path, strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	res, err := h.client.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	return res
}

func decodeJSON(t *testing.T, res *http.Response) map[string]any {
	t.Helper()
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("decode JSON (%s): %v", string(b), err)
	}
	return m
}

func findCookie(res *http.Response, name string) *http.Cookie {
	for _, c := range res.Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// pkce returns a verifier and its S256 challenge.
func pkce(t *testing.T) (verifier, challenge string) {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("rand: %v", err)
	}
	verifier = base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(sum[:])
	return verifier, challenge
}

// csrfToken reads the CSRF token the provider stored in the authorize session,
// avoiding HTML form scraping (a delivery detail, not an OIDC concern).
func (h *harness) csrfToken(t *testing.T, sessionID string) string {
	t.Helper()
	var session struct {
		CSRFToken string `json:"csrf_token"`
	}
	key := fmtSession(sessionID)
	if ok := h.cache.Get(context.Background(), key, &session); !ok {
		t.Fatalf("authorize session %q not found in cache", sessionID)
	}
	return session.CSRFToken
}

func fmtSession(sessionID string) string {
	return strings.Replace(define.AuthorizeRequestCacheKey, "%s", sessionID, 1)
}

// signUp registers the conformance test user (idempotent enough for one run).
func (h *harness) signUp(t *testing.T) {
	t.Helper()
	res := h.postForm(t, "/sign-up", url.Values{
		"username": {"conformance"},
		"nickname": {"Conf"},
		"email":    {testUserEmail},
		"password": {testUserPass},
	})
	if res.StatusCode != http.StatusOK {
		t.Fatalf("/sign-up status = %d, body = %v", res.StatusCode, decodeJSON(t, res))
	}
	res.Body.Close()
}

// obtainAuthCode drives /authorize → /sign-in and returns the authorization
// code, its PKCE verifier, and the nonce that was sent.
func (h *harness) obtainAuthCode(t *testing.T) (code, verifier, nonce string) {
	t.Helper()
	v, challenge := pkce(t)
	nonce = "nonce-" + challenge[:8]
	state := "state-xyz"

	authzURL := "/authorize?" + url.Values{
		"response_type":         {"code"},
		"client_id":             {testClientID},
		"redirect_uri":          {testRedirectURI},
		"scope":                 {testScope},
		"state":                 {state},
		"nonce":                 {nonce},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}.Encode()

	authzRes := h.get(t, authzURL)
	authzRes.Body.Close()
	if authzRes.StatusCode != http.StatusFound {
		t.Fatalf("/authorize status = %d, want 302", authzRes.StatusCode)
	}
	sessionCookie := findCookie(authzRes, define.CookieAuthorizeRequest)
	if sessionCookie == nil {
		t.Fatal("/authorize did not set the auth_session cookie")
	}

	csrf := h.csrfToken(t, sessionCookie.Value)
	signInRes := h.postForm(t, "/sign-in", url.Values{
		"email":      {testUserEmail},
		"password":   {testUserPass},
		"csrf_token": {csrf},
	}, sessionCookie)
	signInRes.Body.Close()
	if signInRes.StatusCode != http.StatusSeeOther && signInRes.StatusCode != http.StatusFound {
		t.Fatalf("/sign-in status = %d, want a redirect", signInRes.StatusCode)
	}
	redirected, err := url.Parse(signInRes.Header.Get("Location"))
	if err != nil {
		t.Fatalf("sign-in redirect not parseable: %v", err)
	}
	if got := redirected.Query().Get("state"); got != state {
		t.Errorf("auth-code redirect state = %q, want %q", got, state)
	}
	code = redirected.Query().Get("code")
	if code == "" {
		t.Fatalf("no authorization code in redirect %q", signInRes.Header.Get("Location"))
	}
	return code, v, nonce
}

// exchangeCode POSTs an authorization_code grant to /token.
func (h *harness) exchangeCode(t *testing.T, code, verifier string) *http.Response {
	t.Helper()
	return h.postForm(t, "/token", url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {testRedirectURI},
		"client_id":     {testClientID},
		"code_verifier": {verifier},
	})
}

// authCodeTokens drives the full browser auth-code+PKCE flow and returns the
// parsed /token response plus the nonce that was sent.
func (h *harness) authCodeTokens(t *testing.T) (tokens map[string]any, nonce string) {
	t.Helper()
	code, verifier, nonce := h.obtainAuthCode(t)
	tokenRes := h.exchangeCode(t, code, verifier)
	if tokenRes.StatusCode != http.StatusOK {
		t.Fatalf("/token status = %d, body = %v", tokenRes.StatusCode, decodeJSON(t, tokenRes))
	}
	return decodeJSON(t, tokenRes), nonce
}
