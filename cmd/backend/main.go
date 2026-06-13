package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"sc/core/random"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	ListenAddr    = ":3000"
	ListenHost    = "localhost:3000"
	AuthServerURL = "http://localhost:9876"

	AuthorizeEndpoint      = AuthServerURL + "/authorize"
	TokenEndpoint          = AuthServerURL + "/token"
	UserinfoEndpoint       = AuthServerURL + "/userinfo"
	RevokeEndpoint         = AuthServerURL + "/oidc/revoke"
	IntrospectEndpoint     = AuthServerURL + "/oidc/introspect"
	LogoutEndpoint         = AuthServerURL + "/oidc/logout"
	UpdateProfileEndpoint  = AuthServerURL + "/api/v3/update-profile"
	ForgotPasswordEndpoint = AuthServerURL + "/forgot-password"
	ResetPasswordEndpoint  = AuthServerURL + "/reset-password"
	ClientID               = "my_client"
	RedirectURI            = "http://" + ListenHost + "/callback"
	Scope                  = "openid profile email"
	sessionCookieName      = "session_id"
	csrfTokenField         = "csrf_token"
	sessionMaxAge          = 86400
	refreshThreshold       = 1 * time.Minute
)

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	IDToken      string `json:"id_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
}

type sessionData struct {
	tokenResponse
	ExpiresAt    time.Time
	LastResponse string
	CSRFToken    string
}

type pendingAuth struct {
	State    string
	Nonce    string
	Verifier string
}

var (
	sessions   = map[string]sessionData{}
	sessionsMu sync.RWMutex
	// pending holds state/nonce for one in-flight login. A second login before
	// the first callback completes overwrites it. Acceptable for a single-user
	// test harness; a real backend must scope this to a per-browser session.
	pending pendingAuth
)

func main() {
	http.HandleFunc("/", handleHome)
	http.HandleFunc("/login", handleLogin)
	http.HandleFunc("/callback", handleCallback)
	http.HandleFunc("/refresh", handleRefresh)
	http.HandleFunc("/revoke", handleRevoke)
	http.HandleFunc("/introspect", handleIntrospect)
	http.HandleFunc("/userinfo", handleUserInfo)
	http.HandleFunc("/logout", handleLogout)
	http.HandleFunc("/update-profile", handleUpdateProfile)
	http.HandleFunc("/forgot-password", handleForgotPassword)
	http.HandleFunc("/reset-password", handleResetPassword)

	fmt.Printf("--- OIDC Test Tool ---\n")
	fmt.Printf("Visit http://%s/ to start\n", ListenHost)
	fmt.Printf("---------------------\n")

	if err := http.ListenAndServe(ListenAddr, nil); err != nil {
		fmt.Printf("Error starting server: %v\n", err)
	}
}

func getSession(r *http.Request) (tokenResponse, bool) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return tokenResponse{}, false
	}
	sessionsMu.RLock()
	defer sessionsMu.RUnlock()
	data, ok := sessions[cookie.Value]
	return data.tokenResponse, ok
}

func getSessionWithRefresh(w http.ResponseWriter, r *http.Request) (tokenResponse, bool) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return tokenResponse{}, false
	}

	sessionsMu.RLock()
	data, ok := sessions[cookie.Value]
	sessionsMu.RUnlock()
	if !ok {
		return tokenResponse{}, false
	}

	if time.Until(data.ExpiresAt) > refreshThreshold {
		return data.tokenResponse, true
	}

	if data.RefreshToken == "" {
		return tokenResponse{}, false
	}

	newTok, err := postToken(url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {ClientID},
		"refresh_token": {data.RefreshToken},
	})
	if err != nil {
		fmt.Printf("[!] Auto-refresh error: %v\n", err)
		return tokenResponse{}, false
	}

	setSession(w, cookie.Value, *newTok)
	fmt.Printf("[+] Auto-refreshed — new access token: %s…\n", newTok.AccessToken[:min(10, len(newTok.AccessToken))])
	return *newTok, true
}

func setSession(w http.ResponseWriter, id string, tok tokenResponse) {
	data := sessionData{
		tokenResponse: tok,
		ExpiresAt:     time.Now().Add(time.Duration(tok.ExpiresIn) * time.Second),
	}
	sessionsMu.Lock()
	if current, ok := sessions[id]; ok {
		data.LastResponse = current.LastResponse
		data.CSRFToken = current.CSRFToken
	}
	sessions[id] = data
	sessionsMu.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    id,
		MaxAge:   sessionMaxAge,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

func sessionID(r *http.Request) (string, bool) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return "", false
	}
	return cookie.Value, true
}

func getLastResponse(r *http.Request) string {
	id, ok := sessionID(r)
	if !ok {
		return ""
	}
	sessionsMu.RLock()
	defer sessionsMu.RUnlock()
	return sessions[id].LastResponse
}

func setLastResponse(id, response string) {
	sessionsMu.Lock()
	defer sessionsMu.Unlock()
	data, ok := sessions[id]
	if !ok {
		return
	}
	data.LastResponse = response
	sessions[id] = data
}

func setCurrentLastResponse(r *http.Request, response string) {
	if id, ok := sessionID(r); ok {
		setLastResponse(id, response)
	}
}

func requireSessionToken(w http.ResponseWriter, r *http.Request) (tokenResponse, bool) {
	tok, ok := getSessionWithRefresh(w, r)
	if !ok || tok.AccessToken == "" {
		http.Redirect(w, r, "/", http.StatusFound)
		return tokenResponse{}, false
	}
	return tok, true
}

func requireLogoutToken(w http.ResponseWriter, r *http.Request) (tokenResponse, bool) {
	tok, ok := getSession(r)
	if !ok || (tok.AccessToken == "" && tok.RefreshToken == "") {
		http.Redirect(w, r, "/", http.StatusFound)
		return tokenResponse{}, false
	}
	return tok, true
}

func requireRefreshToken(w http.ResponseWriter, r *http.Request) (tokenResponse, string, bool) {
	id, ok := sessionID(r)
	if !ok {
		http.Redirect(w, r, "/", http.StatusFound)
		return tokenResponse{}, "", false
	}
	tok, ok := getSession(r)
	if !ok || tok.RefreshToken == "" {
		http.Redirect(w, r, "/", http.StatusFound)
		return tokenResponse{}, "", false
	}
	return tok, id, true
}

func setCSRFToken(id, token string) {
	sessionsMu.Lock()
	defer sessionsMu.Unlock()
	data, ok := sessions[id]
	if !ok {
		return
	}
	data.CSRFToken = token
	sessions[id] = data
}

func csrfToken(r *http.Request) string {
	id, ok := sessionID(r)
	if !ok {
		return ""
	}
	sessionsMu.RLock()
	defer sessionsMu.RUnlock()
	return sessions[id].CSRFToken
}

// requirePOSTWithCSRF guards state-changing actions: cross-site requests can
// neither POST our forms with the per-session token nor read it, so a bare
// <img>/link navigation cannot trigger logout/revoke/refresh.
func requirePOSTWithCSRF(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return false
	}
	token := csrfToken(r)
	if token == "" || subtle.ConstantTimeCompare([]byte(r.FormValue(csrfTokenField)), []byte(token)) != 1 {
		http.Error(w, "invalid csrf token", http.StatusForbidden)
		return false
	}
	return true
}

func clearSession(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(sessionCookieName)
	if err == nil {
		sessionsMu.Lock()
		delete(sessions, cookie.Value)
		sessionsMu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		MaxAge:   -1,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

func handleHome(w http.ResponseWriter, r *http.Request) {
	tok, hasToken := getSessionWithRefresh(w, r)
	buttons := `<a href="/login" class="btn">Login with IdP</a>  <a href="/forgot-password" class="btn btn-secondary">Forgot Password</a>`
	if hasToken {
		csrf := html.EscapeString(csrfToken(r))
		buttons = actionForm("/refresh", "Refresh Token", "btn-secondary", csrf) + `
			<a href="/userinfo"       class="btn btn-secondary">UserInfo</a>
			<a href="/update-profile" class="btn btn-secondary">Update Profile</a>
			<a href="/introspect"     class="btn btn-info">Introspect Token</a>
		` + actionForm("/revoke", "Revoke Token", "btn-warning", csrf) +
			actionForm("/logout", "Logout", "btn-danger", csrf)
	}

	responseSection := ""
	if lastResponse := getLastResponse(r); lastResponse != "" {
		responseSection = fmt.Sprintf(`<div class="response"><pre>%s</pre></div>`, html.EscapeString(lastResponse))
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head>
	<title>OIDC Test Tool</title>
	<style>
		body { font-family: sans-serif; display: flex; justify-content: center; align-items: flex-start; min-height: 100vh; margin: 0; padding: 2rem; background-color: #f4f7f6; box-sizing: border-box; }
		.card { width: 100%%; max-width: 800px; margin: auto; text-align: center; padding: 2rem; background: white; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
		.btn { padding: 10px 20px; font-size: 16px; cursor: pointer; color: white; border: none; border-radius: 4px; text-decoration: none; display: inline-block; margin: 4px; }
		.btn           { background-color: #007bff; }
		.btn-secondary { background-color: #6c757d; }
		.btn-warning   { background-color: #ffc107; color: #212529; }
		.btn-info      { background-color: #17a2b8; }
		.btn-danger    { background-color: #dc3545; }
		.btn:hover     { opacity: 0.85; }
		form.inline    { display: inline-block; margin: 0; }
		.response      { margin-top: 1.5rem; text-align: left; background: #f8f9fa; border: 1px solid #dee2e6; border-radius: 4px; padding: 1rem; overflow-x: auto; }
		.response pre  { margin: 0; font-size: 13px; white-space: pre-wrap; word-break: break-all; }
	</style>
</head>
<body>
	<div class="card">
		<h1>OIDC Test Tool</h1>
		<p>%s</p>
		%s
		%s
	</div>
</body>
</html>`, statusText(tok, hasToken), buttons, responseSection)
}

// actionForm renders a state-changing action as a POST form carrying the
// per-session CSRF token; these must never be plain GET links.
func actionForm(action, label, btnClass, csrf string) string {
	return fmt.Sprintf(`<form method="POST" action="%s" class="inline"><input type="hidden" name="%s" value="%s"><button type="submit" class="btn %s">%s</button></form>`,
		action, csrfTokenField, csrf, btnClass, label)
}

func statusText(tok tokenResponse, hasToken bool) string {
	if hasToken {
		return fmt.Sprintf("Logged in &mdash; access token: <code>%s…</code>", tok.AccessToken[:min(10, len(tok.AccessToken))])
	}
	return "Click the button below to authenticate via OIDC."
}

func handleLogin(w http.ResponseWriter, r *http.Request) {
	if tok, ok := getSessionWithRefresh(w, r); ok && tok.AccessToken != "" {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	state, err := generateRandom(32)
	if err != nil {
		http.Error(w, "failed to generate state", http.StatusInternalServerError)
		return
	}
	nonce, err := generateRandom(32)
	if err != nil {
		http.Error(w, "failed to generate nonce", http.StatusInternalServerError)
		return
	}
	verifier, err := generateRandom(32)
	if err != nil {
		http.Error(w, "failed to generate code verifier", http.StatusInternalServerError)
		return
	}
	pending = pendingAuth{State: state, Nonce: nonce, Verifier: verifier}

	setCurrentLastResponse(r, "")
	params := url.Values{}
	params.Add("client_id", ClientID)
	params.Add("redirect_uri", RedirectURI)
	params.Add("response_type", "code")
	params.Add("scope", Scope)
	params.Add("state", state)
	params.Add("nonce", nonce)
	params.Add("code_challenge", s256Challenge(verifier))
	params.Add("code_challenge_method", "S256")

	authURL := fmt.Sprintf("%s?%s", AuthorizeEndpoint, params.Encode())
	fmt.Printf("[+] Redirecting to: %s\n", authURL)
	http.Redirect(w, r, authURL, http.StatusFound)
}

func handleCallback(w http.ResponseWriter, r *http.Request) {
	code := r.URL.Query().Get("code")
	if code == "" {
		http.Error(w, "no code in request", http.StatusBadRequest)
		return
	}

	state := r.URL.Query().Get("state")
	if pending.State == "" || state != pending.State {
		fmt.Printf("[!] State mismatch: want %q, got %q\n", pending.State, state)
		http.Error(w, "state mismatch", http.StatusBadRequest)
		return
	}
	fmt.Printf("[+] Received code: %s\n", code)

	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("client_id", ClientID)
	data.Set("redirect_uri", RedirectURI)
	data.Set("code_verifier", pending.Verifier)
	data.Set("expire_secs", strconv.Itoa(120))

	tok, err := postToken(data)
	if err != nil {
		fmt.Printf("[!] Token exchange error: %v\n", err)
		http.Error(w, "token exchange failed", http.StatusInternalServerError)
		return
	}

	nonce, err := extractNonce(tok.IDToken)
	if err != nil || nonce != pending.Nonce {
		fmt.Printf("[!] Nonce mismatch: want %q, got %q\n", pending.Nonce, nonce)
		http.Error(w, "nonce mismatch", http.StatusBadRequest)
		return
	}

	pending = pendingAuth{}

	sessionID, err := generateRandom(32)
	if err != nil {
		http.Error(w, "failed to generate session", http.StatusInternalServerError)
		return
	}
	csrf, err := generateRandom(32)
	if err != nil {
		http.Error(w, "failed to generate csrf token", http.StatusInternalServerError)
		return
	}
	setSession(w, sessionID, *tok)
	setCSRFToken(sessionID, csrf)
	setLastResponse(sessionID, prettyJSON(tok))
	fmt.Printf("[+] Access token: %s…\n", tok.AccessToken[:min(10, len(tok.AccessToken))])
	http.Redirect(w, r, "/", http.StatusFound)
}

func handleRefresh(w http.ResponseWriter, r *http.Request) {
	if !requirePOSTWithCSRF(w, r) {
		return
	}
	tok, sessionID, ok := requireRefreshToken(w, r)
	if !ok {
		return
	}

	data := url.Values{}
	data.Set("grant_type", "refresh_token")
	data.Set("client_id", ClientID)
	data.Set("refresh_token", tok.RefreshToken)

	newTok, err := postToken(data)
	if err != nil {
		fmt.Printf("[!] Refresh error: %v\n", err)
		http.Error(w, "refresh failed", http.StatusInternalServerError)
		return
	}

	setSession(w, sessionID, *newTok)
	setLastResponse(sessionID, prettyJSON(newTok))
	fmt.Printf("[+] Refreshed — new access token: %s…\n", newTok.AccessToken[:min(10, len(newTok.AccessToken))])
	http.Redirect(w, r, "/", http.StatusFound)
}

func handleRevoke(w http.ResponseWriter, r *http.Request) {
	if !requirePOSTWithCSRF(w, r) {
		return
	}
	tok, ok := requireSessionToken(w, r)
	if !ok {
		return
	}

	data := url.Values{}
	data.Set("token", tok.AccessToken)
	data.Set("token_type_hint", "access_token")

	body, status, err := postWithBearer(RevokeEndpoint, tok.AccessToken, data)
	if err != nil {
		fmt.Printf("[!] Revoke error: %v\n", err)
		http.Error(w, "revoke failed", http.StatusInternalServerError)
		return
	}
	fmt.Printf("[+] Revoke response (%d): %s\n", status, body)

	setCurrentLastResponse(r, fmt.Sprintf("HTTP %d\n%s", status, body))
	clearSession(w, r)
	http.Redirect(w, r, "/", http.StatusFound)
}

func handleIntrospect(w http.ResponseWriter, r *http.Request) {
	tok, ok := requireSessionToken(w, r)
	if !ok {
		return
	}

	data := url.Values{}
	data.Set("token", tok.AccessToken)
	data.Set("token_type_hint", "access_token")

	body, status, err := postWithBearer(IntrospectEndpoint, tok.AccessToken, data)
	if err != nil {
		fmt.Printf("[!] Introspect error: %v\n", err)
		http.Error(w, "introspect failed", http.StatusInternalServerError)
		return
	}
	fmt.Printf("[+] Introspect response (%d): %s\n", status, body)

	setCurrentLastResponse(r, string(body))
	http.Redirect(w, r, "/", http.StatusFound)
}

func handleUserInfo(w http.ResponseWriter, r *http.Request) {
	tok, ok := requireSessionToken(w, r)
	if !ok {
		return
	}

	body, err := fetchUserInfo(tok.AccessToken)
	if err != nil {
		fmt.Printf("[!] UserInfo error: %v\n", err)
		http.Error(w, "userinfo failed", http.StatusInternalServerError)
		return
	}
	fmt.Printf("[+] UserInfo response: %s\n", body)

	setCurrentLastResponse(r, body)
	http.Redirect(w, r, "/", http.StatusFound)
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	if !requirePOSTWithCSRF(w, r) {
		return
	}
	tok, ok := requireLogoutToken(w, r)
	if !ok {
		return
	}

	// The IdP only revokes for bearer-authenticated logout; the refresh
	// cookie is no longer sent because it no longer proves the actor.
	req, err := http.NewRequest(http.MethodPost, LogoutEndpoint, nil)
	if err != nil {
		http.Error(w, "logout failed", http.StatusInternalServerError)
		return
	}
	if tok.AccessToken != "" {
		req.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Printf("[!] Logout error: %v\n", err)
		http.Error(w, "logout failed", http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()
	fmt.Printf("[+] Logout response: %d\n", resp.StatusCode)

	setCurrentLastResponse(r, fmt.Sprintf("HTTP %d — logged out", resp.StatusCode))
	clearSession(w, r)
	http.Redirect(w, r, "/", http.StatusFound)
}

func handleUpdateProfile(w http.ResponseWriter, r *http.Request) {
	tok, ok := requireSessionToken(w, r)
	if !ok {
		return
	}

	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid form", http.StatusBadRequest)
			return
		}
		data := url.Values{}
		if v := r.FormValue("username"); v != "" {
			data.Set("username", v)
		}
		if v := r.FormValue("nickname"); v != "" {
			data.Set("nickname", v)
		}
		if v := r.FormValue("email"); v != "" {
			data.Set("email", v)
		}
		body, status, err := postWithBearer(UpdateProfileEndpoint, tok.AccessToken, data)
		if err != nil {
			fmt.Printf("[!] Update profile error: %v\n", err)
			http.Error(w, "update profile failed", http.StatusInternalServerError)
			return
		}
		fmt.Printf("[+] Update profile response (%d): %s\n", status, body)
		setCurrentLastResponse(r, string(body))
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, formPage("Update Profile", `
		<form method="POST" action="/update-profile">
			<label>Username</label>
			<input type="text" name="username" placeholder="Leave blank to keep current">
			<label>Nickname</label>
			<input type="text" name="nickname" placeholder="Leave blank to keep current">
			<label>Email</label>
			<input type="email" name="email" placeholder="Leave blank to keep current">
			<p class="hint">Only filled fields are updated.</p>
			<div class="actions">
				<button type="submit" class="btn btn-primary">Save</button>
				<a href="/" class="btn btn-secondary">Cancel</a>
			</div>
		</form>`))
}

func handleForgotPassword(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid form", http.StatusBadRequest)
			return
		}
		data := url.Values{}
		data.Set("email", r.FormValue("email"))
		body, status, err := postForm(ForgotPasswordEndpoint, data)
		if err != nil {
			fmt.Printf("[!] Forgot password error: %v\n", err)
			http.Error(w, "request failed", http.StatusInternalServerError)
			return
		}
		fmt.Printf("[+] Forgot password response (%d): %s\n", status, body)
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, formPage("Forgot Password", `
		<form method="POST" action="/forgot-password">
			<label>Email</label>
			<input type="email" name="email" placeholder="your@email.com" required>
			<div class="actions">
				<button type="submit" class="btn btn-primary">Send Reset Link</button>
				<a href="/" class="btn btn-secondary">Cancel</a>
			</div>
		</form>`))
}

func handleResetPassword(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "invalid form", http.StatusBadRequest)
			return
		}
		data := url.Values{}
		data.Set("token", r.FormValue("token"))
		data.Set("password", r.FormValue("password"))
		body, status, err := postForm(ResetPasswordEndpoint, data)
		if err != nil {
			fmt.Printf("[!] Reset password error: %v\n", err)
			http.Error(w, "request failed", http.StatusInternalServerError)
			return
		}
		fmt.Printf("[+] Reset password response (%d): %s\n", status, body)
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	token := r.URL.Query().Get("token")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, formPage("Reset Password", fmt.Sprintf(`
		<form method="POST" action="/reset-password">
			<label>Reset Token</label>
			<input type="text" name="token" value="%s" placeholder="Paste token from email" required>
			<label>New Password</label>
			<input type="password" name="password" placeholder="At least 8 characters" required>
			<div class="actions">
				<button type="submit" class="btn btn-primary">Reset Password</button>
				<a href="/" class="btn btn-secondary">Cancel</a>
			</div>
		</form>`, token)))
}

// formPage renders a minimal card page for the given title and body HTML.
// Shared by handleForgotPassword, handleResetPassword, and handleUpdateProfile.
func formPage(title, bodyHTML string) string {
	return fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
	<title>%s</title>
	<style>
		body { font-family: sans-serif; display: flex; justify-content: center; align-items: flex-start; min-height: 100vh; margin: 0; padding: 2rem; background-color: #f4f7f6; box-sizing: border-box; }
		.card { width: 100%%; max-width: 480px; margin: auto; padding: 2rem; background: white; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
		h1 { margin-top: 0; }
		label { display: block; margin-top: 1rem; font-weight: bold; font-size: 14px; }
		input { width: 100%%; padding: 8px; margin-top: 4px; border: 1px solid #ced4da; border-radius: 4px; font-size: 14px; box-sizing: border-box; }
		.hint { font-size: 12px; color: #6c757d; margin-top: 2px; }
		.actions { margin-top: 1.5rem; display: flex; gap: 8px; }
		.btn { padding: 10px 20px; font-size: 15px; cursor: pointer; color: white; border: none; border-radius: 4px; text-decoration: none; display: inline-block; }
		.btn-primary { background-color: #007bff; }
		.btn-secondary { background-color: #6c757d; }
		.btn:hover { opacity: 0.85; }
	</style>
</head>
<body>
	<div class="card">
		<h1>%s</h1>
		%s
	</div>
</body>
</html>`, title, title, bodyHTML)
}

func generateRandom(n int) (string, error) {
	return random.Token()
}

func s256Challenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

func extractNonce(idToken string) (string, error) {
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return "", errors.New("invalid id_token")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", err
	}
	var claims struct {
		Nonce string `json:"nonce"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", err
	}
	return claims.Nonce, nil
}

// postForm sends a POST with form data and no auth header.
func postForm(endpoint string, data url.Values) ([]byte, int, error) {
	resp, err := http.PostForm(endpoint, data)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	return body, resp.StatusCode, err
}

func postToken(data url.Values) (*tokenResponse, error) {
	var (
		resp *http.Response
		err  error
	)
	for attempt := range 2 {
		resp, err = http.PostForm(TokenEndpoint, data)
		if err == nil {
			break
		}
		if attempt == 0 && errors.Is(err, io.EOF) {
			continue
		}
		return nil, err
	}
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token endpoint returned %d: %s", resp.StatusCode, body)
	}

	var tok tokenResponse
	if err := json.Unmarshal(body, &tok); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}
	if tok.AccessToken == "" {
		return nil, fmt.Errorf("no access_token in response: %s", body)
	}
	return &tok, nil
}

func postWithBearer(endpoint, token string, data url.Values) ([]byte, int, error) {
	req, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	return body, resp.StatusCode, err
}

func prettyJSON(v any) string {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return fmt.Sprintf("%+v", v)
	}
	return string(b)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func fetchUserInfo(token string) (string, error) {
	var (
		resp *http.Response
		err  error
	)
	for attempt := range 2 {
		req, reqErr := http.NewRequest(http.MethodGet, UserinfoEndpoint, nil)
		if reqErr != nil {
			return "", reqErr
		}
		req.Header.Set("Authorization", "Bearer "+token)

		resp, err = http.DefaultClient.Do(req)
		if err == nil {
			break
		}
		if attempt == 0 && errors.Is(err, io.EOF) {
			continue
		}
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("userinfo endpoint returned %d: %s", resp.StatusCode, body)
	}
	return strings.TrimSpace(string(body)), nil
}
