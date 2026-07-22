package define

import (
	"net/http"
	"net/url"
	"sc/core/web"
	"sc/modules/auth/domain/entity"
)

const (
	SignInPath             = "/sign-in"
	TokenTypeBearer        = "Bearer"
	TokenTypeRefreshToken  = "refresh_token"
	CookieRefreshToken     = "refresh_token"
	CookieAuthorizeRequest = "auth_session"
	HTMLKeyCsrfToken       = "csrf_token"
	HTMLKeyTitle           = "title"
	HTMLPageSignIn         = "sign_in"
	HTMLTitleSignIn        = "Sign In"
)

type CreateUserResponse struct {
	Username string `json:"username"`
	Nickname string `json:"nickname"`
	Email    string `json:"email"`
}

func (r *CreateUserResponse) FromEntity(u *entity.User) {
	r.Username = u.Username
	r.Nickname = u.Nickname
	r.Email = u.Email
}

type TokenResponse struct {
	Scope        string `json:"scope"`
	TokenType    string `json:"token_type"`
	AccessToken  string `json:"access_token"`
	IDToken      string `json:"id_token,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	ExpiresIn    int    `json:"expires_in"`
}

func (r *TokenResponse) FromEntity(tokens *entity.IssuedTokens, expireSecs int) {
	r.Scope = tokens.Scope.String()
	r.TokenType = TokenTypeBearer
	r.AccessToken = tokens.AccessToken
	r.RefreshToken = tokens.RefreshToken
	r.IDToken = tokens.IDToken
	r.ExpiresIn = expireSecs
}

type GetSignInResponse struct {
	CSRFToken string
}

func (r *GetSignInResponse) HTMLPage() string { return HTMLPageSignIn }
func (r *GetSignInResponse) NoStore() bool    { return true }
func (r *GetSignInResponse) HTMLData() map[string]any {
	return map[string]any{
		HTMLKeyTitle:     HTMLTitleSignIn,
		HTMLKeyCsrfToken: r.CSRFToken,
	}
}

type CreateAuthCodeResponse struct {
	RedirectURI string
}

func (r *CreateAuthCodeResponse) URL() string {
	return r.RedirectURI
}

func (r *CreateAuthCodeResponse) Cookies() []web.Cookie {
	return []web.Cookie{{Name: CookieAuthorizeRequest, Value: "", MaxAge: -1, SameSite: new(http.SameSiteLaxMode)}}
}

type LogoutResponse struct {
	RedirectURI string `json:"redirect_uri,omitempty"`
}

func (r *LogoutResponse) URL() string {
	return r.RedirectURI
}

func (r *LogoutResponse) Cookies() []web.Cookie {
	return []web.Cookie{{Name: CookieRefreshToken, Value: "", MaxAge: -1}}
}

// AuthorizeErrorRedirect carries an RFC 6749 §4.1.2.1 error back to the client's
// registered redirect_uri (error + state in the query). It is only used once the
// redirect_uri has been validated against the client registry.
type AuthorizeErrorRedirect struct {
	redirectURI string
	errCode     string
	state       *string
}

func NewAuthorizeErrorRedirect(redirectURI, errCode string, state *string) *AuthorizeErrorRedirect {
	return &AuthorizeErrorRedirect{redirectURI: redirectURI, errCode: errCode, state: state}
}

func (r *AuthorizeErrorRedirect) URL() string {
	u, err := url.Parse(r.redirectURI)
	if err != nil {
		return r.redirectURI
	}
	q := u.Query()
	q.Set("error", r.errCode)
	if r.state != nil {
		q.Set("state", *r.state)
	}
	u.RawQuery = q.Encode()
	return u.String()
}

type GetAuthorizeResponse struct {
	SessionID string
}

func (r *GetAuthorizeResponse) URL() string {
	return SignInPath
}

func (r *GetAuthorizeResponse) Cookies() []web.Cookie {
	return []web.Cookie{{
		Name:     CookieAuthorizeRequest,
		Value:    r.SessionID,
		MaxAge:   int(entity.AuthorizeRequestTTL.Seconds()),
		SameSite: new(http.SameSiteLaxMode),
	}}
}

type GetProfileResponse struct {
	Sub               string `json:"sub"`
	PreferredUsername string `json:"preferred_username"`
	Nickname          string `json:"nickname"`
	Email             string `json:"email"`
	EmailVerified     bool   `json:"email_verified"`
	UpdatedAt         int64  `json:"updated_at"`
}

type UpdateProfileResponse struct {
	UpdatedAt     any    `json:"updated_at"`
	UserID        string `json:"user_id"`
	Email         string `json:"email"`
	Username      string `json:"username"`
	Nickname      string `json:"nickname"`
	EmailVerified bool   `json:"email_verified"`
}

// IntrospectResponse follows RFC 7662. When Active is false, all other fields are omitted.
type IntrospectResponse struct {
	Active    bool     `json:"active"`
	Sub       string   `json:"sub,omitempty"`
	Issuer    string   `json:"iss,omitempty"`
	Audience  []string `json:"aud,omitempty"`
	Scope     string   `json:"scope,omitempty"`
	ExpiresAt int64    `json:"exp,omitempty"`
	IssuedAt  int64    `json:"iat,omitempty"`
	JWTID     string   `json:"jti,omitempty"`
	TokenType string   `json:"token_type,omitempty"`
}
