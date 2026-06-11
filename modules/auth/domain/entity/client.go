package entity

import (
	"errors"
	"fmt"
	"net/url"
	"slices"

	"golang.org/x/crypto/bcrypt"
)

type ClientAuthMethod string

const (
	ClientAuthNone        ClientAuthMethod = "none"
	ClientAuthSecretBasic ClientAuthMethod = "client_secret_basic"
	ClientAuthSecretPost  ClientAuthMethod = "client_secret_post"
)

func ParseClientAuthMethod(raw string) (ClientAuthMethod, error) {
	switch m := ClientAuthMethod(raw); m {
	case ClientAuthNone, ClientAuthSecretBasic, ClientAuthSecretPost:
		return m, nil
	default:
		return "", fmt.Errorf("unsupported token_endpoint_auth_method: %q", raw)
	}
}

type GrantType string

const (
	GrantAuthorizationCode GrantType = "authorization_code"
	GrantRefreshToken      GrantType = "refresh_token"
	GrantPassword          GrantType = "password"
	GrantClientCredentials GrantType = "client_credentials"
)

func ParseGrantType(raw string) (GrantType, error) {
	switch g := GrantType(raw); g {
	case GrantAuthorizationCode, GrantRefreshToken, GrantPassword, GrantClientCredentials:
		return g, nil
	default:
		return "", fmt.Errorf("unsupported grant type: %q", raw)
	}
}

type Client struct {
	ID            ClientID
	TenantID      TenantID
	AuthMethod    ClientAuthMethod
	SecretHash    *string // bcrypt hash; nil for public clients
	RedirectURIs  []string
	AllowedGrants []GrantType
}

type ClientArgs struct {
	ID            string
	TenantID      TenantID
	AuthMethod    ClientAuthMethod
	Secret        string
	RedirectURIs  []string
	AllowedGrants []GrantType
}

func NewClient(args ClientArgs) (*Client, error) {
	id, err := NewClientID(args.ID)
	if err != nil {
		return nil, err
	}
	if err := args.validate(); err != nil {
		return nil, err
	}
	secretHash, err := args.hashSecret()
	if err != nil {
		return nil, err
	}

	tenantID := args.TenantID
	if tenantID == "" {
		tenantID = DefaultTenantID
	}

	uris := make([]string, 0, len(args.RedirectURIs))
	for _, raw := range args.RedirectURIs {
		uris = append(uris, normalizeRedirectURI(raw))
	}

	return &Client{
		ID:            id,
		TenantID:      tenantID,
		AuthMethod:    args.AuthMethod,
		SecretHash:    secretHash,
		RedirectURIs:  uris,
		AllowedGrants: args.AllowedGrants,
	}, nil
}

func (a ClientArgs) validate() error {
	if len(a.RedirectURIs) == 0 {
		return errors.New("client must have at least one redirect URI")
	}
	if len(a.AllowedGrants) == 0 {
		return errors.New("client must allow at least one grant type")
	}
	switch a.AuthMethod {
	case ClientAuthNone:
		if a.Secret != "" {
			return errors.New("public client (auth method none) must not have a secret")
		}
	case ClientAuthSecretBasic, ClientAuthSecretPost:
		if a.Secret == "" {
			return errors.New("confidential client requires a secret")
		}
	default:
		return fmt.Errorf("unsupported token_endpoint_auth_method: %q", a.AuthMethod)
	}
	return nil
}

func (a ClientArgs) hashSecret() (*string, error) {
	if a.AuthMethod == ClientAuthNone {
		return nil, nil
	}
	hashed, err := bcrypt.GenerateFromPassword([]byte(a.Secret), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}
	return new(string(hashed)), nil
}

func (c *Client) IsPublic() bool {
	return c.AuthMethod == ClientAuthNone
}

func (c *Client) VerifySecret(secret string) error {
	if c.SecretHash == nil {
		return errors.New("client has no secret")
	}
	return bcrypt.CompareHashAndPassword([]byte(*c.SecretHash), []byte(secret))
}

func (c *Client) AllowsGrant(grant GrantType) bool {
	return slices.Contains(c.AllowedGrants, grant)
}

func (c *Client) AllowsRedirectURI(uri string) bool {
	return slices.Contains(c.RedirectURIs, normalizeRedirectURI(uri))
}

// normalizeRedirectURI mirrors the binding layer's normalize:"uri" canonical
// form so registered URIs and request URIs compare in the same space.
func normalizeRedirectURI(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	return u.String()
}
