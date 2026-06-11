package service

import (
	"context"
	"errors"

	"sc/modules/auth/domain/entity"
	"sc/modules/auth/port"
)

// ClientCredentials carries client identification from either auth channel:
// form fields (client_secret_post) or the Basic Authorization header
// (client_secret_basic, extracted by middleware into ctx-bound fields).
type ClientCredentials struct {
	ClientID      string
	FormSecret    string
	BasicClientID string
	BasicSecret   string
}

// ClientAuthenticator resolves a client through the registry and verifies its
// credentials. Shared by every endpoint that authenticates clients
// (token exchange, refresh; later revoke/introspect).
type ClientAuthenticator struct {
	registry port.ClientRegistry
}

func NewClientAuthenticator(registry port.ClientRegistry) *ClientAuthenticator {
	return &ClientAuthenticator{registry: registry}
}

// Authenticate returns the client when the credentials prove it:
// public clients must present no secret (PKCE is enforced by the caller),
// confidential clients must present a verifying secret via the channel they
// registered as token_endpoint_auth_method (RFC 8414): client_secret_basic
// credentials are not accepted over the form channel, and vice versa.
func (s *ClientAuthenticator) Authenticate(ctx context.Context, creds ClientCredentials) (*entity.Client, error) {
	clientID, secret, viaBasic, err := resolveCredentialChannel(creds)
	if err != nil {
		return nil, err
	}

	client, err := s.registry.FindByID(ctx, entity.DefaultTenantID, entity.ClientID(clientID))
	if err != nil {
		return nil, err
	}
	if client == nil {
		return nil, errors.New("unknown client")
	}

	switch client.AuthMethod {
	case entity.ClientAuthNone:
		if viaBasic || secret != "" {
			return nil, errors.New("public client must not present credentials")
		}
		return client, nil
	case entity.ClientAuthSecretBasic:
		if !viaBasic {
			return nil, errors.New("client must authenticate with client_secret_basic")
		}
	case entity.ClientAuthSecretPost:
		if viaBasic {
			return nil, errors.New("client must authenticate with client_secret_post")
		}
	default:
		return nil, errors.New("unsupported client auth method")
	}

	if err := client.VerifySecret(secret); err != nil {
		return nil, errors.New("client authentication failed")
	}
	return client, nil
}

// resolveCredentialChannel picks Basic over form (RFC 6749 §2.3) and rejects
// requests that identify two different clients across the channels.
func resolveCredentialChannel(creds ClientCredentials) (clientID, secret string, viaBasic bool, err error) {
	if creds.BasicClientID == "" {
		return creds.ClientID, creds.FormSecret, false, nil
	}
	if creds.ClientID != "" && creds.ClientID != creds.BasicClientID {
		return "", "", false, errors.New("client_id mismatch between Basic auth and request body")
	}
	return creds.BasicClientID, creds.BasicSecret, true, nil
}
