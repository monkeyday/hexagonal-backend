package service

import (
	"context"
	"testing"

	"sc/modules/auth/domain/entity"
)

type stubRegistry struct {
	clients map[entity.ClientID]*entity.Client
}

func (s *stubRegistry) FindByID(_ context.Context, _ entity.TenantID, id entity.ClientID) (*entity.Client, error) {
	return s.clients[id], nil
}

func TestClientAuthenticator_Authenticate(t *testing.T) {
	ctx := context.Background()
	const secret = "conf-secret-1"

	public, err := entity.NewClient(entity.ClientArgs{
		ID:            "public-client",
		AuthMethod:    entity.ClientAuthNone,
		RedirectURIs:  []string{"https://app.example.com/callback"},
		AllowedGrants: []entity.GrantType{entity.GrantAuthorizationCode},
	})
	if err != nil {
		t.Fatalf("NewClient public: %v", err)
	}
	confidential, err := entity.NewClient(entity.ClientArgs{
		ID:            "conf-client",
		AuthMethod:    entity.ClientAuthSecretBasic,
		Secret:        secret,
		RedirectURIs:  []string{"https://app.example.com/callback"},
		AllowedGrants: []entity.GrantType{entity.GrantAuthorizationCode},
	})
	if err != nil {
		t.Fatalf("NewClient confidential: %v", err)
	}
	postClient, err := entity.NewClient(entity.ClientArgs{
		ID:            "post-client",
		AuthMethod:    entity.ClientAuthSecretPost,
		Secret:        secret,
		RedirectURIs:  []string{"https://app.example.com/callback"},
		AllowedGrants: []entity.GrantType{entity.GrantAuthorizationCode},
	})
	if err != nil {
		t.Fatalf("NewClient post: %v", err)
	}

	auth := NewClientAuthenticator(&stubRegistry{clients: map[entity.ClientID]*entity.Client{
		public.ID:       public,
		confidential.ID: confidential,
		postClient.ID:   postClient,
	}})

	tests := []struct {
		name    string
		creds   ClientCredentials
		wantID  entity.ClientID
		wantErr bool
	}{
		{
			name:   "public client without secret — ok",
			creds:  ClientCredentials{ClientID: "public-client"},
			wantID: "public-client",
		},
		{
			name:    "public client presenting a secret — rejected",
			creds:   ClientCredentials{ClientID: "public-client", FormSecret: "anything"},
			wantErr: true,
		},
		{
			name:    "client_secret_basic client via form secret — rejected (wrong channel)",
			creds:   ClientCredentials{ClientID: "conf-client", FormSecret: secret},
			wantErr: true,
		},
		{
			name:   "confidential client via Basic — ok",
			creds:  ClientCredentials{BasicClientID: "conf-client", BasicSecret: secret},
			wantID: "conf-client",
		},
		{
			name:   "client_secret_post client via form secret — ok",
			creds:  ClientCredentials{ClientID: "post-client", FormSecret: secret},
			wantID: "post-client",
		},
		{
			name:    "client_secret_post client via Basic — rejected (wrong channel)",
			creds:   ClientCredentials{BasicClientID: "post-client", BasicSecret: secret},
			wantErr: true,
		},
		{
			name:    "public client identified via Basic header — rejected",
			creds:   ClientCredentials{BasicClientID: "public-client"},
			wantErr: true,
		},
		{
			name:   "Basic plus matching form client_id — ok",
			creds:  ClientCredentials{ClientID: "conf-client", BasicClientID: "conf-client", BasicSecret: secret},
			wantID: "conf-client",
		},
		{
			name:    "Basic and form identify different clients — rejected",
			creds:   ClientCredentials{ClientID: "public-client", BasicClientID: "conf-client", BasicSecret: secret},
			wantErr: true,
		},
		{
			name:    "confidential client with wrong secret — rejected",
			creds:   ClientCredentials{ClientID: "conf-client", FormSecret: "wrong"},
			wantErr: true,
		},
		{
			name:    "confidential client without secret — rejected",
			creds:   ClientCredentials{ClientID: "conf-client"},
			wantErr: true,
		},
		{
			name:    "unknown client — rejected",
			creds:   ClientCredentials{ClientID: "ghost"},
			wantErr: true,
		},
		{
			name:    "form secret does not satisfy Basic channel for a different client",
			creds:   ClientCredentials{BasicClientID: "conf-client", FormSecret: secret},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			client, err := auth.Authenticate(ctx, tc.creds)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if client.ID != tc.wantID {
				t.Errorf("client.ID = %q, want %q", client.ID, tc.wantID)
			}
		})
	}
}
