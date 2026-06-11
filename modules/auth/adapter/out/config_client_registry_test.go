package adapter

import (
	"context"
	"testing"

	"sc/modules/auth/domain/entity"
)

func TestConfigClientRegistry_FindByID(t *testing.T) {
	ctx := context.Background()

	client, err := entity.NewClient(entity.ClientArgs{
		ID:            "client-123",
		AuthMethod:    entity.ClientAuthNone,
		RedirectURIs:  []string{"https://app.example.com/callback"},
		AllowedGrants: []entity.GrantType{entity.GrantAuthorizationCode},
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	registry := NewConfigClientRegistry(client)

	tests := []struct {
		name     string
		tenantID entity.TenantID
		clientID entity.ClientID
		wantHit  bool
	}{
		{name: "hit", tenantID: entity.DefaultTenantID, clientID: "client-123", wantHit: true},
		{name: "miss — unknown client", tenantID: entity.DefaultTenantID, clientID: "unknown", wantHit: false},
		{name: "miss — wrong tenant", tenantID: "acme", clientID: "client-123", wantHit: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := registry.FindByID(ctx, tc.tenantID, tc.clientID)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.wantHit {
				if got == nil || got.ID != tc.clientID {
					t.Fatalf("got %v, want client %q", got, tc.clientID)
				}
				return
			}
			if got != nil {
				t.Fatalf("got %v, want nil for miss", got)
			}
		})
	}
}
