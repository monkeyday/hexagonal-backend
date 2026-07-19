package port

import (
	"context"
	"sc/modules/auth/domain/entity"
)

// ClientRegistry resolves registered OAuth clients.
// FindByID returns (nil, nil) when no client matches; callers must treat a
// nil client as unknown and reject (fail closed).
type ClientRegistry interface {
	FindByID(ctx context.Context, tenantID entity.TenantID, id entity.ClientID) (*entity.Client, error)
}
