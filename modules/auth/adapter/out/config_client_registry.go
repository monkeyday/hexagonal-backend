package adapter

import (
	"context"

	"sc/modules/auth/domain/entity"
)

type clientKey struct {
	tenantID entity.TenantID
	id       entity.ClientID
}

// ConfigClientRegistry is a static registry holding clients built from
// configuration at startup.
type ConfigClientRegistry struct {
	clients map[clientKey]*entity.Client
}

func NewConfigClientRegistry(clients ...*entity.Client) *ConfigClientRegistry {
	m := make(map[clientKey]*entity.Client, len(clients))
	for _, c := range clients {
		m[clientKey{tenantID: c.TenantID, id: c.ID}] = c
	}
	return &ConfigClientRegistry{clients: m}
}

func (r *ConfigClientRegistry) FindByID(_ context.Context, tenantID entity.TenantID, id entity.ClientID) (*entity.Client, error) {
	return r.clients[clientKey{tenantID: tenantID, id: id}], nil
}
