package adapter

import (
	"time"

	"sc/modules/auth/domain/entity"
)

// grantDoc is the persistence representation of entity.Grant, shared by the
// file and Mongo grant repositories.
type grantDoc struct {
	ID              string     `json:"id"               bson:"_id"`
	UserID          string     `json:"user_id"          bson:"user_id"`
	ClientID        string     `json:"client_id"        bson:"client_id"`
	DeviceID        string     `json:"device_id"        bson:"device_id"`
	AuthenticatedAt time.Time  `json:"authenticated_at" bson:"authenticated_at"`
	CreatedAt       time.Time  `json:"created_at"       bson:"created_at"`
	ExpiresAt       time.Time  `json:"expires_at"       bson:"expires_at"`
	RevokedAt       *time.Time `json:"revoked_at"       bson:"revoked_at"`
}

func grantToDoc(g *entity.Grant) *grantDoc {
	return &grantDoc{
		ID:              string(g.ID),
		UserID:          string(g.UserID),
		ClientID:        string(g.ClientID),
		DeviceID:        g.DeviceID,
		AuthenticatedAt: g.AuthenticatedAt,
		CreatedAt:       g.CreatedAt,
		ExpiresAt:       g.ExpiresAt,
		RevokedAt:       g.RevokedAt,
	}
}

func grantToEntity(d *grantDoc) (*entity.Grant, error) {
	return &entity.Grant{
		ID:              entity.GrantID(d.ID),
		UserID:          entity.UserID(d.UserID),
		ClientID:        entity.ClientID(d.ClientID),
		DeviceID:        d.DeviceID,
		AuthenticatedAt: d.AuthenticatedAt,
		CreatedAt:       d.CreatedAt,
		ExpiresAt:       d.ExpiresAt,
		RevokedAt:       d.RevokedAt,
	}, nil
}
