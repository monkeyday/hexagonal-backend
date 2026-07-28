package entity

import (
	"errors"

	"github.com/google/uuid"
)

type ClientID string

// GrantID identifies one successful end-user authentication and its
// refresh-token rotation chain (RFC 6749 grant). Distinct from SessionID,
// which is the pre-authentication AuthorizeRequest handle.
type GrantID string

type SessionID string
type TenantID string
type UserID string

// DefaultTenantID is the single realm used until multi-tenancy lands.
const DefaultTenantID TenantID = "default"

func NewClientID(id string) (ClientID, error) {
	if id == "" {
		return "", errors.New("client_id must not be empty")
	}
	return ClientID(id), nil
}

func NewGrantID() GrantID {
	return GrantID(uuid.NewString())
}

func NewSessionID() SessionID {
	return SessionID(uuid.NewString())
}

func NewUserID() UserID {
	return UserID(uuid.NewString())
}
