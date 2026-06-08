package entity

import (
	"errors"

	"github.com/google/uuid"
)

type ClientID string
type SessionID string
type UserID string

func NewClientID(id string) (ClientID, error) {
	if id == "" {
		return "", errors.New("client_id must not be empty")
	}
	return ClientID(id), nil
}

func NewSessionID() SessionID {
	return SessionID(uuid.NewString())
}

func NewUserID() UserID {
	return UserID(uuid.NewString())
}
