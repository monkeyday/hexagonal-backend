package adapter

import (
	"testing"

	filerepo "sc/infrastructure/repository/file"
	"sc/modules/auth/port"
)

func newGrantFileStore(t *testing.T) *filerepo.FileStore {
	t.Helper()
	store, err := filerepo.NewFileStore(t.TempDir(), "grants.json")
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	return store
}

func TestFileGrantRepository(t *testing.T) {
	runGrantContract(t, func(t *testing.T) port.GrantRepository {
		repo, err := NewFileGrantRepository(newGrantFileStore(t))
		if err != nil {
			t.Fatalf("NewFileGrantRepository: %v", err)
		}
		return repo
	})
}
