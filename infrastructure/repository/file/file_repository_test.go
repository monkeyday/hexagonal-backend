package filerepo

import (
	"errors"
	"testing"

	coreerror "sc/core/error"
	infrarepo "sc/infrastructure/repository"
)

type record struct {
	ID    string
	Email string
	Note  *string
}

func newRecordRepo(t *testing.T) *FileRepository[record, record] {
	t.Helper()
	store, err := NewFileStore(t.TempDir(), "records.json")
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	repo, err := New[record, record](
		store,
		func(r *record) *record { return r },
		func(d *record) (*record, error) { return d, nil },
		func(r *record) string { return r.ID },
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return repo
}

func TestFileRepository_FindByField(t *testing.T) {
	repo := newRecordRepo(t)
	if err := repo.Save(&record{ID: "1", Email: "a@example.com"}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := repo.Save(&record{ID: "2", Email: "b@example.com"}); err != nil {
		t.Fatalf("Save: %v", err)
	}

	tests := []struct {
		name    string
		field   string
		value   string
		wantID  string
		wantErr error
	}{
		{name: "hit", field: "Email", value: "b@example.com", wantID: "2"},
		{name: "repeated lookup uses the built index", field: "Email", value: "a@example.com", wantID: "1"},
		{name: "miss", field: "Email", value: "nobody@example.com", wantErr: coreerror.ErrNotFound},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := repo.FindByField(tc.field, tc.value)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("err = %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.ID != tc.wantID {
				t.Fatalf("ID = %q, want %q", got.ID, tc.wantID)
			}
		})
	}

	t.Run("unknown field", func(t *testing.T) {
		_, err := repo.FindByField("Nope", "x")
		var invalid *infrarepo.ErrInvalidField
		if !errors.As(err, &invalid) {
			t.Fatalf("err = %v, want ErrInvalidField", err)
		}
	})
}

func TestFileRepository_IndexFollowsWrites(t *testing.T) {
	repo := newRecordRepo(t)
	if err := repo.Save(&record{ID: "1", Email: "old@example.com"}); err != nil {
		t.Fatalf("Save: %v", err)
	}
	// Build the index before mutating so the test exercises index maintenance.
	if _, err := repo.FindByField("Email", "old@example.com"); err != nil {
		t.Fatalf("FindByField: %v", err)
	}

	t.Run("Save replaces the indexed value", func(t *testing.T) {
		if err := repo.Save(&record{ID: "1", Email: "new@example.com"}); err != nil {
			t.Fatalf("Save: %v", err)
		}
		if _, err := repo.FindByField("Email", "old@example.com"); !errors.Is(err, coreerror.ErrNotFound) {
			t.Fatalf("stale index entry: err = %v, want ErrNotFound", err)
		}
		got, err := repo.FindByField("Email", "new@example.com")
		if err != nil || got.ID != "1" {
			t.Fatalf("got %v, %v; want record 1", got, err)
		}
	})

	t.Run("UpdateByField re-indexes the changed field", func(t *testing.T) {
		err := repo.UpdateByField("Email", "new@example.com", func(r *record) error {
			r.Email = "updated@example.com"
			return nil
		})
		if err != nil {
			t.Fatalf("UpdateByField: %v", err)
		}
		got, err := repo.FindByField("Email", "updated@example.com")
		if err != nil || got.ID != "1" {
			t.Fatalf("got %v, %v; want record 1", got, err)
		}
	})

	t.Run("CreateIfFieldNotExists conflicts on the indexed value", func(t *testing.T) {
		err := repo.CreateIfFieldNotExists("Email", "updated@example.com", &record{ID: "2", Email: "updated@example.com"})
		if !errors.Is(err, coreerror.ErrConflict) {
			t.Fatalf("err = %v, want ErrConflict", err)
		}
		if err := repo.CreateIfFieldNotExists("Email", "free@example.com", &record{ID: "2", Email: "free@example.com"}); err != nil {
			t.Fatalf("CreateIfFieldNotExists: %v", err)
		}
	})
}

func TestFileRepository_UpdateAll(t *testing.T) {
	store, err := NewFileStore(t.TempDir(), "records.json")
	if err != nil {
		t.Fatalf("NewFileStore: %v", err)
	}
	newRepo := func() *FileRepository[record, record] {
		repo, err := New[record, record](
			store,
			func(r *record) *record { return r },
			func(d *record) (*record, error) { return d, nil },
			func(r *record) string { return r.ID },
		)
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		return repo
	}

	repo := newRepo()
	for _, r := range []*record{
		{ID: "1", Email: "a@example.com"},
		{ID: "2", Email: "b@example.com"},
		{ID: "3", Email: "c@example.com"},
	} {
		if err := repo.Save(r); err != nil {
			t.Fatalf("Save: %v", err)
		}
	}

	note := "batched"
	err = repo.UpdateAll(func(r *record) (bool, error) {
		if r.ID == "2" {
			return false, nil
		}
		r.Note = &note
		return true, nil
	})
	if err != nil {
		t.Fatalf("UpdateAll: %v", err)
	}

	// Reload from disk: the batch must have been persisted in one pass.
	reloaded := newRepo()
	for id, wantNote := range map[string]bool{"1": true, "2": false, "3": true} {
		got, err := reloaded.FindByField("ID", id)
		if err != nil {
			t.Fatalf("FindByField(%s): %v", id, err)
		}
		if (got.Note != nil) != wantNote {
			t.Errorf("record %s: Note set = %v, want %v", id, got.Note != nil, wantNote)
		}
	}

	t.Run("update error aborts without partial application", func(t *testing.T) {
		err := repo.UpdateAll(func(r *record) (bool, error) {
			if r.ID == "3" {
				return false, errors.New("boom")
			}
			r.Email = "mutated@example.com"
			return true, nil
		})
		if err == nil {
			t.Fatal("expected error")
		}
		if _, err := repo.FindByField("Email", "mutated@example.com"); !errors.Is(err, coreerror.ErrNotFound) {
			t.Fatalf("partial application leaked: err = %v, want ErrNotFound", err)
		}
	})

	t.Run("no-op batch leaves items untouched", func(t *testing.T) {
		before, err := repo.FindByField("ID", "1")
		if err != nil {
			t.Fatalf("FindByField: %v", err)
		}
		if err := repo.UpdateAll(func(*record) (bool, error) { return false, nil }); err != nil {
			t.Fatalf("UpdateAll: %v", err)
		}
		after, err := repo.FindByField("ID", "1")
		if err != nil {
			t.Fatalf("FindByField: %v", err)
		}
		if before != after {
			t.Error("no-op UpdateAll must not replace stored items")
		}
	})
}
