package filerepo

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	coreerror "sc/core/error"
	infrarepo "sc/infrastructure/repository"
	"sync"
)

// CreateIfFieldNotExists checks under the write lock that no item has the given field value,
// then saves the new item. Returns coreerror.ErrConflict if the field value is already taken.
func (r *FileRepository[T, D]) CreateIfFieldNotExists(field, value string, item *T) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, err := FindByField(r.items, Field(field), value)
	if err == nil {
		return coreerror.ErrConflict
	}
	if !errors.Is(err, coreerror.ErrNotFound) {
		return err
	}
	id := r.getID(item)
	docs := make(map[string]*D, len(r.items)+1)
	for k, v := range r.items {
		docs[k] = r.toDoc(v)
	}
	docs[id] = r.toDoc(item)
	if err := writeToFile(r.store.filePath, docs); err != nil {
		return err
	}
	r.items[id] = item
	return nil
}

type FileStore struct {
	filePath string
}

func NewFileStore(dbDir, fileName string) (*FileStore, error) {
	filePath := filepath.Join(dbDir, fileName)

	if _, err := os.Stat(filePath); err == nil {
		return &FileStore{filePath: filePath}, nil
	}

	if err := os.MkdirAll(dbDir, 0750); err != nil {
		return nil, infrarepo.NewErrInitFailed(err)
	}

	file, err := os.Create(filePath)
	if err != nil {
		return nil, infrarepo.NewErrInitFailed(err)
	}
	defer file.Close()

	if err := json.NewEncoder(file).Encode(map[string]struct{}{}); err != nil {
		return nil, infrarepo.NewErrInitFailed(err)
	}

	return &FileStore{filePath: filePath}, nil
}

type FileRepository[T any, D any] struct {
	mu       sync.RWMutex
	items    map[string]*T
	store    *FileStore
	toDoc    func(*T) *D
	toEntity func(*D) (*T, error)
	getID    func(*T) string
}

func New[T any, D any](
	store *FileStore,
	seed map[string]*T,
	toDoc func(*T) *D,
	toEntity func(*D) (*T, error),
	getID func(*T) string,
) (*FileRepository[T, D], error) {
	loaded, err := loadFromFile[D](store.filePath)
	if err != nil {
		return nil, err
	}

	if len(loaded) == 0 && len(seed) > 0 {
		docs := make(map[string]*D, len(seed))
		for k, item := range seed {
			docs[k] = toDoc(item)
		}
		if err := writeToFile(store.filePath, docs); err != nil {
			return nil, err
		}
		loaded = docs
	}

	items := make(map[string]*T, len(loaded))
	for k, d := range loaded {
		item, err := toEntity(d)
		if err != nil {
			return nil, err
		}
		items[k] = item
	}

	return &FileRepository[T, D]{
		items:    items,
		store:    store,
		toDoc:    toDoc,
		toEntity: toEntity,
		getID:    getID,
	}, nil
}

func (r *FileRepository[T, D]) FindByField(field string, value string) (*T, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return FindByField(r.items, Field(field), value)
}

// All returns live pointers into the repository's internal map.
// Callers must not modify returned values unless they immediately pass them back to Save.
func (r *FileRepository[T, D]) All() []*T {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make([]*T, 0, len(r.items))
	for _, item := range r.items {
		result = append(result, item)
	}
	return result
}

// UpdateByField finds an item by field value and applies update under the write lock,
// making the check-mutate-save sequence atomic. If update returns an error the item is not saved.
func (r *FileRepository[T, D]) UpdateByField(field string, value string, update func(*T) error) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	item, err := FindByField(r.items, Field(field), value)
	if err != nil {
		return err
	}
	cp := *item
	if err := update(&cp); err != nil {
		return err
	}

	id := r.getID(&cp)
	docs := make(map[string]*D, len(r.items))
	for k, v := range r.items {
		docs[k] = r.toDoc(v)
	}
	docs[id] = r.toDoc(&cp)
	if err := writeToFile(r.store.filePath, docs); err != nil {
		return err
	}
	r.items[id] = &cp
	return nil
}

func (r *FileRepository[T, D]) Save(item *T) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	id := r.getID(item)
	docs := make(map[string]*D, len(r.items)+1)
	for k, v := range r.items {
		docs[k] = r.toDoc(v)
	}
	docs[id] = r.toDoc(item)
	if err := writeToFile(r.store.filePath, docs); err != nil {
		return err
	}
	r.items[id] = item
	return nil
}

func writeToFile[D any](filePath string, docs map[string]*D) error {
	tmp := filePath + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return infrarepo.NewErrWriteFailed(err)
	}
	if err := json.NewEncoder(f).Encode(docs); err != nil {
		f.Close()
		os.Remove(tmp)
		return infrarepo.NewErrWriteFailed(err)
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return infrarepo.NewErrWriteFailed(err)
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return infrarepo.NewErrWriteFailed(err)
	}
	if err := os.Rename(tmp, filePath); err != nil {
		os.Remove(tmp)
		return infrarepo.NewErrWriteFailed(err)
	}
	return nil
}

func loadFromFile[D any](filePath string) (map[string]*D, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, infrarepo.NewErrReadFailed(err)
	}
	defer file.Close()

	var result map[string]*D
	if err := json.NewDecoder(file).Decode(&result); err != nil {
		return nil, infrarepo.NewErrReadFailed(err)
	}
	return result, nil
}
