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
	_, err := r.findByFieldLocked(Field(field), value)
	if err == nil {
		return coreerror.ErrConflict
	}
	if !errors.Is(err, coreerror.ErrNotFound) {
		return err
	}
	id := r.getID(item)
	if err := r.writeItemsWith(id, item); err != nil {
		return err
	}
	r.items[id] = item
	r.updateIndexesForItem(id, item)
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
	mu            sync.RWMutex
	items         map[string]*T
	indexedFields map[Field]map[string]string
	store         *FileStore
	toDoc         func(*T) *D
	toEntity      func(*D) (*T, error)
	getID         func(*T) string
}

func New[T any, D any](
	store *FileStore,
	toDoc func(*T) *D,
	toEntity func(*D) (*T, error),
	getID func(*T) string,
) (*FileRepository[T, D], error) {
	loaded, err := loadFromFile[D](store.filePath)
	if err != nil {
		return nil, err
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
		items:         items,
		indexedFields: make(map[Field]map[string]string),
		store:         store,
		toDoc:         toDoc,
		toEntity:      toEntity,
		getID:         getID,
	}, nil
}

func (r *FileRepository[T, D]) FindByField(field string, value string) (*T, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.findByFieldLocked(Field(field), value)
}

// UpdateByField finds an item by field value and applies update under the write lock,
// making the check-mutate-save sequence atomic. If update returns an error the item is not saved.
func (r *FileRepository[T, D]) UpdateByField(field string, value string, update func(*T) error) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	item, err := r.findByFieldLocked(Field(field), value)
	if err != nil {
		return err
	}
	cp := *item
	if err := update(&cp); err != nil {
		return err
	}

	id := r.getID(&cp)
	if err := r.writeItemsWith(id, &cp); err != nil {
		return err
	}
	r.items[id] = &cp
	r.updateIndexesForItem(id, &cp)
	return nil
}

func (r *FileRepository[T, D]) UpdateAll(update func(*T) (bool, error)) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	nextItems := make(map[string]*T, len(r.items))
	for id, item := range r.items {
		nextItems[id] = item
		cp := *item
		changed, err := update(&cp)
		if err != nil {
			return err
		}
		if changed {
			nextItems[id] = &cp
		}
	}
	if sameItems(r.items, nextItems) {
		return nil
	}
	if err := r.writeItems(nextItems); err != nil {
		return err
	}
	r.items = nextItems
	r.rebuildIndexes()
	return nil
}

func (r *FileRepository[T, D]) Save(item *T) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	id := r.getID(item)
	if err := r.writeItemsWith(id, item); err != nil {
		return err
	}
	r.items[id] = item
	r.updateIndexesForItem(id, item)
	return nil
}

func (r *FileRepository[T, D]) findByFieldLocked(field Field, value string) (*T, error) {
	index, ok := r.indexedFields[field]
	if !ok {
		var err error
		index, err = r.buildIndex(field)
		if err != nil {
			return nil, err
		}
		r.indexedFields[field] = index
	}
	id, ok := index[value]
	if !ok {
		return nil, coreerror.ErrNotFound
	}
	item, ok := r.items[id]
	if !ok {
		delete(index, value)
		return nil, coreerror.ErrNotFound
	}
	return item, nil
}

func (r *FileRepository[T, D]) buildIndex(field Field) (map[string]string, error) {
	index := make(map[string]string, len(r.items))
	for id, item := range r.items {
		value, ok, err := stringFieldValue(item, field)
		if err != nil {
			return nil, err
		}
		if ok {
			index[value] = id
		}
	}
	return index, nil
}

func (r *FileRepository[T, D]) updateIndexesForItem(id string, item *T) {
	for field, index := range r.indexedFields {
		for value, indexedID := range index {
			if indexedID == id {
				delete(index, value)
			}
		}
		if value, ok, err := stringFieldValue(item, field); err == nil && ok {
			index[value] = id
		}
	}
}

func (r *FileRepository[T, D]) rebuildIndexes() {
	for field := range r.indexedFields {
		index, err := r.buildIndex(field)
		if err != nil {
			// Drop the index so the next lookup rebuilds it and surfaces the error.
			delete(r.indexedFields, field)
			continue
		}
		r.indexedFields[field] = index
	}
}

func (r *FileRepository[T, D]) writeItems(items map[string]*T) error {
	docs := make(map[string]*D, len(items))
	for k, v := range items {
		docs[k] = r.toDoc(v)
	}
	return writeToFile(r.store.filePath, docs)
}

// writeItemsWith persists the current items with item added or replaced under id,
// without mutating r.items; the caller applies the in-memory change only after
// the write succeeds.
func (r *FileRepository[T, D]) writeItemsWith(id string, item *T) error {
	docs := make(map[string]*D, len(r.items)+1)
	for k, v := range r.items {
		docs[k] = r.toDoc(v)
	}
	docs[id] = r.toDoc(item)
	return writeToFile(r.store.filePath, docs)
}

func sameItems[T any](a, b map[string]*T) bool {
	if len(a) != len(b) {
		return false
	}
	for k, av := range a {
		if b[k] != av {
			return false
		}
	}
	return true
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
