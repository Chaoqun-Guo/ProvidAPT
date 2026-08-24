// Copyright (c) 2026 Chaoqun-Guo
// SPDX-License-Identifier: Apache-2.0

package secure

import (
	"io"

	"github.com/cockroachdb/pebble"
)

// EncryptedStore wraps a pebble.DB and transparently encrypts values on write,
// decrypts on read. Keys are NOT encrypted to preserve indexability.
type EncryptedStore struct {
	db  *pebble.DB
	key []byte
}

// NewEncryptedStore wraps an existing pebble.DB with value-level encryption.
func NewEncryptedStore(db *pebble.DB, key []byte) *EncryptedStore {
	return &EncryptedStore{db: db, key: key}
}

// Get decrypts the value retrieved from Pebble.
func (es *EncryptedStore) Get(key []byte) ([]byte, io.Closer, error) {
	encValue, closer, err := es.db.Get(key)
	if err != nil {
		return nil, closer, err
	}
	plaintext, err := Decrypt(es.key, encValue)
	if err != nil {
		_ = closer.Close()
		return nil, nil, err
	}
	return plaintext, closer, nil
}

// Set encrypts the value before writing to Pebble.
func (es *EncryptedStore) Set(key, value []byte, opts *pebble.WriteOptions) error {
	encValue, err := Encrypt(es.key, value)
	if err != nil {
		return err
	}
	return es.db.Set(key, encValue, opts)
}

// Delete deletes a key from Pebble (no encryption involved).
func (es *EncryptedStore) Delete(key []byte, opts *pebble.WriteOptions) error {
	return es.db.Delete(key, opts)
}

// NewIter returns an iterator that transparently decrypts values.
func (es *EncryptedStore) NewIter(opts *pebble.IterOptions) (*EncryptedIterator, error) {
	iter, err := es.db.NewIter(opts)
	if err != nil {
		return nil, err
	}
	return &EncryptedIterator{
		iter: iter,
		key:  es.key,
	}, nil
}

// Close closes the underlying Pebble database.
func (es *EncryptedStore) Close() error {
	return es.db.Close()
}

// Flush flushes the underlying Pebble database.
func (es *EncryptedStore) Flush() error {
	return es.db.Flush()
}

// Metrics returns the underlying Pebble metrics.
func (es *EncryptedStore) Metrics() *pebble.Metrics {
	return es.db.Metrics()
}

// UnderlyingDB exposes the raw pebble.DB for direct operations.
func (es *EncryptedStore) UnderlyingDB() *pebble.DB {
	return es.db
}

// ── Encrypted Iterator ───────────────────────────────────────

// EncryptedIterator wraps a pebble.Iterator and decrypts values on the fly.
type EncryptedIterator struct {
	iter *pebble.Iterator
	key  []byte
}

func (ei *EncryptedIterator) First() bool            { return ei.iter.First() }
func (ei *EncryptedIterator) Last() bool             { return ei.iter.Last() }
func (ei *EncryptedIterator) SeekGE(key []byte) bool { return ei.iter.SeekGE(key) }
func (ei *EncryptedIterator) SeekLT(key []byte) bool { return ei.iter.SeekLT(key) }
func (ei *EncryptedIterator) Next() bool             { return ei.iter.Next() }
func (ei *EncryptedIterator) Prev() bool             { return ei.iter.Prev() }
func (ei *EncryptedIterator) Valid() bool            { return ei.iter.Valid() }
func (ei *EncryptedIterator) Error() error           { return ei.iter.Error() }
func (ei *EncryptedIterator) Key() []byte            { return ei.iter.Key() }
func (ei *EncryptedIterator) Close() error           { return ei.iter.Close() }

// Value decrypts the value at the current iterator position.
func (ei *EncryptedIterator) Value() []byte {
	encValue := ei.iter.Value()
	if encValue == nil {
		return nil
	}
	plaintext, err := Decrypt(ei.key, encValue)
	if err != nil {
		return nil
	}
	return plaintext
}
