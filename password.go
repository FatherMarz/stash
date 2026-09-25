package main

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"sync"
	"time"

	bolt "go.etcd.io/bbolt"
)

// The owner password gates every read of a raw secret value. Tokens alone
// can list names, write, run commands, and proxy, but never see a value.
// Agents hold tokens. Only the human knows the password.

var metaPassword = []byte("owner-password")

var (
	ErrNoPassword    = errors.New("no owner password is set: run `stash password set` in a terminal")
	ErrWrongPassword = errors.New("wrong owner password")
	ErrLocked        = errors.New("too many wrong passwords: reveals are locked for 15 minutes")
)

const pbkdf2Iter = 600_000

type passwordRecord struct {
	Salt []byte `json:"salt"`
	Hash []byte `json:"hash"`
	Iter int    `json:"iter"`
}

func (s *Store) loadPassword() (*passwordRecord, error) {
	var rec *passwordRecord
	err := s.db.View(func(tx *bolt.Tx) error {
		v := tx.Bucket(bucketMeta).Get(metaPassword)
		if v == nil {
			return nil
		}
		rec = &passwordRecord{}
		return json.Unmarshal(v, rec)
	})
	return rec, err
}

func (s *Store) HasPassword() (bool, error) {
	rec, err := s.loadPassword()
	return rec != nil, err
}

// CheckPassword returns ErrNoPassword, ErrWrongPassword, or nil.
func (s *Store) CheckPassword(pw string) error {
	rec, err := s.loadPassword()
	if err != nil {
		return err
	}
	if rec == nil {
		return ErrNoPassword
	}
	got, err := pbkdf2.Key(sha256.New, pw, rec.Salt, rec.Iter, len(rec.Hash))
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(got, rec.Hash) != 1 {
		return ErrWrongPassword
	}
	return nil
}

// SetPassword sets the owner password. Changing an existing password needs
// the old one, so a token holder cannot replace it.
func (s *Store) SetPassword(old, pw string) error {
	if len(pw) < 8 {
		return errors.New("the password must be at least 8 characters")
	}
	has, err := s.HasPassword()
	if err != nil {
		return err
	}
	if has {
		if err := s.CheckPassword(old); err != nil {
			return err
		}
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	hash, err := pbkdf2.Key(sha256.New, pw, salt, pbkdf2Iter, 32)
	if err != nil {
		return err
	}
	blob, err := json.Marshal(passwordRecord{Salt: salt, Hash: hash, Iter: pbkdf2Iter})
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketMeta).Put(metaPassword, blob)
	})
}

// ClearPassword removes the owner password. It is an offline recovery path,
// like ResetAdmin.
func (s *Store) ClearPassword() error {
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketMeta).Delete(metaPassword)
	})
}

// guard locks out password guesses: 5 wrong tries lock reveals for 15
// minutes, so an agent cannot brute-force the password through the API.
type guard struct {
	mu     sync.Mutex
	fails  int
	locked time.Time
}

const (
	guardMaxFails = 5
	guardLockFor  = 15 * time.Minute
)

func (g *guard) check(st *Store, pw string) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if time.Now().Before(g.locked) {
		return ErrLocked
	}
	err := st.CheckPassword(pw)
	if errors.Is(err, ErrWrongPassword) {
		g.fails++
		if g.fails >= guardMaxFails {
			g.fails = 0
			g.locked = time.Now().Add(guardLockFor)
		}
		return err
	}
	if err == nil {
		g.fails = 0
	}
	return err
}
