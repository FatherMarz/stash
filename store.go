package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	bolt "go.etcd.io/bbolt"
)

var (
	bucketSecrets = []byte("secrets")
	bucketTokens  = []byte("tokens")
	bucketAudit   = []byte("audit")
	bucketRoutes  = []byte("routes")
)

var ErrNotFound = errors.New("not found")

var nameRe = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,199}$`)

// Token is an API credential. Only its SHA-256 hash is stored.
type Token struct {
	Name    string    `json:"name"`
	Role    string    `json:"role"` // "proxy", "ro", "rw", or "admin"
	Created time.Time `json:"created"`
}

// Route forwards agent requests to an upstream API with the real secret
// injected as a header. Agents with a "proxy" token can use routes but can
// never read the secret itself.
type Route struct {
	Name     string    `json:"name"`
	Upstream string    `json:"upstream"` // e.g. https://api.openai.com
	Secret   string    `json:"secret"`   // name of the secret to inject
	Header   string    `json:"header"`   // e.g. "Authorization: Bearer {value}"
	Created  time.Time `json:"created"`
}

type AuditEntry struct {
	Time   time.Time `json:"time"`
	Token  string    `json:"token"`
	Action string    `json:"action"`
	Secret string    `json:"secret,omitempty"`
}

type Store struct {
	db   *bolt.DB
	aead cipher.AEAD
}

// OpenStore opens (or creates) the database and encryption key in dir.
func OpenStore(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	key, err := loadKey(dir)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	db, err := bolt.Open(filepath.Join(dir, "stash.db"), 0o600, &bolt.Options{Timeout: 2 * time.Second})
	if err != nil {
		return nil, err
	}
	err = db.Update(func(tx *bolt.Tx) error {
		for _, b := range [][]byte{bucketSecrets, bucketTokens, bucketAudit, bucketRoutes} {
			if _, err := tx.CreateBucketIfNotExists(b); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		db.Close()
		return nil, err
	}
	return &Store{db: db, aead: aead}, nil
}

func (s *Store) Close() error { return s.db.Close() }

// loadKey returns the 32-byte master key. Priority: STASH_MASTER_KEY env
// var, then the stash.key file. If neither exists, a new key is generated
// and written to stash.key with mode 0600.
func loadKey(dir string) ([]byte, error) {
	if h := os.Getenv("STASH_MASTER_KEY"); h != "" {
		key, err := hex.DecodeString(strings.TrimSpace(h))
		if err != nil || len(key) != 32 {
			return nil, errors.New("STASH_MASTER_KEY must be 64 hex characters")
		}
		return key, nil
	}
	path := filepath.Join(dir, "stash.key")
	if b, err := os.ReadFile(path); err == nil {
		key, err := hex.DecodeString(strings.TrimSpace(string(b)))
		if err != nil || len(key) != 32 {
			return nil, fmt.Errorf("key file %s is not 64 hex characters", path)
		}
		return key, nil
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, []byte(hex.EncodeToString(key)+"\n"), 0o600); err != nil {
		return nil, err
	}
	return key, nil
}

// encrypt seals plain with AES-256-GCM. Output layout: nonce || ciphertext.
func (s *Store) encrypt(plain []byte) ([]byte, error) {
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return s.aead.Seal(nonce, nonce, plain, nil), nil
}

func (s *Store) decrypt(blob []byte) ([]byte, error) {
	n := s.aead.NonceSize()
	if len(blob) < n {
		return nil, errors.New("stored value is corrupt")
	}
	return s.aead.Open(nil, blob[:n], blob[n:], nil)
}

func validName(name string) error {
	if !nameRe.MatchString(name) {
		return errors.New("name must match [A-Za-z0-9_.-], start with a letter, digit, or underscore, and be at most 200 characters")
	}
	return nil
}

func (s *Store) Set(name, value string) error {
	if err := validName(name); err != nil {
		return err
	}
	blob, err := s.encrypt([]byte(value))
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketSecrets).Put([]byte(name), blob)
	})
}

func (s *Store) Get(name string) (string, error) {
	var blob []byte
	err := s.db.View(func(tx *bolt.Tx) error {
		v := tx.Bucket(bucketSecrets).Get([]byte(name))
		if v == nil {
			return ErrNotFound
		}
		blob = append([]byte(nil), v...)
		return nil
	})
	if err != nil {
		return "", err
	}
	plain, err := s.decrypt(blob)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

func (s *Store) List() ([]string, error) {
	var names []string
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketSecrets).ForEach(func(k, _ []byte) error {
			names = append(names, string(k))
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(names)
	return names, nil
}

// All returns every secret, decrypted.
func (s *Store) All() (map[string]string, error) {
	blobs := map[string][]byte{}
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketSecrets).ForEach(func(k, v []byte) error {
			blobs[string(k)] = append([]byte(nil), v...)
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	out := make(map[string]string, len(blobs))
	for name, blob := range blobs {
		plain, err := s.decrypt(blob)
		if err != nil {
			return nil, fmt.Errorf("secret %s: %w", name, err)
		}
		out[name] = string(plain)
	}
	return out, nil
}

func (s *Store) Delete(name string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketSecrets)
		if b.Get([]byte(name)) == nil {
			return ErrNotFound
		}
		return b.Delete([]byte(name))
	})
}

func hashToken(plain string) []byte {
	sum := sha256.Sum256([]byte(plain))
	return []byte(hex.EncodeToString(sum[:]))
}

// NewToken creates a token and returns its plaintext form once.
func (s *Store) NewToken(name, role string) (string, error) {
	if err := validName(name); err != nil {
		return "", err
	}
	switch role {
	case "proxy", "ro", "rw", "admin":
	default:
		return "", errors.New(`role must be "proxy", "ro", "rw", or "admin"`)
	}
	raw := make([]byte, 24)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	plain := "stash_" + hex.EncodeToString(raw)
	rec, err := json.Marshal(Token{Name: name, Role: role, Created: time.Now().UTC()})
	if err != nil {
		return "", err
	}
	err = s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketTokens)
		var dup bool
		b.ForEach(func(_, v []byte) error {
			var t Token
			if json.Unmarshal(v, &t) == nil && t.Name == name {
				dup = true
			}
			return nil
		})
		if dup {
			return fmt.Errorf("a token named %q already exists", name)
		}
		return b.Put(hashToken(plain), rec)
	})
	if err != nil {
		return "", err
	}
	return plain, nil
}

func (s *Store) VerifyToken(plain string) (*Token, error) {
	var tok *Token
	err := s.db.View(func(tx *bolt.Tx) error {
		v := tx.Bucket(bucketTokens).Get(hashToken(plain))
		if v == nil {
			return ErrNotFound
		}
		var t Token
		if err := json.Unmarshal(v, &t); err != nil {
			return err
		}
		tok = &t
		return nil
	})
	return tok, err
}

func (s *Store) ListTokens() ([]Token, error) {
	var out []Token
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketTokens).ForEach(func(_, v []byte) error {
			var t Token
			if err := json.Unmarshal(v, &t); err != nil {
				return err
			}
			out = append(out, t)
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Created.Before(out[j].Created) })
	return out, nil
}

func (s *Store) RevokeToken(name string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketTokens)
		var key []byte
		b.ForEach(func(k, v []byte) error {
			var t Token
			if json.Unmarshal(v, &t) == nil && t.Name == name {
				key = append([]byte(nil), k...)
			}
			return nil
		})
		if key == nil {
			return ErrNotFound
		}
		return b.Delete(key)
	})
}

// EnsureAdmin creates the "admin" token on first run. It returns the
// plaintext token and true when it created one.
func (s *Store) EnsureAdmin() (string, bool, error) {
	toks, err := s.ListTokens()
	if err != nil {
		return "", false, err
	}
	for _, t := range toks {
		if t.Role == "admin" {
			return "", false, nil
		}
	}
	plain, err := s.NewToken("admin", "admin")
	if err != nil {
		return "", false, err
	}
	return plain, true, nil
}

// ResetAdmin revokes every admin token and creates a new one. It is an
// offline recovery path for a lost admin token.
func (s *Store) ResetAdmin() (string, error) {
	toks, err := s.ListTokens()
	if err != nil {
		return "", err
	}
	for _, t := range toks {
		if t.Role == "admin" {
			if err := s.RevokeToken(t.Name); err != nil {
				return "", err
			}
		}
	}
	return s.NewToken("admin", "admin")
}

// SetRoute creates or overwrites a proxy route.
func (s *Store) SetRoute(r Route) error {
	if err := validName(r.Name); err != nil {
		return err
	}
	u, err := url.Parse(r.Upstream)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return errors.New("upstream must be a full URL like https://api.openai.com")
	}
	if r.Header == "" {
		r.Header = "Authorization: Bearer {value}"
	}
	if !strings.Contains(r.Header, ":") || !strings.Contains(r.Header, "{value}") {
		return errors.New(`header must look like "Name: prefix {value}"`)
	}
	r.Created = time.Now().UTC()
	rec, err := json.Marshal(r)
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketRoutes).Put([]byte(r.Name), rec)
	})
}

func (s *Store) GetRoute(name string) (*Route, error) {
	var rt *Route
	err := s.db.View(func(tx *bolt.Tx) error {
		v := tx.Bucket(bucketRoutes).Get([]byte(name))
		if v == nil {
			return ErrNotFound
		}
		var r Route
		if err := json.Unmarshal(v, &r); err != nil {
			return err
		}
		rt = &r
		return nil
	})
	return rt, err
}

func (s *Store) ListRoutes() ([]Route, error) {
	var out []Route
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketRoutes).ForEach(func(_, v []byte) error {
			var r Route
			if err := json.Unmarshal(v, &r); err != nil {
				return err
			}
			out = append(out, r)
			return nil
		})
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (s *Store) DeleteRoute(name string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketRoutes)
		if b.Get([]byte(name)) == nil {
			return ErrNotFound
		}
		return b.Delete([]byte(name))
	})
}

func (s *Store) Audit(token, action, secret string) error {
	rec, err := json.Marshal(AuditEntry{Time: time.Now().UTC(), Token: token, Action: action, Secret: secret})
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketAudit)
		seq, err := b.NextSequence()
		if err != nil {
			return err
		}
		key := make([]byte, 8)
		binary.BigEndian.PutUint64(key, seq)
		return b.Put(key, rec)
	})
}

// AuditLog returns the newest entries first, at most limit of them.
func (s *Store) AuditLog(limit int) ([]AuditEntry, error) {
	if limit <= 0 {
		limit = 100
	}
	var out []AuditEntry
	err := s.db.View(func(tx *bolt.Tx) error {
		c := tx.Bucket(bucketAudit).Cursor()
		for k, v := c.Last(); k != nil && len(out) < limit; k, v = c.Prev() {
			var e AuditEntry
			if err := json.Unmarshal(v, &e); err != nil {
				return err
			}
			out = append(out, e)
		}
		return nil
	})
	return out, err
}
