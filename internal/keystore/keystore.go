// Package keystore implements an on-disk keyring compatible with real
// GnuPG's on-disk layout: public keys in a "keybox" (pubring.kbx) file
// and private key material in private-keys-v1.d/*.key files, keyed by
// keygrip and optionally passphrase-protected exactly as gpg-agent
// itself would store them (see internal/kbx and internal/agentkey).
package keystore

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/ProtonMail/gopenpgp/v2/crypto"
	"github.com/oza6ut0ne/gpg-go/internal/agentkey"
	"github.com/oza6ut0ne/gpg-go/internal/kbx"
	"github.com/oza6ut0ne/gpg-go/internal/opsutil"
)

// Store holds the loaded public keybox and tracks the private-keys-v1.d
// directory for a home directory.
type Store struct {
	dir     string
	kbxPath string
	privDir string

	blobs []*kbx.Blob
	pub   []*crypto.Key
}

// Open loads (or initializes empty) a keybox from dir.
func Open(dir string) (*Store, error) {
	s := &Store{
		dir:     dir,
		kbxPath: filepath.Join(dir, "pubring.kbx"),
		privDir: filepath.Join(dir, "private-keys-v1.d"),
	}
	if err := s.Reload(); err != nil {
		return nil, err
	}
	return s, nil
}

// Reload re-reads the keybox file from disk.
func (s *Store) Reload() error {
	blobs, err := kbx.ReadFile(s.kbxPath)
	if err != nil {
		return fmt.Errorf("loading %s: %w", s.kbxPath, err)
	}
	s.blobs = blobs
	s.rebuildPub()
	return nil
}

// rebuildPub re-derives s.pub from s.blobs. A blob that fails to parse
// (a handful of real-world keys, once past sanitizeKeyblock's fallback,
// still contain data go-crypto's strict parser rejects) is skipped with
// a warning rather than aborting every operation on the whole keyring.
func (s *Store) rebuildPub() {
	s.pub = nil
	for _, b := range s.blobs {
		if b.Type != kbx.BlobTypeOpenPGP {
			continue
		}
		keys, err := ParseKeys(b.Keyblock)
		if err != nil {
			fpr := "unknown"
			if len(b.Fingerprints) > 0 {
				fpr = fmt.Sprintf("%X", b.Fingerprints[0])
			}
			fmt.Fprintf(os.Stderr, "gpg-go: warning: skipping unparsable key %s: %v\n", fpr, err)
			continue
		}
		s.pub = append(s.pub, keys...)
	}
}

// SavePublic writes the current keybox to disk.
func (s *Store) SavePublic() error {
	return kbx.WriteFile(s.kbxPath, s.blobs)
}

// SaveSecret is a no-op: private-keys-v1.d entries are written
// immediately by AddSecretKey/DeleteSecretKey, matching gpg-agent's own
// behavior of never batching secret key writes.
func (s *Store) SaveSecret() error { return nil }

// PublicKeys returns all public keys in the store.
func (s *Store) PublicKeys() []*crypto.Key { return s.pub }

// SecretKeys returns the public keys in the store that have at least one
// matching private-keys-v1.d entry (primary or subkey). The returned
// *crypto.Key values are public-only stand-ins for identification and
// listing; use AttachSecret to actually unlock private material.
func (s *Store) SecretKeys() []*crypto.Key {
	var out []*crypto.Key
	for _, k := range s.pub {
		grips, err := s.keygripsFor(k)
		if err != nil {
			continue
		}
		for _, g := range grips {
			if _, err := os.Stat(filepath.Join(s.privDir, g+".key")); err == nil {
				out = append(out, k)
				break
			}
		}
	}
	return out
}

// AddPublic merges k's public key material into the keybox, replacing
// any existing entry with the same primary fingerprint. Returns true if
// the key is new.
func (s *Store) AddPublic(k *crypto.Key) (bool, error) {
	pubOnly := k
	if k.IsPrivate() {
		var err error
		pubOnly, err = k.ToPublic()
		if err != nil {
			return false, err
		}
	}
	keyblock, err := pubOnly.GetPublicKey()
	if err != nil {
		return false, err
	}
	blob, err := kbx.NewOpenPGPBlob(keyblock)
	if err != nil {
		return false, fmt.Errorf("building keybox entry: %w", err)
	}

	fpr := pubOnly.GetFingerprint()
	for i, b := range s.blobs {
		if b.Type == kbx.BlobTypeOpenPGP && len(b.Fingerprints) > 0 &&
			strings.EqualFold(fmt.Sprintf("%x", b.Fingerprints[0]), fpr) {
			s.blobs[i] = blob
			s.rebuildPub()
			return false, nil
		}
	}
	s.blobs = append(s.blobs, blob)
	s.rebuildPub()
	return true, nil
}

// DeletePublic removes the public key with the given fingerprint.
func (s *Store) DeletePublic(fpr string) bool {
	for i, b := range s.blobs {
		if b.Type == kbx.BlobTypeOpenPGP && len(b.Fingerprints) > 0 &&
			strings.EqualFold(fmt.Sprintf("%x", b.Fingerprints[0]), fpr) {
			s.blobs = append(s.blobs[:i], s.blobs[i+1:]...)
			s.rebuildPub()
			return true
		}
	}
	return false
}

// keygripsFor returns the keygrip (uppercase hex) of pub's primary key
// and every subkey whose algorithm/curve this tool supports.
func (s *Store) keygripsFor(pub *crypto.Key) ([]string, error) {
	e := pub.GetEntity()
	var out []string
	if grip, ok := opsutil.KeygripForPublicKey(e.PrimaryKey); ok {
		out = append(out, grip)
	}
	for _, sub := range e.Subkeys {
		if grip, ok := opsutil.KeygripForPublicKey(sub.PublicKey); ok {
			out = append(out, grip)
		}
	}
	return out, nil
}

// AddSecretKey extracts priv's private key components (primary and
// subkeys), protects each with passphrase (nil/empty leaves them
// unprotected, as gpg does for "%no-protection" batch key generation),
// writes them to private-keys-v1.d, and ensures the public part is
// present in the keybox too.
func (s *Store) AddSecretKey(priv *crypto.Key, passphrase []byte) error {
	if _, err := s.AddPublic(priv); err != nil {
		return err
	}
	components, err := opsutil.ExtractPrivateComponents(priv)
	if err != nil {
		return err
	}
	if len(components) == 0 {
		return fmt.Errorf("no private key material found (unsupported algorithm?)")
	}
	if err := os.MkdirAll(s.privDir, 0o700); err != nil {
		return err
	}
	for _, c := range components {
		out := c.Key
		if len(passphrase) > 0 {
			out, err = c.Key.Protect(passphrase)
			if err != nil {
				return fmt.Errorf("protecting %s: %w", c.Keygrip, err)
			}
		}
		if err := agentkey.WriteFile(filepath.Join(s.privDir, c.Keygrip+".key"), out); err != nil {
			return err
		}
	}
	return nil
}

// DeleteSecretKey removes every private-keys-v1.d entry belonging to
// pub. Returns true if anything was removed.
func (s *Store) DeleteSecretKey(pub *crypto.Key) (bool, error) {
	grips, err := s.keygripsFor(pub)
	if err != nil {
		return false, err
	}
	removed := false
	for _, g := range grips {
		err := os.Remove(filepath.Join(s.privDir, g+".key"))
		if err == nil {
			removed = true
		} else if !os.IsNotExist(err) {
			return removed, err
		}
	}
	return removed, nil
}

// SecretIsProtected reports whether any private-keys-v1.d entry
// belonging to pub is passphrase-protected.
func (s *Store) SecretIsProtected(pub *crypto.Key) (bool, error) {
	grips, err := s.keygripsFor(pub)
	if err != nil {
		return false, err
	}
	for _, g := range grips {
		k, err := agentkey.ReadFile(filepath.Join(s.privDir, g+".key"))
		if err != nil {
			continue
		}
		if k.IsProtected() {
			return true, nil
		}
	}
	return false, nil
}

// AttachSecret returns a copy of pub with as much private key material
// as private-keys-v1.d holds for it attached and (if necessary) unlocked
// with passphrase.
func (s *Store) AttachSecret(pub *crypto.Key, passphrase []byte) (*crypto.Key, error) {
	badPassphrase := false

	lookup := func(gripHex string) (*opsutil.SecretParams, bool) {
		k, err := agentkey.ReadFile(filepath.Join(s.privDir, gripHex+".key"))
		if err != nil {
			return nil, false
		}
		if k.IsProtected() {
			if len(passphrase) == 0 {
				return nil, false
			}
			unlocked, err := k.Unprotect(passphrase)
			if err != nil {
				badPassphrase = true
				return nil, false
			}
			k = unlocked
		}
		return &opsutil.SecretParams{D: k.Find("d"), P: k.Find("p"), Q: k.Find("q")}, true
	}

	result, attached, err := opsutil.AttachSecretKeys(pub, lookup)
	if err != nil {
		return nil, err
	}
	if !attached {
		if badPassphrase {
			return nil, fmt.Errorf("wrong passphrase")
		}
		return nil, fmt.Errorf("no private key material available")
	}
	return result, nil
}

// Find returns the keys (from pub or sec) matching a gpg-style user-id
// query: a fingerprint / long or short key ID (optionally "0x"-prefixed),
// or a case-insensitive substring of the name/email.
func Find(keys []*crypto.Key, query string) []*crypto.Key {
	if query == "" {
		return keys
	}
	norm := strings.ToLower(strings.TrimPrefix(strings.ToLower(query), "0x"))
	norm = strings.ReplaceAll(norm, " ", "")
	if isHex(norm) && (len(norm) == 40 || len(norm) == 16 || len(norm) == 8) {
		var out []*crypto.Key
		for _, k := range keys {
			for _, fpr := range allFingerprints(k) {
				if strings.HasSuffix(strings.ToLower(fpr), norm) {
					out = append(out, k)
					break
				}
			}
		}
		return out
	}

	needle := strings.ToLower(query)
	var out []*crypto.Key
	for _, k := range keys {
		for _, id := range identities(k) {
			if strings.Contains(strings.ToLower(id), needle) {
				out = append(out, k)
				break
			}
		}
	}
	return out
}

func isHex(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return false
		}
	}
	return true
}

// allFingerprints returns the hex fingerprint of the primary key and of
// every subkey, so lookups by (sub)key ID also find the owning entity.
func allFingerprints(k *crypto.Key) []string {
	e := k.GetEntity()
	out := []string{k.GetFingerprint()}
	for _, sub := range e.Subkeys {
		out = append(out, fmt.Sprintf("%x", sub.PublicKey.Fingerprint))
	}
	return out
}

// identities returns "Name <email>" strings for a key's user IDs.
func identities(k *crypto.Key) []string {
	e := k.GetEntity()
	var out []string
	for _, id := range e.Identities {
		out = append(out, id.Name)
	}
	return out
}
