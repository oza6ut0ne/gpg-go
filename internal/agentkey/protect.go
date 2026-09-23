// Package agentkey implements gpg-agent's private-keys-v1.d/*.key file
// format: an S-expression describing a private key, optionally protected
// (encrypted) with a passphrase using OpenPGP-style iterated+salted S2K
// key derivation and AES-128-OCB. The framing, AAD construction and
// protection modes here are reverse engineered from, and verified
// against, GnuPG's agent/protect.c.
package agentkey

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
	"fmt"
	"time"

	gocbmode "github.com/ProtonMail/go-crypto/ocb"
	"github.com/ProtonMail/go-crypto/openpgp/s2k"
	"github.com/oza6ut0ne/gpg-go/internal/sexp"
)

// ProtectMode identifies a private-keys-v1.d protection scheme.
type ProtectMode string

const (
	ModeOCBAES ProtectMode = "openpgp-s2k3-ocb-aes"
)

// defaultS2KCount is a fixed, "reasonably strong" iteration count for our
// own writes (gpg-agent calibrates this to ~100ms on the local machine;
// we use a fixed value instead since we cannot easily calibrate and any
// value >= 65536 is accepted by gpg-agent).
const defaultS2KCount = 10_000_000

// Key is a parsed (possibly still protected) private-keys-v1.d key.
type Key struct {
	Algo string // "ecc" or "rsa"

	// Clear (never encrypted) parameters, in on-disk order, as
	// (name value) pairs, e.g. ("curve","Ed25519"),("flags","eddsa"),("q",<point>).
	Clear []Param

	// Protected (secret) parameters, in on-disk order, e.g. ("d",<scalar>)
	// for ECC, or ("d",...),("p",...),("q",...),("u",...) for RSA. Populated
	// only once Unprotect has succeeded (or if the key was never protected).
	Secret []Param

	ProtectedAt string // 15-char ISO timestamp, if present

	// Set only while still protected (before a successful Unprotect):
	protectedMode  ProtectMode
	salt           []byte
	s2kCount       int
	nonce          []byte
	ciphertext     []byte
	protectedAtNod *sexp.Node
}

// Param is a single named S-expression parameter, e.g. (q #...#).
type Param struct {
	Name  string
	Value []byte
}

func paramNode(p Param) *sexp.Node {
	return sexp.L(sexp.S(p.Name), sexp.A(p.Value))
}

// algoPrefix returns the canonical-form opening of the algorithm list,
// e.g. "(3:ecc" for "ecc" — this is included in the AAD/MIC region by
// gpg-agent (calculate_mic's hash_begin points at the list's own opening
// paren, before the algorithm name is even parsed).
func algoPrefix(algo string) []byte {
	return []byte(fmt.Sprintf("(%d:%s", len(algo), algo))
}

// IsProtected reports whether the key still needs a passphrase to unlock.
func (k *Key) IsProtected() bool {
	return k.protectedMode != ""
}

// Find returns the value of the named parameter from Clear then Secret.
func (k *Key) Find(name string) []byte {
	for _, p := range k.Clear {
		if p.Name == name {
			return p.Value
		}
	}
	for _, p := range k.Secret {
		if p.Name == name {
			return p.Value
		}
	}
	return nil
}

// BuildUnprotected constructs a Key wrapping already-available clear and
// secret parameters (no protection).
func BuildUnprotected(algo string, clear, secret []Param) *Key {
	return &Key{Algo: algo, Clear: clear, Secret: secret}
}

// nowTimestamp returns the current time as gpg-agent's 15-char isotime
// (e.g. "20260923T002227").
func nowTimestamp() string {
	return time.Now().UTC().Format("20060102T150405")
}

// Protect encrypts the key's Secret parameters with passphrase, returning
// a new Key value whose Secret is cleared and which is ready to be
// serialized (via Node) as a protected-private-key.
func (k *Key) Protect(passphrase []byte) (*Key, error) {
	if len(passphrase) == 0 {
		return nil, fmt.Errorf("agentkey: empty passphrase")
	}
	if k.IsProtected() {
		return nil, fmt.Errorf("agentkey: key is already protected")
	}

	salt := make([]byte, 8)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	count := defaultS2KCount

	key := deriveKey(passphrase, salt, count)
	aead, err := newOCB(key)
	if err != nil {
		return nil, err
	}

	protectedAt := nowTimestamp()
	protectedAtNode := sexp.L(sexp.S("protected-at"), sexp.A([]byte(protectedAt)))

	var clearBytes []byte
	for _, p := range k.Clear {
		clearBytes = append(clearBytes, paramNode(p).Canonical()...)
	}
	var secretBytes []byte
	for _, p := range k.Secret {
		secretBytes = append(secretBytes, paramNode(p).Canonical()...)
	}

	aad := algoPrefix(k.Algo)
	aad = append(aad, clearBytes...)
	aad = append(aad, protectedAtNode.Canonical()...)
	aad = append(aad, ')')

	plaintext := append([]byte("(("), secretBytes...)
	plaintext = append(plaintext, ')', ')')

	ciphertext := aead.Seal(nil, nonce, plaintext, aad)

	out := &Key{
		Algo:        k.Algo,
		Clear:       k.Clear,
		ProtectedAt: protectedAt,
	}
	out.protectedMode = ModeOCBAES
	out.salt = salt
	out.s2kCount = count
	out.nonce = nonce
	out.ciphertext = ciphertext
	return out, nil
}

// Unprotect decrypts the key's protected parameters with passphrase,
// returning a new Key with Secret populated (and no longer protected).
func (k *Key) Unprotect(passphrase []byte) (*Key, error) {
	if !k.IsProtected() {
		return nil, fmt.Errorf("agentkey: key is not protected")
	}
	if k.protectedMode != ModeOCBAES {
		return nil, fmt.Errorf("agentkey: unsupported protection mode %q", k.protectedMode)
	}
	if len(passphrase) == 0 {
		return nil, fmt.Errorf("agentkey: empty passphrase")
	}

	key := deriveKey(passphrase, k.salt, k.s2kCount)
	aead, err := newOCB(key)
	if err != nil {
		return nil, err
	}

	var clearBytes []byte
	for _, p := range k.Clear {
		clearBytes = append(clearBytes, paramNode(p).Canonical()...)
	}
	aad := algoPrefix(k.Algo)
	aad = append(aad, clearBytes...)
	if k.protectedAtNod != nil {
		aad = append(aad, k.protectedAtNod.Canonical()...)
	}
	aad = append(aad, ')')

	plaintext, err := aead.Open(nil, k.nonce, k.ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("agentkey: bad passphrase or corrupted key: %w", err)
	}
	// plaintext is "((<params>))"; strip the two leading and two trailing
	// parens to get back the concatenated protected param list bytes.
	if len(plaintext) < 4 || plaintext[0] != '(' || plaintext[1] != '(' ||
		plaintext[len(plaintext)-1] != ')' || plaintext[len(plaintext)-2] != ')' {
		return nil, fmt.Errorf("agentkey: unexpected plaintext framing")
	}
	inner := plaintext[2 : len(plaintext)-2]

	secretParams, err := parseParamList(inner)
	if err != nil {
		return nil, fmt.Errorf("agentkey: parsing decrypted parameters: %w", err)
	}

	return &Key{
		Algo:        k.Algo,
		Clear:       k.Clear,
		Secret:      secretParams,
		ProtectedAt: k.ProtectedAt,
	}, nil
}

// parseParamList parses a concatenated run of canonical "(name value)"
// lists back into Params.
func parseParamList(data []byte) ([]Param, error) {
	var out []Param
	for len(data) > 0 {
		n, rest, err := sexp.Parse(data)
		if err != nil {
			return nil, err
		}
		if !n.IsList() || n.Len() != 2 || !n.Get(0).IsAtom() || !n.Get(1).IsAtom() {
			return nil, fmt.Errorf("unexpected parameter shape")
		}
		out = append(out, Param{Name: n.Get(0).Str(), Value: n.Get(1).Atom})
		data = rest
	}
	return out, nil
}

func deriveKey(passphrase, salt []byte, count int) []byte {
	out := make([]byte, 16) // AES-128
	s2k.Iterated(out, sha1.New(), passphrase, salt, count)
	return out
}

func newOCB(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return gocbmode.NewOCBWithNonceAndTagSize(block, 12, 16)
}
