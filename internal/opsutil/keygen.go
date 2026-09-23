package opsutil

import (
	"crypto"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	openpgp "github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	pgpcrypto "github.com/ProtonMail/gopenpgp/v2/crypto"
)

// userIDPattern parses a gpg-style "Name (Comment) <email>" user ID, with
// every part optional.
var userIDPattern = regexp.MustCompile(`^\s*([^(<]*?)\s*(?:\(([^)]*)\))?\s*(?:<([^>]*)>)?\s*$`)

// ParseUserID splits a user ID string into name, comment and email.
func ParseUserID(uid string) (name, comment, email string) {
	m := userIDPattern.FindStringSubmatch(uid)
	if m == nil {
		return strings.TrimSpace(uid), "", ""
	}
	return strings.TrimSpace(m[1]), strings.TrimSpace(m[2]), strings.TrimSpace(m[3])
}

// NormalizeAlgo maps gpg-style algorithm names to a (keyType, bits) pair.
// keyType is either "rsa" or "ed25519" (Ed25519 signing key + Curve25519
// encryption subkey, gpg's current default).
func NormalizeAlgo(algo string) (keyType string, bits int, err error) {
	switch strings.ToLower(algo) {
	case "", "default", "future-default", "ed25519", "cv25519", "ed25519/cv25519":
		return "ed25519", 0, nil
	case "rsa", "rsa3072":
		return "rsa", 3072, nil
	case "rsa2048":
		return "rsa", 2048, nil
	case "rsa4096":
		return "rsa", 4096, nil
	default:
		if strings.HasPrefix(strings.ToLower(algo), "rsa") {
			if n, err2 := strconv.Atoi(algo[3:]); err2 == nil {
				return "rsa", n, nil
			}
		}
		return "", 0, fmt.Errorf("unsupported algorithm %q (supported: default, ed25519, rsa2048, rsa3072, rsa4096)", algo)
	}
}

// ParseExpire converts a gpg-style expiration spec (0, "1y", "6m", "30d", or
// a raw number of days) into a duration in seconds. 0 means "never expire".
func ParseExpire(spec string) (uint32, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" || spec == "0" {
		return 0, nil
	}
	unit := spec[len(spec)-1]
	var mult int64
	numPart := spec
	switch unit {
	case 'd', 'D':
		mult = 86400
		numPart = spec[:len(spec)-1]
	case 'w', 'W':
		mult = 86400 * 7
		numPart = spec[:len(spec)-1]
	case 'm', 'M':
		mult = 86400 * 30
		numPart = spec[:len(spec)-1]
	case 'y', 'Y':
		mult = 86400 * 365
		numPart = spec[:len(spec)-1]
	default:
		mult = 86400 // bare number = days, as in gpg
	}
	n, err := strconv.ParseInt(numPart, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid expiration %q: %w", spec, err)
	}
	return uint32(n * mult), nil
}

// GenerateKey creates a new key pair and returns the unlocked private Key.
// expireSecs of 0 means the key never expires.
func GenerateKey(name, comment, email, algo string, bits int, expireSecs uint32) (*pgpcrypto.Key, error) {
	keyType, defaultBits, err := NormalizeAlgo(algo)
	if err != nil {
		return nil, err
	}
	if bits == 0 {
		bits = defaultBits
	}

	cfg := &packet.Config{
		Time:                   func() time.Time { return time.Now() },
		DefaultHash:            crypto.SHA256,
		DefaultCipher:          packet.CipherAES256,
		DefaultCompressionAlgo: packet.CompressionZLIB,
		KeyLifetimeSecs:        expireSecs,
	}

	switch keyType {
	case "rsa":
		cfg.Algorithm = packet.PubKeyAlgoRSA
		cfg.RSABits = bits
	case "ed25519":
		cfg.Algorithm = packet.PubKeyAlgoEdDSA
	default:
		return nil, fmt.Errorf("unsupported key type %q", keyType)
	}

	entity, err := openpgp.NewEntity(name, comment, email, cfg)
	if err != nil {
		return nil, fmt.Errorf("generating key: %w", err)
	}
	if entity.PrivateKey == nil {
		return nil, fmt.Errorf("generating key: no private key produced")
	}

	return pgpcrypto.NewKeyFromEntity(entity)
}
