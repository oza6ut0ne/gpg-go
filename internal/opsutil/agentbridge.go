package opsutil

import (
	"crypto/rsa"
	"fmt"
	"math/big"

	openpgp "github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/ecdh"
	"github.com/ProtonMail/go-crypto/openpgp/eddsa"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	pgpcrypto "github.com/ProtonMail/gopenpgp/v2/crypto"
	"github.com/oza6ut0ne/gpg-go/internal/keygrip"
)

// SecretParams holds the raw private key parameters recovered from a
// gpg-agent private-keys-v1.d entry: D alone for ECC (EdDSA/ECDH), or
// D, P and Q for RSA (U/Qinv is recomputed).
type SecretParams struct {
	D, P, Q []byte
}

// SecretLookup resolves a keygrip (uppercase hex, 40 chars) to its
// decrypted secret parameters.
type SecretLookup func(keygripHex string) (*SecretParams, bool)

// AttachSecretKeys returns a copy of pub (a public-only *crypto.Key, as
// parsed from a keybox) with as much private key material attached as
// lookup can supply for its primary key and subkeys. attached reports
// whether any private material was found at all.
func AttachSecretKeys(pub *pgpcrypto.Key, lookup SecretLookup) (result *pgpcrypto.Key, attached bool, err error) {
	src := pub.GetEntity()

	cp := *src
	e := &cp
	e.Subkeys = make([]openpgp.Subkey, len(src.Subkeys))
	copy(e.Subkeys, src.Subkeys)

	if priv, ok, aerr := attachOne(src.PrimaryKey, true, lookup); aerr != nil {
		return nil, false, aerr
	} else if ok {
		e.PrivateKey = priv
		attached = true
	}

	for i := range e.Subkeys {
		if priv, ok, aerr := attachOne(e.Subkeys[i].PublicKey, false, lookup); aerr != nil {
			return nil, false, aerr
		} else if ok {
			e.Subkeys[i].PrivateKey = priv
			attached = true
		}
	}

	k, err := pgpcrypto.NewKeyFromEntity(e)
	if err != nil {
		return nil, false, err
	}
	return k, attached, nil
}

// attachOne builds a *packet.PrivateKey for a single public key packet if
// lookup has matching secret material for its keygrip, or (nil,false,nil)
// if the algorithm is unsupported or the secret is unavailable.
func attachOne(pk *packet.PublicKey, isPrimary bool, lookup SecretLookup) (*packet.PrivateKey, bool, error) {
	grip, ok := keygripOf(pk)
	if !ok {
		return nil, false, nil
	}
	secret, ok := lookup(keygrip.Hex(grip))
	if !ok {
		return nil, false, nil
	}

	var sk *packet.PrivateKey
	switch pub := pk.PublicKey.(type) {
	case *eddsa.PublicKey:
		if len(secret.D) == 0 {
			return nil, false, fmt.Errorf("agent key: missing d for EdDSA key")
		}
		priv := eddsa.NewPrivateKey(*pub)
		// Wire/agent-file secrets are big-endian ("MPI-like"); go-crypto's
		// in-memory D may use a curve-specific native format, so this
		// conversion is required even where it happens to be a no-op.
		if err := priv.UnmarshalByteSecret(secret.D); err != nil {
			return nil, false, fmt.Errorf("agent key: invalid EdDSA secret: %w", err)
		}
		// EdDSA is sign-only: go-crypto's NewDecrypterPrivateKey has no
		// case for *eddsa.PrivateKey (it panics on an "unknown decrypter
		// type") and would never be reachable at runtime anyway, since
		// EdDSA keys are never used to decrypt — this applies whether
		// the key is primary or (e.g. a dedicated signing) subkey.
		sk = packet.NewSignerPrivateKey(pk.CreationTime, priv)

	case *ecdh.PublicKey:
		if len(secret.D) == 0 {
			return nil, false, fmt.Errorf("agent key: missing d for ECDH key")
		}
		priv := ecdh.NewPrivateKey(*pub)
		// Curve25519's native (little-endian) in-memory form differs from
		// the big-endian wire/agent-file form; UnmarshalByteSecret byte-
		// reverses (and re-pads) to convert between the two.
		if err := priv.UnmarshalByteSecret(secret.D); err != nil {
			return nil, false, fmt.Errorf("agent key: invalid ECDH secret: %w", err)
		}
		sk = packet.NewDecrypterPrivateKey(pk.CreationTime, priv)

	case *rsa.PublicKey:
		if len(secret.D) == 0 || len(secret.P) == 0 || len(secret.Q) == 0 {
			return nil, false, fmt.Errorf("agent key: missing d/p/q for RSA key")
		}
		priv := &rsa.PrivateKey{
			PublicKey: *pub,
			D:         new(big.Int).SetBytes(secret.D),
			Primes: []*big.Int{
				new(big.Int).SetBytes(secret.P),
				new(big.Int).SetBytes(secret.Q),
			},
		}
		priv.Precompute()
		if isPrimary {
			sk = packet.NewSignerPrivateKey(pk.CreationTime, priv)
		} else {
			sk = packet.NewDecrypterPrivateKey(pk.CreationTime, priv)
		}

	default:
		return nil, false, nil
	}

	// NewSigner/DecrypterPrivateKey build a fresh embedded PublicKey from
	// scratch and have no way to know it should be marked as a subkey;
	// without this, serializing the resulting entity emits a bogus
	// second *primary* secret key packet instead of a secret subkey
	// packet for every subkey.
	sk.PublicKey.IsSubkey = pk.IsSubkey
	return sk, true, nil
}

// keygripOf computes the gpg-agent keygrip for a public key packet, or
// ok=false if the algorithm/curve is not one we know how to grip.
func keygripOf(pk *packet.PublicKey) (grip [20]byte, ok bool) {
	switch pub := pk.PublicKey.(type) {
	case *eddsa.PublicKey:
		if pub.GetCurve().GetCurveName() != "ed25519" {
			return grip, false
		}
		return keygrip.EdDSA25519(pub.MarshalPoint()), true
	case *ecdh.PublicKey:
		if pub.GetCurve().GetCurveName() != "curve25519" {
			return grip, false
		}
		return keygrip.ECDH25519(pub.MarshalPoint()), true
	case *rsa.PublicKey:
		return keygrip.RSA(pub.N.Bytes()), true
	default:
		return grip, false
	}
}

// KeygripForPublicKey exposes keygripOf for callers (e.g. the keystore)
// that need to match a parsed public key against a private-keys-v1.d
// filename without necessarily attaching secret material.
func KeygripForPublicKey(pk *packet.PublicKey) (string, bool) {
	grip, ok := keygripOf(pk)
	if !ok {
		return "", false
	}
	return keygrip.Hex(grip), true
}
