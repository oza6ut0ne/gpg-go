package opsutil

import (
	"crypto/rsa"
	"fmt"
	"math/big"

	"github.com/ProtonMail/go-crypto/openpgp/ecdh"
	"github.com/ProtonMail/go-crypto/openpgp/eddsa"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	pgpcrypto "github.com/ProtonMail/gopenpgp/v2/crypto"
	"github.com/oza6ut0ne/gpg-go/internal/agentkey"
	"github.com/oza6ut0ne/gpg-go/internal/keygrip"
)

// ExtractedComponent is one key or subkey's private material, ready to be
// protected (agentkey.Key.Protect) and written to private-keys-v1.d.
type ExtractedComponent struct {
	Fingerprint string // uppercase hex
	Keygrip     string // uppercase hex
	Key         *agentkey.Key
}

// ExtractPrivateComponents walks priv (which must be fully unlocked: every
// private key/subkey either unencrypted or already Decrypt()-ed) and
// returns one ExtractedComponent per component whose private material and
// keygrip this package knows how to handle (EdDSA/ECDH-Curve25519/RSA).
// Components using unsupported algorithms are silently skipped.
func ExtractPrivateComponents(priv *pgpcrypto.Key) ([]*ExtractedComponent, error) {
	if !priv.IsPrivate() {
		return nil, fmt.Errorf("agentkey: key has no private material")
	}
	e := priv.GetEntity()

	var out []*ExtractedComponent
	if e.PrivateKey != nil {
		c, err := extractComponent(e.PrimaryKey, e.PrivateKey)
		if err != nil {
			return nil, err
		}
		if c != nil {
			out = append(out, c)
		}
	}
	for _, sub := range e.Subkeys {
		if sub.PrivateKey == nil {
			continue
		}
		c, err := extractComponent(sub.PublicKey, sub.PrivateKey)
		if err != nil {
			return nil, err
		}
		if c != nil {
			out = append(out, c)
		}
	}
	return out, nil
}

func extractComponent(pub *packet.PublicKey, sk *packet.PrivateKey) (*ExtractedComponent, error) {
	if sk.Encrypted {
		return nil, fmt.Errorf("agentkey: private key material is still locked")
	}
	if sk.Dummy() {
		return nil, nil
	}

	grip, ok := keygripOf(pub)
	if !ok {
		return nil, nil
	}
	fpr := fmt.Sprintf("%X", pub.Fingerprint)

	switch priv := sk.PrivateKey.(type) {
	case *eddsa.PrivateKey:
		clear := []agentkey.Param{
			{Name: "curve", Value: []byte("Ed25519")},
			{Name: "flags", Value: []byte("eddsa")},
			{Name: "q", Value: priv.PublicKey.MarshalPoint()},
		}
		secret := []agentkey.Param{{Name: "d", Value: priv.MarshalByteSecret()}}
		return &ExtractedComponent{
			Fingerprint: fpr,
			Keygrip:     keygrip.Hex(grip),
			Key:         agentkey.BuildUnprotected("ecc", clear, secret),
		}, nil

	case *ecdh.PrivateKey:
		clear := []agentkey.Param{
			{Name: "curve", Value: []byte("Curve25519")},
			{Name: "flags", Value: []byte("djb-tweak")},
			{Name: "q", Value: priv.PublicKey.MarshalPoint()},
		}
		secret := []agentkey.Param{{Name: "d", Value: priv.MarshalByteSecret()}}
		return &ExtractedComponent{
			Fingerprint: fpr,
			Keygrip:     keygrip.Hex(grip),
			Key:         agentkey.BuildUnprotected("ecc", clear, secret),
		}, nil

	case *rsa.PrivateKey:
		priv.Precompute()
		clear := []agentkey.Param{
			{Name: "n", Value: keygrip.StdBytes(priv.PublicKey.N.Bytes())},
			{Name: "e", Value: keygrip.StdBytes(big.NewInt(int64(priv.PublicKey.E)).Bytes())},
		}
		secret := []agentkey.Param{
			{Name: "d", Value: keygrip.StdBytes(priv.D.Bytes())},
			{Name: "p", Value: keygrip.StdBytes(priv.Primes[0].Bytes())},
			{Name: "q", Value: keygrip.StdBytes(priv.Primes[1].Bytes())},
			{Name: "u", Value: keygrip.StdBytes(priv.Precomputed.Qinv.Bytes())},
		}
		return &ExtractedComponent{
			Fingerprint: fpr,
			Keygrip:     keygrip.Hex(grip),
			Key:         agentkey.BuildUnprotected("rsa", clear, secret),
		}, nil

	default:
		return nil, nil
	}
}
