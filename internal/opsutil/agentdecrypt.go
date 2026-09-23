package opsutil

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/ProtonMail/go-crypto/openpgp/aes/keywrap"
	"github.com/ProtonMail/go-crypto/openpgp/ecdh"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	pgpcrypto "github.com/ProtonMail/gopenpgp/v2/crypto"
	"github.com/oza6ut0ne/gpg-go/internal/gpgagent"
	"github.com/oza6ut0ne/gpg-go/internal/pgppacket"
	"github.com/oza6ut0ne/gpg-go/internal/sexp"
)

// curve25519OIDField is the OpenPGP curve-OID field (1-byte length
// prefix + DER content octets, no ASN.1 tag) for Curve25519
// (1.3.6.1.4.1.3029.1.5.1) — the only ECDH curve this tool generates.
var curve25519OIDField = []byte{0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01}

// pkeskRSAOrECDH holds the algorithm-specific data of a Public-Key
// Encrypted Session Key packet (RFC 4880 §5.1) needed to ask gpg-agent
// to decrypt it: for ECDH, the ephemeral point and the wrapped session
// key; for RSA, the encrypted session-key integer.
type pkesk struct {
	keyID uint64
	algo  uint8
	// ECDH
	ephemeralPoint []byte
	wrappedKey     []byte
	// RSA
	encryptedInt []byte
}

// ErrPKESKNotFound means message has no Public-Key Encrypted Session Key
// packet addressed to the given key ID — i.e. this particular key isn't
// one of the message's (non-hidden) recipients, as distinct from a real
// decryption failure. Callers trying several candidate keys in turn
// should treat this as "try the next one", not a fatal error.
var ErrPKESKNotFound = errors.New("gpgagent: no matching public-key encrypted session key packet found")

// findPKESK locates the Public-Key Encrypted Session Key packet (tag 1)
// in message addressed to keyID and returns its parsed fields.
func findPKESK(message []byte, keyID uint64) (*pkesk, error) {
	packets, err := pgppacket.Walk(message)
	if err != nil {
		return nil, err
	}
	for _, p := range packets {
		if p.Tag != 1 {
			continue
		}
		if len(p.Body) < 10 {
			continue
		}
		id := beUint64(p.Body[1:9])
		if id != keyID {
			continue
		}
		algo := p.Body[9]
		rest := p.Body[10:]
		switch algo {
		case 18: // ECDH
			point, tail, err := readMPIBytes(rest)
			if err != nil {
				return nil, err
			}
			wrapped, err := readOIDStyleBytes(tail)
			if err != nil {
				return nil, err
			}
			return &pkesk{keyID: id, algo: algo, ephemeralPoint: point, wrappedKey: wrapped}, nil
		case 1, 2, 3: // RSA (encrypt-only/sign-only share the same MPI shape)
			mpi, _, err := readMPIBytes(rest)
			if err != nil {
				return nil, err
			}
			return &pkesk{keyID: id, algo: algo, encryptedInt: mpi}, nil
		default:
			return nil, fmt.Errorf("gpgagent: unsupported PKESK algorithm %d", algo)
		}
	}
	return nil, ErrPKESKNotFound
}

// findWildcardPKESKs locates every Public-Key Encrypted Session Key
// packet (tag 1) in message addressed to the OpenPGP wildcard key ID
// (all zero bytes) — used for a hidden/anonymous recipient (gpg's -R),
// whose real key ID is deliberately withheld. A message can have several
// of these (one per hidden recipient), and since none of them say which
// key they're for, the only way to find a match is to try each
// candidate key against each one.
func findWildcardPKESKs(message []byte) ([]*pkesk, error) {
	packets, err := pgppacket.Walk(message)
	if err != nil {
		return nil, err
	}
	var out []*pkesk
	for _, p := range packets {
		if p.Tag != 1 || len(p.Body) < 10 {
			continue
		}
		if beUint64(p.Body[1:9]) != 0 {
			continue
		}
		algo := p.Body[9]
		rest := p.Body[10:]
		switch algo {
		case 18: // ECDH
			point, tail, err := readMPIBytes(rest)
			if err != nil {
				return nil, err
			}
			wrapped, err := readOIDStyleBytes(tail)
			if err != nil {
				return nil, err
			}
			out = append(out, &pkesk{keyID: 0, algo: algo, ephemeralPoint: point, wrappedKey: wrapped})
		case 1, 2, 3: // RSA
			mpi, _, err := readMPIBytes(rest)
			if err != nil {
				return nil, err
			}
			out = append(out, &pkesk{keyID: 0, algo: algo, encryptedInt: mpi})
		default:
			// Skip an unsupported algorithm rather than failing the
			// whole scan — another wildcard PKESK in the message might
			// still be usable.
			continue
		}
	}
	return out, nil
}

func beUint64(b []byte) uint64 {
	var v uint64
	for _, c := range b {
		v = v<<8 | uint64(c)
	}
	return v
}

// readMPIBytes reads a standard 2-byte-bitlength-prefixed OpenPGP MPI,
// returning its content bytes and the remaining input.
func readMPIBytes(b []byte) (content, rest []byte, err error) {
	if len(b) < 2 {
		return nil, nil, fmt.Errorf("gpgagent: truncated MPI")
	}
	bitLen := int(b[0])<<8 | int(b[1])
	byteLen := (bitLen + 7) / 8
	b = b[2:]
	if len(b) < byteLen {
		return nil, nil, fmt.Errorf("gpgagent: truncated MPI content")
	}
	return b[:byteLen], b[byteLen:], nil
}

// readOIDStyleBytes reads a 1-byte-length-prefixed field, as used for
// the wrapped session key half of an ECDH PKESK (go-crypto builds it via
// its "OID" encoding type, which is exactly this shape).
func readOIDStyleBytes(b []byte) ([]byte, error) {
	if len(b) < 1 {
		return nil, fmt.Errorf("gpgagent: truncated length-prefixed field")
	}
	n := int(b[0])
	b = b[1:]
	if len(b) < n {
		return nil, fmt.Errorf("gpgagent: truncated length-prefixed field content")
	}
	return b[:n], nil
}

// cipherAlgoNames maps RFC 4880 §9.2 symmetric algorithm numbers to the
// names gopenpgp.SessionKey.Algo expects.
var cipherAlgoNames = map[byte]string{
	2: "3des", 3: "cast5", 7: "aes128", 8: "aes192", 9: "aes256",
}

// AgentDecryptSupported reports whether AgentDecryptSessionKeyECDH knows
// how to decrypt with subPub's algorithm/curve (only Curve25519 ECDH is
// implemented; notably not RSA, which still falls back to this tool's
// own private-keys-v1.d handling).
func AgentDecryptSupported(subPub *packet.PublicKey) bool {
	ecdhPub, ok := subPub.PublicKey.(*ecdh.PublicKey)
	return ok && ecdhPub.GetCurve().GetCurveName() == "curve25519"
}

// errKeywrapFailed means the AES-key-wrap integrity check on an
// unwrapped session key failed (or its contents came out malformed,
// which for a genuine key basically never happens and so is treated the
// same way). For an exact key-ID match this indicates real corruption;
// when brute-forcing wildcard PKESKs it just means "not this key, try
// the next one" — cryptographically, a wrong key-encryption-key fails
// this check essentially certainly.
var errKeywrapFailed = errors.New("gpgagent: unwrapping session key failed (wrong key or corrupted message)")

// ecdhSubkeyPublicKey validates that subPub is a Curve25519 ECDH key,
// the only curve agent-based ECDH decryption supports here.
func ecdhSubkeyPublicKey(subPub *packet.PublicKey) (*ecdh.PublicKey, error) {
	ecdhPub, ok := subPub.PublicKey.(*ecdh.PublicKey)
	if !ok {
		return nil, fmt.Errorf("gpgagent: subkey is not an ECDH key")
	}
	if ecdhPub.GetCurve().GetCurveName() != "curve25519" {
		return nil, fmt.Errorf("gpgagent: agent-based ECDH decryption only supports Curve25519")
	}
	return ecdhPub, nil
}

// AgentDecryptSessionKeyECDH asks gpg-agent to perform the raw ECDH
// point multiplication for the Curve25519 subkey identified by keygrip
// (subPub is that subkey's own public key packet, needed for its
// fingerprint and KDF parameters), then completes the RFC 6637 KDF and
// AES-key-unwrap locally to recover the OpenPGP session key.
func AgentDecryptSessionKeyECDH(message []byte, subPub *packet.PublicKey, keygrip, keyDesc string, client *gpgagent.Client) (*pgpcrypto.SessionKey, error) {
	ecdhPub, err := ecdhSubkeyPublicKey(subPub)
	if err != nil {
		return nil, err
	}

	pk, err := findPKESK(message, subPub.KeyId)
	if err != nil {
		return nil, err
	}
	if pk.algo != 18 {
		return nil, fmt.Errorf("gpgagent: expected an ECDH session key packet")
	}
	return decryptECDHPKESK(pk, ecdhPub, subPub, keygrip, keyDesc, client)
}

// AgentDecryptSessionKeyECDHWildcard tries every hidden/anonymous
// (wildcard key ID) ECDH PKESK packet in message against subPub's
// Curve25519 subkey via gpg-agent — the counterpart, for agent-backed
// keys, of what real gpg calls "trying secret key X..." when a message
// doesn't say which key it's addressed to. Returns ErrPKESKNotFound if
// none of the message's wildcard ECDH PKESKs (there may be none, or
// several for other recipients) unwrap with this key; any other error
// from the agent itself is returned immediately.
func AgentDecryptSessionKeyECDHWildcard(message []byte, subPub *packet.PublicKey, keygrip, keyDesc string, client *gpgagent.Client) (*pgpcrypto.SessionKey, error) {
	ecdhPub, err := ecdhSubkeyPublicKey(subPub)
	if err != nil {
		return nil, err
	}

	candidates, err := findWildcardPKESKs(message)
	if err != nil {
		return nil, err
	}
	for _, pk := range candidates {
		if pk.algo != 18 {
			continue
		}
		sk, err := decryptECDHPKESK(pk, ecdhPub, subPub, keygrip, keyDesc, client)
		if err == nil {
			return sk, nil
		}
		if errors.Is(err, errKeywrapFailed) {
			continue
		}
		return nil, err
	}
	return nil, ErrPKESKNotFound
}

// decryptECDHPKESK performs the actual PKDECRYPT-and-unwrap for one
// already-located ECDH PKESK, shared by the exact-key-ID and
// wildcard-brute-force entry points above.
func decryptECDHPKESK(pk *pkesk, ecdhPub *ecdh.PublicKey, subPub *packet.PublicKey, keygrip, keyDesc string, client *gpgagent.Client) (*pgpcrypto.SessionKey, error) {
	cipherSexp := sexp.L(
		sexp.S("enc-val"),
		sexp.L(sexp.S("ecdh"),
			sexp.L(sexp.S("s"), sexp.A(pk.wrappedKey)),
			sexp.L(sexp.S("e"), sexp.A(pk.ephemeralPoint)),
		),
	).Canonical()

	result, err := client.Decrypt(keygrip, keyDesc, cipherSexp)
	if err != nil {
		return nil, err
	}
	node, _, err := sexp.Parse(result)
	if err != nil {
		return nil, fmt.Errorf("gpgagent: parsing PKDECRYPT result: %w", err)
	}
	zb, err := decryptValueBytes(node)
	if err != nil {
		return nil, err
	}
	// gpg-agent returns the shared secret in GnuPG's native-point form
	// (0x40-prefixed, like Curve25519 public keys/points elsewhere in
	// OpenPGP), not the bare RFC 6637 "ZB" the KDF expects.
	if len(zb) == 33 && zb[0] == 0x40 {
		zb = zb[1:]
	}

	fp := subPub.Fingerprint
	kek := ecdhKDF(ecdhPub, zb, curve25519OIDContentField(), fp)

	m, err := keywrap.Unwrap(kek, pk.wrappedKey)
	if err != nil {
		return nil, errKeywrapFailed
	}
	if len(m) == 0 {
		return nil, errKeywrapFailed
	}
	padLen := int(m[len(m)-1])
	if padLen <= 0 || padLen > len(m) {
		return nil, errKeywrapFailed
	}
	m = m[:len(m)-padLen]
	if len(m) < 3 {
		return nil, errKeywrapFailed
	}

	algoID := m[0]
	keyAndChecksum := m[1:]
	if len(keyAndChecksum) < 2 {
		return nil, errKeywrapFailed
	}
	sessKey := keyAndChecksum[:len(keyAndChecksum)-2]
	checksum := keyAndChecksum[len(keyAndChecksum)-2:]
	var sum uint16
	for _, b := range sessKey {
		sum += uint16(b)
	}
	if byte(sum>>8) != checksum[0] || byte(sum) != checksum[1] {
		return nil, errKeywrapFailed
	}

	algoName, ok := cipherAlgoNames[algoID]
	if !ok {
		return nil, fmt.Errorf("gpgagent: unsupported session key cipher %d", algoID)
	}

	return &pgpcrypto.SessionKey{Key: sessKey, Algo: algoName}, nil
}

// curve25519OIDContentField returns the length-prefixed OID field bytes
// as used in the RFC 6637 KDF "Param" construction.
func curve25519OIDContentField() []byte { return curve25519OIDField }

// decryptValueBytes extracts the raw bytes from gpg-agent's PKDECRYPT
// result, which is a canonical "(5:value<N>:<bytes>)" or, for very old
// libgcrypt, a bare opaque MPI-like fragment; we only need to support
// the modern wrapped form this tool's own agent talks.
func decryptValueBytes(node *sexp.Node) ([]byte, error) {
	if node.IsList() && node.Len() == 2 && node.Get(0).Str() == "value" && node.Get(1).IsAtom() {
		return node.Get(1).Atom, nil
	}
	return nil, fmt.Errorf("gpgagent: unexpected PKDECRYPT result shape")
}

// ecdhKDF implements RFC 6637 §8's "Param"/KDF construction, deriving
// the AES key-encryption-key from the ECDH shared secret zb.
func ecdhKDF(pub *ecdh.PublicKey, zb, curveOIDField, fingerprint []byte) []byte {
	var param bytes.Buffer
	param.Write(curveOIDField)
	param.Write([]byte{18, 3, 1, pub.KDF.Hash.Id(), pub.KDF.Cipher.Id()})
	param.Write([]byte("Anonymous Sender    "))
	param.Write(fingerprint)

	h := pub.KDF.Hash.New()
	h.Write([]byte{0, 0, 0, 1})
	h.Write(zb)
	h.Write(param.Bytes())
	mb := h.Sum(nil)

	keySize := pub.KDF.Cipher.KeySize()
	if keySize > len(mb) {
		keySize = len(mb)
	}
	return mb[:keySize]
}
