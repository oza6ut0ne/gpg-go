// Package keygrip computes libgcrypt-compatible "keygrips": the SHA-1
// based key identifiers gpg-agent uses as private-keys-v1.d/*.key
// filenames. The algorithms and curve constants here are reverse
// engineered from, and verified byte-for-byte against, libgcrypt's
// cipher/ecc.c (compute_keygrip), cipher/rsa.c (compute_keygrip) and
// cipher/ecc-curves.c (the domain_parms table).
package keygrip

import (
	"crypto/sha1"
	"fmt"
	"math/big"
)

// curve holds the domain parameters exactly as libgcrypt's internal
// ecc-curves.c domain_parms table defines them (hex, as literally
// written there — including the deliberately "wrong" Curve25519 g_y
// used only for keygrip stability, per a libgcrypt code comment).
type curve struct {
	p, a, b, n, gx, gy string
}

var ed25519Curve = curve{
	p:  "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFED",
	a:  "-01",
	b:  "2DFC9311D490018C7338BF8688861767FF8FF5B2BEBE27548A14B235ECA6874A",
	n:  "1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED",
	gx: "216936D3CD6E53FEC0A4E231FDD6DC5C692CC7609525A7B2C9562D608F25D51A",
	gy: "6666666666666666666666666666666666666666666666666666666666666658",
}

var curve25519 = curve{
	p:  "7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFED",
	a:  "01DB41",
	b:  "01",
	n:  "1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED",
	gx: "0000000000000000000000000000000000000000000000000000000000000009",
	gy: "20AE19A1B8A086B4E01EDD2C7748D14C923D4D7E6D7C61B229E9C5A27ECED3D9",
}

// hexMinimal returns the minimal-length big-endian magnitude bytes for a
// hex string as libgcrypt's _gcry_mpi_get_buffer would (no sign, no
// padding). A leading "-" is stripped: libgcrypt's keygrip computation
// hashes the raw magnitude of these table constants (e.g. Ed25519's
// a = "-0x01" contributes a single 0x01 byte), not a reduction mod p.
func hexMinimal(hex string) []byte {
	neg := false
	if len(hex) > 0 && hex[0] == '-' {
		neg = true
		hex = hex[1:]
	}
	_ = neg
	n := new(big.Int)
	n.SetString(hex, 16)
	return n.Bytes()
}

// hashDomainAndPoint implements the common part of compute_keygrip:
// SHA-1 over (1:p..)(1:a..)(1:b..)(1:g..)(1:n..)(1:q..) for the given
// curve and compact (prefix-stripped) point q.
func hashDomainAndPoint(c curve, qCompact []byte) [20]byte {
	// g is built by gnupg as one big number from the *concatenated hex
	// strings* "04"+gx+gy (see _gcry_ecc_update_curve_param), not from
	// gx and gy normalized independently — gx's leading zero bytes (as
	// in Curve25519's base point, x=9) must be preserved since they are
	// not leading in the combined number.
	g := hexMinimal("04" + c.gx + c.gy)

	h := sha1.New()
	write := func(tag byte, data []byte) {
		h.Write([]byte(fmt.Sprintf("(1:%c%d:", tag, len(data))))
		h.Write(data)
		h.Write([]byte{')'})
	}
	write('p', hexMinimal(c.p))
	write('a', hexMinimal(c.a))
	write('b', hexMinimal(c.b))
	write('g', g)
	write('n', hexMinimal(c.n))
	write('q', qCompact)

	var out [20]byte
	copy(out[:], h.Sum(nil))
	return out
}

// stripPrefix40 removes the leading 0x40 "native point" marker byte
// OpenPGP/gnupg use for Ed25519/X25519 points, as libgcrypt's keygrip
// code does before hashing (both the EdDSA "ensure compact" path and
// the ECDH "djb-tweak" path end up removing this same byte for these
// curves).
func stripPrefix40(q []byte) []byte {
	if len(q) > 0 && q[0] == 0x40 {
		return q[1:]
	}
	return q
}

// EdDSA25519 computes the keygrip for an Ed25519 signing key given its
// public point q, with or without the leading 0x40 marker byte.
func EdDSA25519(q []byte) [20]byte {
	return hashDomainAndPoint(ed25519Curve, stripPrefix40(q))
}

// ECDH25519 computes the keygrip for a Curve25519 (X25519/cv25519)
// encryption key given its public point q, with or without the leading
// 0x40 marker byte.
func ECDH25519(q []byte) [20]byte {
	return hashDomainAndPoint(curve25519, stripPrefix40(q))
}

// RSA computes the keygrip for an RSA key given its modulus n, in
// whatever minimal big-endian form it is stored (a leading 0x00 is
// added automatically if the top bit of the first byte is set, matching
// libgcrypt's "STD" MPI convention).
func RSA(n []byte) [20]byte {
	n = stdNormalize(n)
	var out [20]byte
	copy(out[:], sha1Sum(n))
	return out
}

// StdBytes trims any leading zero bytes and then re-adds a single leading
// zero if the top bit of the first remaining byte is set, i.e.
// libgcrypt's GCRYMPI_FMT_STD unsigned-integer convention used throughout
// gpg-agent's RSA parameter storage (n, e, d, p, q, u).
func StdBytes(b []byte) []byte {
	return stdNormalize(b)
}

func stdNormalize(b []byte) []byte {
	i := 0
	for i < len(b)-1 && b[i] == 0 {
		i++
	}
	b = b[i:]
	if len(b) > 0 && b[0]&0x80 != 0 {
		out := make([]byte, len(b)+1)
		copy(out[1:], b)
		return out
	}
	return b
}

func sha1Sum(b []byte) []byte {
	h := sha1.Sum(b)
	return h[:]
}

// Hex formats a keygrip as the uppercase hex string used for
// private-keys-v1.d/*.key filenames.
func Hex(grip [20]byte) string {
	return fmt.Sprintf("%X", grip[:])
}
