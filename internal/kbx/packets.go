package kbx

import (
	"bytes"
	"fmt"

	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/oza6ut0ne/gpg-go/internal/pgppacket"
)

// fingerprintOf reparses a public-key or public-subkey raw packet (via
// go-crypto) to extract its fingerprint.
func fingerprintOf(pk pgppacket.Packet) ([]byte, error) {
	// Rebuild a minimal, valid new-format packet (tag 6) around the
	// existing body bytes so go-crypto's packet reader can parse it,
	// regardless of the original packet's own header encoding.
	var hdr bytes.Buffer
	hdr.WriteByte(0xC0 | 6)
	n := len(pk.Body)
	switch {
	case n < 192:
		hdr.WriteByte(byte(n))
	case n < 8384:
		n -= 192
		hdr.WriteByte(byte(192 + n>>8))
		hdr.WriteByte(byte(n & 0xff))
	default:
		hdr.WriteByte(255)
		hdr.WriteByte(byte(n >> 24))
		hdr.WriteByte(byte(n >> 16))
		hdr.WriteByte(byte(n >> 8))
		hdr.WriteByte(byte(n))
	}
	hdr.Write(pk.Body)

	p, err := packet.Read(bytes.NewReader(hdr.Bytes()))
	if err != nil {
		return nil, fmt.Errorf("parsing public key packet: %w", err)
	}
	switch key := p.(type) {
	case *packet.PublicKey:
		return key.Fingerprint, nil
	default:
		return nil, fmt.Errorf("unexpected packet type %T", p)
	}
}
