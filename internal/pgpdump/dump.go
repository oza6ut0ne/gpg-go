// Package pgpdump implements gpg's --list-packets: a human-readable,
// non-decrypting dump of an OpenPGP object's packet structure, in the
// same rough spirit (though not necessarily byte-identical wording) as
// GnuPG's own debug listing.
package pgpdump

import (
	"bytes"
	stdcrypto "crypto"
	"fmt"
	"io"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/oza6ut0ne/gpg-go/internal/pgppacket"
)

// Dump writes a packet-by-packet listing of data (armored or binary) to w.
func Dump(w io.Writer, data []byte) error {
	binary, err := toBinary(data)
	if err != nil {
		return fmt.Errorf("dearmoring: %w", err)
	}

	packets, err := pgppacket.Walk(binary)
	if err != nil {
		return fmt.Errorf("parsing packets: %w", err)
	}
	for _, p := range packets {
		printHeaderLine(w, p)
		printPacket(w, p)
	}
	return nil
}

func toBinary(data []byte) ([]byte, error) {
	if !strings.HasPrefix(strings.TrimSpace(string(data)), "-----BEGIN PGP") {
		return data, nil
	}
	block, err := armor.Decode(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	return io.ReadAll(block.Body)
}

func printHeaderLine(w io.Writer, p pgppacket.Packet) {
	suffix := ""
	if p.NewFormat {
		suffix = " new-ctb"
	}
	fmt.Fprintf(w, "# off=%d ctb=%02x tag=%d hlen=%d plen=%d%s\n",
		p.Offset, p.CTB, p.Tag, p.HeaderLen, p.BodyLen, suffix)
}

func printPacket(w io.Writer, p pgppacket.Packet) {
	pk, err := packet.Read(bytes.NewReader(p.Full))
	if err != nil {
		printUnknown(w, p)
		return
	}

	switch v := pk.(type) {
	case *packet.EncryptedKey:
		printEncryptedKey(w, v)
	case *packet.Signature:
		printSignature(w, v)
	case *packet.SymmetricKeyEncrypted:
		fmt.Fprintf(w, ":symkey enc packet: version %d, cipher %d\n", v.Version, v.CipherFunc)
	case *packet.OnePassSignature:
		printOnePassSignature(w, v)
	case *packet.PrivateKey:
		printPrivateKey(w, v)
	case *packet.PublicKey:
		printPublicKey(w, v)
	case *packet.Compressed:
		algo := byte(0)
		if len(p.Body) > 0 {
			algo = p.Body[0]
		}
		fmt.Fprintf(w, ":compressed packet: algo=%d\n", algo)
	case *packet.SymmetricallyEncrypted:
		label := "encrypted data packet"
		mdc := ""
		if v.IntegrityProtected {
			mdc = "\n\tmdc_method: 2"
		}
		fmt.Fprintf(w, ":%s:\n\tlength: %d%s\n", label, len(p.Body), mdc)
	case *packet.AEADEncrypted:
		fmt.Fprintf(w, ":aead encrypted packet:\n\tlength: %d\n", len(p.Body))
	case *packet.LiteralData:
		printLiteralData(w, p, v)
	case *packet.UserId:
		fmt.Fprintf(w, ":user ID packet: %q\n", v.Id)
	case *packet.UserAttribute:
		fmt.Fprintln(w, ":attribute packet:")
	case *packet.Marker:
		fmt.Fprintln(w, ":marker packet:")
	case packet.Padding:
		fmt.Fprintf(w, ":padding packet: length %d\n", len(p.Body))
	default:
		printUnknown(w, p)
	}
}

func printUnknown(w io.Writer, p pgppacket.Packet) {
	fmt.Fprintf(w, ":unknown packet: type %d, length %d\n", p.Tag, len(p.Body))
	const maxDump = 48
	n := len(p.Body)
	if n > maxDump {
		n = maxDump
	}
	if n > 0 {
		fmt.Fprintf(w, "\tdump: %x\n", p.Body[:n])
	}
}

func printEncryptedKey(w io.Writer, v *packet.EncryptedKey) {
	if v.Version >= 6 && len(v.KeyFingerprint) > 0 {
		fmt.Fprintf(w, ":pubkey enc packet: version %d, algo %d, fingerprint %X\n", v.Version, v.Algo, v.KeyFingerprint)
		return
	}
	fmt.Fprintf(w, ":pubkey enc packet: version %d, algo %d, keyid %016X\n", v.Version, v.Algo, v.KeyId)
}

func printSignature(w io.Writer, v *packet.Signature) {
	keyID := uint64(0)
	if v.IssuerKeyId != nil {
		keyID = *v.IssuerKeyId
	}
	fmt.Fprintf(w, ":signature packet: algo %d, keyid %016X\n", v.PubKeyAlgo, keyID)
	fmt.Fprintf(w, "\tversion %d, created %d, md5len 0, sigclass 0x%02x\n", v.Version, v.CreationTime.Unix(), v.SigType)
	fmt.Fprintf(w, "\tdigest algo %d\n", hashID(v.Hash))
}

func printOnePassSignature(w io.Writer, v *packet.OnePassSignature) {
	fmt.Fprintf(w, ":onepass_sig packet: keyid %016X\n", v.KeyId)
	last := 0
	if v.IsLast {
		last = 1
	}
	fmt.Fprintf(w, "\tversion %d, sigclass 0x%02x, digest %d, pubkey %d, last=%d\n",
		v.Version, v.SigType, hashID(v.Hash), v.PubKeyAlgo, last)
}

func printPrivateKey(w io.Writer, v *packet.PrivateKey) {
	label := "secret key packet"
	if v.IsSubkey {
		label = "secret sub key packet"
	}
	fmt.Fprintf(w, ":%s:\n", label)
	protected := "not protected"
	if v.Encrypted {
		protected = "protected"
	}
	fmt.Fprintf(w, "\tversion %d, algo %d, created %d, %s\n", v.PublicKey.Version, v.PublicKey.PubKeyAlgo, v.PublicKey.CreationTime.Unix(), protected)
	fmt.Fprintf(w, "\tkeyid %016X\n", v.PublicKey.KeyId)
}

func printPublicKey(w io.Writer, v *packet.PublicKey) {
	label := "public key packet"
	if v.IsSubkey {
		label = "public sub key packet"
	}
	fmt.Fprintf(w, ":%s:\n", label)
	fmt.Fprintf(w, "\tversion %d, algo %d, created %d, expires 0\n", v.Version, v.PubKeyAlgo, v.CreationTime.Unix())
	fmt.Fprintf(w, "\tkeyid %016X\n", v.KeyId)
}

func printLiteralData(w io.Writer, p pgppacket.Packet, v *packet.LiteralData) {
	// LiteralData.Body is the remaining io.Reader after the header
	// fields (format, filename, time) have already been consumed, so
	// its length isn't directly available; recompute it from the raw
	// body: 1 (format) + 1 (name length) + len(name) + 4 (time).
	headerLen := 1 + 1 + len(v.FileName) + 4
	dataLen := len(p.Body) - headerLen
	if dataLen < 0 {
		dataLen = 0
	}
	fmt.Fprintf(w, ":literal data packet:\n")
	fmt.Fprintf(w, "\tmode %c (%d), created %d, name=%q,\n\traw data: %d bytes\n",
		v.Format, v.Format, v.Time, v.FileName, dataLen)
}

// openPGPHashIDs maps the standard library hash identifiers to their
// OpenPGP algorithm numbers (RFC 4880 §9.4 / crypto-refresh registry).
var openPGPHashIDs = map[stdcrypto.Hash]int{
	stdcrypto.MD5:       1,
	stdcrypto.SHA1:      2,
	stdcrypto.RIPEMD160: 3,
	stdcrypto.SHA256:    8,
	stdcrypto.SHA384:    9,
	stdcrypto.SHA512:    10,
	stdcrypto.SHA224:    11,
	stdcrypto.SHA3_256:  12,
	stdcrypto.SHA3_512:  14,
}

// hashID maps a crypto.Hash to its OpenPGP algorithm number for display,
// matching the numeric IDs gpg itself prints.
func hashID(h stdcrypto.Hash) int {
	return openPGPHashIDs[h]
}
