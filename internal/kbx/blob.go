// Package kbx implements GnuPG's "keybox" (.kbx) binary keyring format
// (pubring.kbx), as used by GnuPG 2.1+ to store public keys. The layout
// here is reverse engineered from, and verified against, GnuPG's
// kbx/keybox-blob.c.
package kbx

import (
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/oza6ut0ne/gpg-go/internal/pgppacket"
)

const (
	BlobTypeEmpty   = 0
	BlobTypeHeader  = 1
	BlobTypeOpenPGP = 2
	BlobTypeX509    = 3
)

// Blob is one keybox record. Raw always holds the complete on-disk bytes
// (including the leading 4-byte length), so blobs this package does not
// need to modify (headers, X.509 blobs, blobs it did not build itself)
// round-trip byte for byte.
type Blob struct {
	Type byte
	Raw  []byte

	// Populated only for Type == BlobTypeOpenPGP.
	Fingerprints [][]byte // primary key first, then subkeys, each 20 bytes
	Keyblock     []byte   // the raw unarmored OpenPGP packet stream
}

// headerBlob returns a fresh "First blob" (type 1) marking the file as
// used for OpenPGP.
func headerBlob() *Blob {
	buf := make([]byte, 32)
	binary.BigEndian.PutUint32(buf[0:4], 32)
	buf[4] = BlobTypeHeader
	buf[5] = 1
	binary.BigEndian.PutUint16(buf[6:8], 2) // "used for OpenPGP blobs"
	copy(buf[8:12], []byte("KBXf"))
	now := uint32(time.Now().Unix())
	binary.BigEndian.PutUint32(buf[16:20], now)
	binary.BigEndian.PutUint32(buf[20:24], now)
	return &Blob{Type: BlobTypeHeader, Raw: buf}
}

// fixup is a deferred 4-byte big-endian write into the blob buffer,
// applied once the final length is known (mirrors keybox-blob.c's own
// fixup list, used for the same reason: some offsets are only known
// after later data has been appended).
type fixup struct {
	offset int
	value  uint32
}

// NewOpenPGPBlob builds a fresh type-2 (OpenPGP) keybox blob wrapping
// keyblock, an unarmored OpenPGP transferable public key (primary key,
// user IDs, signatures and subkeys, exactly as produced by serializing a
// single OpenPGP entity).
func NewOpenPGPBlob(keyblock []byte) (*Blob, error) {
	packets, err := pgppacket.Walk(keyblock)
	if err != nil {
		return nil, fmt.Errorf("kbx: parsing keyblock: %w", err)
	}

	var fprs [][]byte
	var uids []pgppacket.Packet
	for _, pk := range packets {
		switch pk.Tag {
		case 6, 14: // public key, public subkey
			fpr, err := fingerprintOf(pk)
			if err != nil {
				return nil, err
			}
			fprs = append(fprs, fpr)
		case 13: // user ID
			uids = append(uids, pk)
		}
	}
	if len(fprs) == 0 {
		return nil, fmt.Errorf("kbx: keyblock contains no public key packets")
	}

	var buf bytes.Buffer
	var fixups []fixup
	put32 := func(v uint32) { var b [4]byte; binary.BigEndian.PutUint32(b[:], v); buf.Write(b[:]) }
	put16 := func(v uint16) { var b [2]byte; binary.BigEndian.PutUint16(b[:], v); buf.Write(b[:]) }
	put8 := func(v byte) { buf.WriteByte(v) }
	addFixup := func(offset int, value uint32) { fixups = append(fixups, fixup{offset, value}) }

	put32(0) // blob length, fixed up at the end
	put8(BlobTypeOpenPGP)
	put8(1)  // version 1 (20-byte fingerprints)
	put16(0) // blob flags
	put32(0) // offset to keyblock, fixed up
	put32(0) // length of keyblock, fixed up
	put16(uint16(len(fprs)))
	put16(20 + 4 + 2 + 2) // size of key info

	type keyInfoAddr struct{ offKidAddr int }
	var keyAddrs []keyInfoAddr
	for _, fpr := range fprs {
		buf.Write(fpr) // 20 bytes
		offKidAddr := buf.Len()
		put32(0) // offset to keyid, fixed up below
		put16(0) // flags
		put16(0) // reserved
		keyAddrs = append(keyAddrs, keyInfoAddr{offKidAddr})
	}

	put16(0) // size of serial number (none)

	put16(uint16(len(uids)))
	put16(4 + 4 + 2 + 1 + 1) // size of uid info
	var uidAddrs []int
	for _, u := range uids {
		uidAddrs = append(uidAddrs, buf.Len())
		put32(0) // offset to userid, fixed up
		put32(uint32(len(u.Body)))
		put16(0) // flags
		put8(0)  // validity
		put8(0)  // reserved
	}

	put16(0) // number of signatures
	put16(4) // size of sig info

	put8(0)                          // assigned ownertrust
	put8(0)                          // validity of all user IDs
	put16(0)                         // reserved
	put32(0)                         // recheck-after
	put32(0)                         // newest timestamp
	put32(uint32(time.Now().Unix())) // creation time
	put32(0)                         // size of reserved space

	// v4/v5 key IDs are just the low 8 bytes of the already-stored
	// fingerprint: point the offset 8 bytes before this field itself.
	for _, ka := range keyAddrs {
		addFixup(ka.offKidAddr, uint32(ka.offKidAddr-8))
	}

	kbstart := buf.Len()
	addFixup(8, uint32(kbstart))
	for i, u := range uids {
		addFixup(uidAddrs[i], uint32(kbstart+u.Offset+u.HeaderLen))
	}
	buf.Write(keyblock)
	addFixup(12, uint32(buf.Len()-kbstart))

	buf.Write(make([]byte, 20)) // checksum placeholder

	out := buf.Bytes()
	addFixup(0, uint32(len(out)))
	for _, f := range fixups {
		binary.BigEndian.PutUint32(out[f.offset:f.offset+4], f.value)
	}
	sum := sha1.Sum(out[:len(out)-20])
	copy(out[len(out)-20:], sum[:])

	return &Blob{
		Type:         BlobTypeOpenPGP,
		Raw:          out,
		Fingerprints: fprs,
		Keyblock:     keyblock,
	}, nil
}
