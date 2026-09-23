package kbx

import (
	"encoding/binary"
	"fmt"
	"os"
)

// ReadFile reads and parses every blob in a pubring.kbx file. A missing
// file yields an empty (but valid) list, matching a freshly initialized
// keybox. Non-OpenPGP and header blobs are kept as opaque Raw bytes.
func ReadFile(path string) ([]*Blob, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return Parse(data)
}

// Parse splits data into its constituent blobs.
func Parse(data []byte) ([]*Blob, error) {
	var out []*Blob
	i := 0
	for i < len(data) {
		if i+4 > len(data) {
			return nil, fmt.Errorf("kbx: truncated blob length at offset %d", i)
		}
		length := binary.BigEndian.Uint32(data[i : i+4])
		if length == 0 {
			break // trailing empty/padding blob
		}
		end := i + int(length)
		if end > len(data) || end <= i+5 {
			return nil, fmt.Errorf("kbx: invalid blob length %d at offset %d", length, i)
		}
		raw := data[i:end]
		blobType := raw[4]

		b := &Blob{Type: blobType, Raw: raw}
		if blobType == BlobTypeOpenPGP {
			if err := parseOpenPGPBlob(b); err != nil {
				return nil, fmt.Errorf("kbx: parsing OpenPGP blob at offset %d: %w", i, err)
			}
		}
		out = append(out, b)
		i = end
	}
	return out, nil
}

// parseOpenPGPBlob fills in Fingerprints and Keyblock for a type-2 blob
// from its already-stored Raw bytes.
func parseOpenPGPBlob(b *Blob) error {
	raw := b.Raw
	if len(raw) < 20 {
		return fmt.Errorf("blob too short")
	}
	version := raw[5]
	kbOffset := binary.BigEndian.Uint32(raw[8:12])
	kbLength := binary.BigEndian.Uint32(raw[12:16])
	nkeys := binary.BigEndian.Uint16(raw[16:18])
	keyInfoSize := binary.BigEndian.Uint16(raw[18:20])

	if uint64(kbOffset)+uint64(kbLength) > uint64(len(raw)) {
		return fmt.Errorf("keyblock range out of bounds")
	}
	b.Keyblock = raw[kbOffset : kbOffset+kbLength]

	fprLen := 20
	if version == 2 {
		fprLen = 32
	}
	pos := 20
	for k := 0; k < int(nkeys); k++ {
		if pos+int(keyInfoSize) > len(raw) {
			return fmt.Errorf("key info entry out of bounds")
		}
		fpr := make([]byte, fprLen)
		copy(fpr, raw[pos:pos+fprLen])
		b.Fingerprints = append(b.Fingerprints, fpr)
		pos += int(keyInfoSize)
	}
	return nil
}

// WriteFile writes blobs to path, prepending a fresh header blob if none
// of the given blobs is already a header blob.
func WriteFile(path string, blobs []*Blob) error {
	hasHeader := false
	for _, b := range blobs {
		if b.Type == BlobTypeHeader {
			hasHeader = true
			break
		}
	}
	var out []byte
	if !hasHeader {
		out = append(out, headerBlob().Raw...)
	}
	for _, b := range blobs {
		out = append(out, b.Raw...)
	}
	return os.WriteFile(path, out, 0o644)
}
