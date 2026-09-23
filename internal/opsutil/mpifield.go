package opsutil

import (
	"io"
	"math/bits"
)

// mpiField is a from-scratch, minimal reimplementation of go-crypto's
// (unexported, internal/encoding) MPI type: an OpenPGP multiprecision
// integer, i.e. a 2-byte big-endian bit length followed by the minimal
// big-endian magnitude bytes. It exists so external code (this package)
// can populate a *packet.Signature's Edwards/RSA signature fields
// (declared as the internal encoding.Field interface) after computing a
// signature value externally (e.g. via gpg-agent), which go-crypto
// itself provides no public constructor for.
//
// encoding.Field's methods use only stdlib types, so this satisfies it
// structurally without needing to import the internal package.
type mpiField struct {
	bytes     []byte
	bitLength uint16
}

// newMPIField builds an mpiField from a big-endian magnitude, matching
// go-crypto's own NewMPI (stripping leading zero bytes and computing the
// exact bit length of the leading byte).
func newMPIField(b []byte) *mpiField {
	for len(b) != 0 && b[0] == 0 {
		b = b[1:]
	}
	if len(b) == 0 {
		return &mpiField{b, 0}
	}
	bitLength := 8*uint16(len(b)-1) + uint16(bits.Len8(b[0]))
	return &mpiField{b, bitLength}
}

func (m *mpiField) Bytes() []byte         { return m.bytes }
func (m *mpiField) BitLength() uint16     { return m.bitLength }
func (m *mpiField) EncodedLength() uint16 { return uint16(2 + len(m.bytes)) }

func (m *mpiField) EncodedBytes() []byte {
	return append([]byte{byte(m.bitLength >> 8), byte(m.bitLength)}, m.bytes...)
}

func (m *mpiField) ReadFrom(r io.Reader) (int64, error) {
	var buf [2]byte
	n, err := io.ReadFull(r, buf[:])
	if err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return int64(n), err
	}
	m.bitLength = uint16(buf[0])<<8 | uint16(buf[1])
	m.bytes = make([]byte, (int(m.bitLength)+7)/8)
	nn, err := io.ReadFull(r, m.bytes)
	if err == io.EOF {
		err = io.ErrUnexpectedEOF
	}
	return int64(n) + int64(nn), err
}
