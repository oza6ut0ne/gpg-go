// Package pgppacket implements a minimal, dependency-free walk of raw
// OpenPGP packet header framing (RFC 4880 §4.2, old and new format,
// definite lengths only — the only forms that ever appear in an
// exported keyblock or message). It deliberately does not interpret
// packet bodies; callers that need typed fields feed a packet's Full
// bytes to github.com/ProtonMail/go-crypto/openpgp/packet.Read.
package pgppacket

import "fmt"

// Packet is one packet found while walking a raw byte stream: its tag,
// its position, and its exact original bytes.
type Packet struct {
	Tag       int
	Offset    int // offset of the packet's own header, in the walked data
	HeaderLen int
	BodyLen   int
	CTB       byte // the first (tag) byte, as gpg's --list-packets shows it
	NewFormat bool
	Full      []byte // header + body, exact original bytes
	Body      []byte
}

// Walk parses the packet header framing of data into a sequence of
// Packets, leaving each packet's body opaque.
func Walk(data []byte) ([]Packet, error) {
	var out []Packet
	i := 0
	for i < len(data) {
		first := data[i]
		if first&0x80 == 0 {
			return nil, fmt.Errorf("invalid packet tag byte 0x%02x at offset %d", first, i)
		}
		var tag, bodyLen, headerLen int
		newFormat := first&0x40 != 0
		if newFormat {
			tag = int(first & 0x3f)
			if i+1 >= len(data) {
				return nil, fmt.Errorf("truncated packet header at offset %d", i)
			}
			l1 := int(data[i+1])
			switch {
			case l1 < 192:
				bodyLen = l1
				headerLen = 2
			case l1 < 224:
				if i+2 >= len(data) {
					return nil, fmt.Errorf("truncated packet header at offset %d", i)
				}
				bodyLen = (l1-192)<<8 + int(data[i+2]) + 192
				headerLen = 3
			case l1 == 255:
				if i+5 >= len(data) {
					return nil, fmt.Errorf("truncated packet header at offset %d", i)
				}
				bodyLen = int(data[i+2])<<24 | int(data[i+3])<<16 | int(data[i+4])<<8 | int(data[i+5])
				headerLen = 6
			default:
				return nil, fmt.Errorf("unsupported partial-length packet at offset %d", i)
			}
		} else {
			tag = int((first >> 2) & 0x0f)
			switch first & 0x03 {
			case 0:
				if i+1 >= len(data) {
					return nil, fmt.Errorf("truncated packet header at offset %d", i)
				}
				bodyLen = int(data[i+1])
				headerLen = 2
			case 1:
				if i+2 >= len(data) {
					return nil, fmt.Errorf("truncated packet header at offset %d", i)
				}
				bodyLen = int(data[i+1])<<8 | int(data[i+2])
				headerLen = 3
			case 2:
				if i+4 >= len(data) {
					return nil, fmt.Errorf("truncated packet header at offset %d", i)
				}
				bodyLen = int(data[i+1])<<24 | int(data[i+2])<<16 | int(data[i+3])<<8 | int(data[i+4])
				headerLen = 5
			default:
				return nil, fmt.Errorf("unsupported indeterminate-length packet at offset %d", i)
			}
		}

		end := i + headerLen + bodyLen
		if end > len(data) {
			return nil, fmt.Errorf("packet body at offset %d exceeds input", i)
		}
		out = append(out, Packet{
			Tag:       tag,
			Offset:    i,
			HeaderLen: headerLen,
			BodyLen:   bodyLen,
			CTB:       first,
			NewFormat: newFormat,
			Full:      data[i:end],
			Body:      data[i+headerLen : end],
		})
		i = end
	}
	return out, nil
}
