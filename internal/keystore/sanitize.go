package keystore

import "github.com/oza6ut0ne/gpg-go/internal/pgppacket"

// Real-world keyrings (this tool's own kbx/agentkey writer never produces
// such data, but keys fetched from keyservers occasionally do) sometimes
// contain a signature packet that is structurally out of place: e.g. a
// user-ID certification packet misfiled right after a subkey packet
// instead of before it. GnuPG itself tolerates this (it just ignores a
// signature that doesn't fit its current context), but go-crypto's
// parser is stricter and aborts the entire keyblock with e.g.
// "openpgp: invalid data: subkey signature with wrong type".
//
// sanitizeKeyblock drops any signature packet whose type could not
// possibly apply to its position, so the rest of an otherwise-valid key
// can still be parsed instead of failing outright.

// sigType extracts a signature packet's type byte (works for v3 through
// v6 signature packets), or ok=false if the body is too short to tell.
func sigType(body []byte) (int, bool) {
	if len(body) < 2 {
		return 0, false
	}
	if body[0] == 3 { // old v3 signature packet layout
		if len(body) < 3 {
			return 0, false
		}
		return int(body[2]), true
	}
	return int(body[1]), true
}

const (
	pktTagSignature = 2
	pktTagUserID    = 13
	pktTagPublicKey = 6
	pktTagPublicSub = 14
	pktTagUserAttr  = 17
	pktTagSecretKey = 5
	pktTagSecretSub = 7
)

func isPrimaryKeyTag(tag int) bool { return tag == pktTagPublicKey || tag == pktTagSecretKey }
func isSubkeyTag(tag int) bool     { return tag == pktTagPublicSub || tag == pktTagSecretSub }

// Signature type bytes, per RFC 4880 §5.2.1 / crypto-refresh.
const (
	sigUIDGeneric        = 0x10
	sigUIDPersona        = 0x11
	sigUIDCasual         = 0x12
	sigUIDPositive       = 0x13
	sigSubkeyBinding     = 0x18
	sigPrimaryKeyBinding = 0x19
	sigDirectKey         = 0x1f
	sigKeyRevocation     = 0x20
	sigSubkeyRevocation  = 0x28
	sigCertRevocation    = 0x30
)

func isUIDContextSigType(t int) bool {
	switch t {
	case sigUIDGeneric, sigUIDPersona, sigUIDCasual, sigUIDPositive, sigCertRevocation:
		return true
	}
	return false
}

func isSubkeyContextSigType(t int) bool {
	switch t {
	case sigSubkeyBinding, sigSubkeyRevocation, sigPrimaryKeyBinding:
		return true
	}
	return false
}

func isPrimaryContextSigType(t int) bool {
	switch t {
	case sigDirectKey, sigKeyRevocation:
		return true
	}
	return false
}

// sanitizeKeyblock returns data with any out-of-place signature packets
// removed. changed is false (and data itself is returned) when nothing
// needed dropping.
func sanitizeKeyblock(data []byte) (out []byte, changed bool, err error) {
	packets, err := pgppacket.Walk(data)
	if err != nil {
		return nil, false, err
	}

	context := "primary"
	var kept [][]byte
	for _, p := range packets {
		switch {
		case isPrimaryKeyTag(p.Tag):
			context = "primary"
		case p.Tag == pktTagUserID || p.Tag == pktTagUserAttr:
			context = "uid"
		case isSubkeyTag(p.Tag):
			context = "subkey"
		case p.Tag == pktTagSignature:
			if st, ok := sigType(p.Body); ok {
				var validHere bool
				switch context {
				case "uid":
					validHere = isUIDContextSigType(st)
				case "subkey":
					validHere = isSubkeyContextSigType(st)
				case "primary":
					validHere = isPrimaryContextSigType(st) || isUIDContextSigType(st)
				}
				if !validHere {
					changed = true
					continue
				}
			}
		}
		kept = append(kept, p.Full)
	}

	if !changed {
		return data, false, nil
	}
	var buf []byte
	for _, k := range kept {
		buf = append(buf, k...)
	}
	return buf, true, nil
}
