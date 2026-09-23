package opsutil

import (
	"bytes"
	stdcrypto "crypto"
	"crypto/rand"
	stdrsa "crypto/rsa"
	"fmt"
	"io"
	"strings"
	"time"

	openpgp "github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/eddsa"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	pgpcrypto "github.com/ProtonMail/gopenpgp/v2/crypto"
	"github.com/oza6ut0ne/gpg-go/internal/gpgagent"
	"github.com/oza6ut0ne/gpg-go/internal/sexp"
)

// agentHashIDs maps OpenPGP hash algorithm numbers (RFC 4880 §9.4) to
// crypto.Hash, the reverse of the table pgpdump keeps for display.
var agentHashIDs = map[uint8]stdcrypto.Hash{
	1: stdcrypto.MD5, 2: stdcrypto.SHA1, 3: stdcrypto.RIPEMD160,
	8: stdcrypto.SHA256, 9: stdcrypto.SHA384, 10: stdcrypto.SHA512,
	11: stdcrypto.SHA224, 12: stdcrypto.SHA3_256, 14: stdcrypto.SHA3_512,
}

// pickHashForSigning approximates go-crypto's own selectHashForSigningKey:
// prefer SHA256 if the signing identity's self-signature accepts it,
// otherwise its first preferred hash, defaulting to SHA256 if unknown.
func pickHashForSigning(e *openpgp.Entity) stdcrypto.Hash {
	ident := e.PrimaryIdentity()
	if ident == nil || ident.SelfSignature == nil || len(ident.SelfSignature.PreferredHash) == 0 {
		return stdcrypto.SHA256
	}
	prefs := ident.SelfSignature.PreferredHash
	for _, id := range prefs {
		if id == 8 { // SHA256
			return stdcrypto.SHA256
		}
	}
	if h, ok := agentHashIDs[prefs[0]]; ok {
		return h
	}
	return stdcrypto.SHA256
}

// AgentSigningSupported reports whether AgentSignDetached (and friends)
// know how to sign with pub's algorithm, so callers can decide whether
// to try the agent at all versus falling back to this tool's own
// private-keys-v1.d handling without risking a confusing hard error for
// an algorithm this path simply doesn't cover (e.g. a foreign,
// non-EdDSA/RSA imported key).
func AgentSigningSupported(pub *packet.PublicKey) bool {
	switch pub.PublicKey.(type) {
	case *stdrsa.PublicKey, *eddsa.PublicKey:
		return true
	default:
		return false
	}
}

// AgentKeyDesc formats the description gpg-agent shows in pinentry (or
// includes in its passphrase inquiry) for an operation on the given key.
func AgentKeyDesc(uid, op string) string {
	if uid == "" {
		return op
	}
	return fmt.Sprintf("%s (%s)", op, uid)
}

// agentSign builds a complete v4 OpenPGP signature packet over message,
// with the actual cryptographic signing operation performed by
// gpg-agent for the key identified by keygrip. signer is the specific
// public key packet doing the signing — the entity's primary key, or one
// of its subkeys (e.g. a dedicated signing subkey, which is what every
// OpenPGP smartcard/token exposes) — so the resulting signature's
// PubKeyAlgo/IssuerFingerprint correctly identify whichever key actually
// signed, not always the primary. Supports Ed25519 (EdDSA-legacy) and
// RSA signing keys — the only two algorithms this tool generates.
//
// For RSA, go-crypto's own Signature.Sign accepts an external
// crypto.Signer, so the agent is plugged in directly. EdDSA has no such
// extension point (go-crypto hard-requires a local *eddsa.PrivateKey),
// so this instead lets Signature.Sign run once against a throwaway local
// EdDSA key sharing the same public point — which correctly builds every
// subpacket and the exact digest to sign as a side effect, since those
// only depend on the (real, correct) embedded PublicKey — discards the
// resulting (wrong) signature values, recovers the identical digest
// bytes via hash.Hash.Sum (documented not to mutate state), and replaces
// them with the real signature obtained from the agent.
func agentSign(e *openpgp.Entity, signer *packet.PublicKey, keygrip, keyDesc string, client *gpgagent.Client, sigType packet.SignatureType, hash stdcrypto.Hash, message io.Reader) (*packet.Signature, error) {
	sig := &packet.Signature{
		Version:           signer.Version,
		SigType:           sigType,
		PubKeyAlgo:        signer.PubKeyAlgo,
		Hash:              hash,
		CreationTime:      time.Now(),
		IssuerKeyId:       &signer.KeyId,
		IssuerFingerprint: signer.Fingerprint,
	}
	cfg := &packet.Config{Time: func() time.Time { return sig.CreationTime }}

	// For a text-mode signature, the bytes actually hashed must be
	// canonicalised (CRLF line endings, no trailing whitespace) per RFC
	// 4880 §5.2.1, exactly as go-crypto's own detachSign does — but the
	// final Sign call below still gets the underlying (unwrapped) hasher,
	// since NewCanonicalTextHash only transforms what's written into it.
	hasher := hash.New()
	var w io.Writer = hasher
	if sigType == packet.SigTypeText {
		w = openpgp.NewCanonicalTextHash(hasher)
	}
	if _, err := io.Copy(w, message); err != nil {
		return nil, err
	}

	switch pk := signer.PublicKey.(type) {
	case *stdrsa.PublicKey:
		rsaSigner := &agentRSASigner{client: client, keygrip: keygrip, keyDesc: keyDesc, pub: pk}
		priv := &packet.PrivateKey{PublicKey: *signer, PrivateKey: rsaSigner}
		if err := sig.Sign(hasher, priv, cfg); err != nil {
			return nil, fmt.Errorf("gpgagent: signing via agent: %w", err)
		}
		return sig, nil

	case *eddsa.PublicKey:
		dummy := eddsa.NewPrivateKey(*pk)
		dummy.D = make([]byte, 32)
		if _, err := rand.Read(dummy.D); err != nil {
			return nil, err
		}

		priv := &packet.PrivateKey{PublicKey: *signer, PrivateKey: dummy}
		if err := sig.Sign(hasher, priv, cfg); err != nil {
			return nil, fmt.Errorf("preparing signature for agent: %w", err)
		}
		digest := hasher.Sum(nil)

		node, err := client.Sign(keygrip, keyDesc, signer.PubKeyAlgo, hash, digest)
		if err != nil {
			return nil, err
		}
		r, s, err := parseEdDSASigVal(node)
		if err != nil {
			return nil, err
		}
		sig.EdDSASigR = newMPIField(r)
		sig.EdDSASigS = newMPIField(s)
		return sig, nil

	default:
		return nil, fmt.Errorf("gpgagent: signing via agent is not supported for this key algorithm")
	}
}

// AgentSignDetached signs data (the exact bytes of the file being
// signed) with a key gpg-agent holds, returning a detached signature
// packet, armored if requested.
func AgentSignDetached(data []byte, pub *pgpcrypto.Key, signer *packet.PublicKey, keygrip, keyDesc string, client *gpgagent.Client, armor bool) ([]byte, error) {
	e := pub.GetEntity()
	sig, err := agentSign(e, signer, keygrip, keyDesc, client, packet.SigTypeBinary, pickHashForSigning(e), bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	if err := sig.Serialize(&buf); err != nil {
		return nil, err
	}
	if armor {
		s, err := armorSignature(buf.Bytes())
		if err != nil {
			return nil, err
		}
		return []byte(s), nil
	}
	return buf.Bytes(), nil
}

// nopWriteCloser adapts an io.Writer (here, a *bytes.Buffer) to
// io.WriteCloser for packet.SerializeLiteral, which needs to Close its
// writer to finalize the literal packet's length — without that closing
// also finalizing (or otherwise disturbing) the buffer the trailing
// Signature packet still needs to be appended to.
type nopWriteCloser struct{ io.Writer }

func (nopWriteCloser) Close() error { return nil }

// writeAgentSignedPayload writes a one-pass signature packet, the
// literal data itself, and a trailing signature packet into w, with the
// signing operation performed by gpg-agent — the structure gpg's plain
// `-s` (sign without encrypting) produces, and also the payload a
// signed-and-encrypted (-se) message compresses and symmetrically
// encrypts. w need not be seekable or bufferable in memory (it's
// typically the still-open compression/encryption writer of an
// in-progress outer packet), which is why this writes directly into it
// rather than returning a byte slice.
func writeAgentSignedPayload(w io.Writer, data []byte, e *openpgp.Entity, signer *packet.PublicKey, filename, keygrip, keyDesc string, client *gpgagent.Client) (*packet.Signature, error) {
	sig, err := agentSign(e, signer, keygrip, keyDesc, client, packet.SigTypeBinary, pickHashForSigning(e), bytes.NewReader(data))
	if err != nil {
		return nil, err
	}

	ops := &packet.OnePassSignature{
		Version:    3,
		SigType:    packet.SigTypeBinary,
		Hash:       sig.Hash,
		PubKeyAlgo: signer.PubKeyAlgo,
		KeyId:      signer.KeyId,
		IsLast:     true,
	}
	if err := ops.Serialize(w); err != nil {
		return nil, err
	}

	// nopWriteCloser: closing the literal packet writer must only
	// finalize ITS OWN length framing, not cascade into closing w — w
	// (typically a compression writer) still needs the trailing
	// Signature packet written into it below, and its own Close comes
	// later, once the caller is done with it entirely.
	lw, err := packet.SerializeLiteral(nopWriteCloser{w}, true, filename, uint32(sig.CreationTime.Unix()))
	if err != nil {
		return nil, err
	}
	if _, err := lw.Write(data); err != nil {
		return nil, err
	}
	if err := lw.Close(); err != nil {
		return nil, err
	}

	if err := sig.Serialize(w); err != nil {
		return nil, err
	}
	return sig, nil
}

// AgentSignEmbedded produces an inline-signed message — a one-pass
// signature packet, the literal data itself, and a trailing signature
// packet — matching the structure gpg's plain `-s` (sign without
// encrypting) produces, with the signing operation performed by
// gpg-agent.
func AgentSignEmbedded(data []byte, pub *pgpcrypto.Key, signer *packet.PublicKey, filename, keygrip, keyDesc string, client *gpgagent.Client, armor bool) ([]byte, error) {
	var buf bytes.Buffer
	if _, err := writeAgentSignedPayload(&buf, data, pub.GetEntity(), signer, filename, keygrip, keyDesc, client); err != nil {
		return nil, err
	}

	if armor {
		s, err := armorMessage(buf.Bytes())
		if err != nil {
			return nil, err
		}
		return []byte(s), nil
	}
	return buf.Bytes(), nil
}

// AgentClearSign produces a cleartext-signed message (RFC 4880 §7) over
// text, with the signing operation performed by gpg-agent. The
// signature itself is an ordinary text-mode detached signature (exactly
// what opsutil.ClearSign's local path produces via KeyRing.SignDetached
// on a text PlainMessage); only the framing differs, and that framing is
// independent of who signed, so the same armorClearSigned helper is
// reused. The hash is hardcoded to SHA512 (not pickHashForSigning's
// usual per-key choice) because armorClearSigned (matching GopenPGP's
// own ClearTextMessage.GetArmored) writes a fixed "Hash: SHA512" armor
// header unconditionally — using anything else here would produce a
// message whose declared and actual hash algorithms disagree
// ("signature digest conflict"), exactly matching gopenpgp's own local
// ClearSign, which relies on this same SHA512 default via its own
// signing config.
func AgentClearSign(text string, pub *pgpcrypto.Key, signer *packet.PublicKey, keygrip, keyDesc string, client *gpgagent.Client) (string, error) {
	sig, err := agentSign(pub.GetEntity(), signer, keygrip, keyDesc, client, packet.SigTypeText, stdcrypto.SHA512, strings.NewReader(text))
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	if err := sig.Serialize(&buf); err != nil {
		return "", err
	}
	return armorClearSigned(text, buf.Bytes())
}

// agentRSASigner implements crypto.Signer, delegating the actual RSA
// signing operation to gpg-agent. go-crypto's Signature.Sign accepts
// this directly for PubKeyAlgoRSA.
type agentRSASigner struct {
	client           *gpgagent.Client
	keygrip, keyDesc string
	pub              *stdrsa.PublicKey
}

func (a *agentRSASigner) Public() stdcrypto.PublicKey { return a.pub }

func (a *agentRSASigner) Sign(_ io.Reader, digest []byte, opts stdcrypto.SignerOpts) ([]byte, error) {
	node, err := a.client.Sign(a.keygrip, a.keyDesc, packet.PubKeyAlgoRSA, opts.HashFunc(), digest)
	if err != nil {
		return nil, err
	}
	return parseRSASigVal(node)
}

// sigValInner returns the algorithm-specific sublist of a parsed
// "(sig-val (<algo> ...))" gpg-agent PKSIGN result.
func sigValInner(node *sexp.Node) (*sexp.Node, error) {
	if !node.IsList() || node.Len() != 2 || node.Get(0).Str() != "sig-val" {
		return nil, fmt.Errorf("gpgagent: unexpected PKSIGN result shape")
	}
	inner := node.Get(1)
	if !inner.IsList() {
		return nil, fmt.Errorf("gpgagent: unexpected PKSIGN result shape")
	}
	return inner, nil
}

func parseEdDSASigVal(node *sexp.Node) (r, s []byte, err error) {
	inner, err := sigValInner(node)
	if err != nil {
		return nil, nil, err
	}
	rNode, sNode := inner.Find("r"), inner.Find("s")
	if rNode == nil || sNode == nil || !rNode.Get(1).IsAtom() || !sNode.Get(1).IsAtom() {
		return nil, nil, fmt.Errorf("gpgagent: malformed eddsa sig-val")
	}
	return rNode.Get(1).Atom, sNode.Get(1).Atom, nil
}

func parseRSASigVal(node *sexp.Node) ([]byte, error) {
	inner, err := sigValInner(node)
	if err != nil {
		return nil, err
	}
	sNode := inner.Find("s")
	if sNode == nil || !sNode.Get(1).IsAtom() {
		return nil, fmt.Errorf("gpgagent: malformed rsa sig-val")
	}
	return sNode.Get(1).Atom, nil
}
