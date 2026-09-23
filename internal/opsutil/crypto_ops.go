// Package opsutil implements the cryptographic operations of the tool
// (encrypt/decrypt/sign/verify/symmetric, key generation) on top of
// GopenPGP's crypto.KeyRing API.
package opsutil

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"time"

	openpgp "github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/ProtonMail/gopenpgp/v2/crypto"
)

// PublicKeyRing builds a KeyRing containing only the public parts of keys.
func PublicKeyRing(keys []*crypto.Key) (*crypto.KeyRing, error) {
	kr, err := crypto.NewKeyRing(nil)
	if err != nil {
		return nil, err
	}
	for _, k := range keys {
		pub := k
		if k.IsPrivate() {
			p, err := k.ToPublic()
			if err != nil {
				return nil, err
			}
			pub = p
		}
		if err := kr.AddKey(pub); err != nil {
			return nil, err
		}
	}
	return kr, nil
}

// PrivateKeyRing builds a KeyRing from already-unlocked private keys.
func PrivateKeyRing(keys ...*crypto.Key) (*crypto.KeyRing, error) {
	kr, err := crypto.NewKeyRing(nil)
	if err != nil {
		return nil, err
	}
	for _, k := range keys {
		if k == nil {
			continue
		}
		if err := kr.AddKey(k); err != nil {
			return nil, err
		}
	}
	return kr, nil
}

// Encrypt encrypts data for the given recipient public keys, optionally
// signing it with signer (an unlocked private key, may be nil).
func Encrypt(data []byte, filename string, recipients []*crypto.Key, signer *crypto.Key, armor bool) ([]byte, error) {
	if len(recipients) == 0 {
		return nil, fmt.Errorf("no recipients specified")
	}
	pubRing, err := PublicKeyRing(recipients)
	if err != nil {
		return nil, err
	}

	var signRing *crypto.KeyRing
	if signer != nil {
		signRing, err = PrivateKeyRing(signer)
		if err != nil {
			return nil, err
		}
	}

	msg := crypto.NewPlainMessage(data)
	if filename != "" {
		msg.Filename = filename
	}

	pgpMsg, err := pubRing.EncryptWithCompression(msg, signRing)
	if err != nil {
		return nil, fmt.Errorf("encrypting: %w", err)
	}

	if armor {
		s, err := armorMessage(pgpMsg.GetBinary())
		if err != nil {
			return nil, err
		}
		return []byte(s), nil
	}
	return pgpMsg.GetBinary(), nil
}

// DecryptResult carries the outcome of a Decrypt call.
type DecryptResult struct {
	Plaintext  []byte
	Filename   string
	Verified   bool   // true if a signature was present and matched a provided verify key
	SignedByID string // hex key ID of the signer, if a signature was found
	SigError   error  // non-nil if a signature was present but did not verify
}

// DecryptMessage decrypts an already-parsed PGP message using the given
// (unlocked) secret keys, optionally verifying an embedded signature
// against verifyKeys. secretKeys may be empty for a signed-but-not-encrypted
// message. Unlike GopenPGP's own KeyRing.Decrypt, this reports the actual
// signer key ID even for a signed-then-encrypted message, since the
// signature (and its issuer) is only visible after decryption.
func DecryptMessage(pgpMsg *crypto.PGPMessage, secretKeys []*crypto.Key, verifyKeys []*crypto.Key) (*DecryptResult, error) {
	var entities openpgp.EntityList
	for _, k := range secretKeys {
		entities = append(entities, k.GetEntity())
	}
	for _, k := range verifyKeys {
		entities = append(entities, k.GetEntity())
	}

	cfg := &packet.Config{Time: func() time.Time { return time.Now() }}
	md, err := openpgp.ReadMessage(bytes.NewReader(pgpMsg.GetBinary()), entities, nil, cfg)
	if err != nil {
		return nil, fmt.Errorf("decrypting: %w", err)
	}
	return readDecryptResult(md)
}

// DecryptDataPacketWithSessionKey decrypts an OpenPGP symmetrically (or
// AEAD) encrypted data packet using an already-recovered session key —
// the gpg-agent-decrypt counterpart of DecryptMessage, needed because
// gopenpgp's own SessionKey.DecryptAndVerify/Decrypt don't expose the
// signer's key ID the way go-crypto's openpgp.ReadMessage's
// MessageDetails does (used here for exactly the same reason
// DecryptMessage bypasses GopenPGP's own KeyRing.Decrypt), and because
// SessionKey.DecryptAndVerify errors out when the message has no
// embedded signature at all rather than treating that as unsigned (as
// DecryptMessage/openpgp.ReadMessage correctly do).
func DecryptDataPacketWithSessionKey(sk *crypto.SessionKey, dataPacket []byte, verifyKeys []*crypto.Key) (*DecryptResult, error) {
	p, err := packet.NewReader(bytes.NewReader(dataPacket)).Next()
	if err != nil {
		return nil, fmt.Errorf("decrypting: %w", err)
	}
	edp, ok := p.(packet.EncryptedDataPacket)
	if !ok {
		return nil, fmt.Errorf("decrypting: not an encrypted data packet")
	}
	cipherFunc, err := sk.GetCipherFunc()
	if err != nil {
		return nil, fmt.Errorf("decrypting: %w", err)
	}
	decrypted, err := edp.Decrypt(cipherFunc, sk.Key)
	if err != nil {
		return nil, fmt.Errorf("decrypting: %w", err)
	}

	var entities openpgp.EntityList
	for _, k := range verifyKeys {
		entities = append(entities, k.GetEntity())
	}

	cfg := &packet.Config{Time: func() time.Time { return time.Now() }}
	md, err := openpgp.ReadMessage(decrypted, entities, nil, cfg)
	if err != nil {
		return nil, fmt.Errorf("decrypting: %w", err)
	}
	return readDecryptResult(md)
}

// readDecryptResult reads md's body and reports its signature status,
// shared by DecryptMessage and DecryptDataPacketWithSessionKey.
func readDecryptResult(md *openpgp.MessageDetails) (*DecryptResult, error) {
	body, err := io.ReadAll(md.UnverifiedBody)
	if err != nil {
		return nil, fmt.Errorf("decrypting: %w", err)
	}

	res := &DecryptResult{
		Plaintext: body,
	}
	if md.LiteralData != nil {
		res.Filename = md.LiteralData.FileName
	}
	if md.IsSigned {
		res.SignedByID = fmt.Sprintf("%016x", md.SignedByKeyId)
		switch {
		case md.SignatureError != nil:
			res.SigError = md.SignatureError
		case md.SignedBy != nil:
			res.Verified = true
		}
	}
	return res, nil
}

// LoadPGPMessage parses data (armored or binary) into a PGPMessage.
func LoadPGPMessage(data []byte) (*crypto.PGPMessage, error) {
	trimmed := strings.TrimSpace(string(data))
	if strings.HasPrefix(trimmed, "-----BEGIN PGP") {
		return crypto.NewPGPMessageFromArmored(trimmed)
	}
	return crypto.NewPGPMessage(data), nil
}

func loadPGPMessage(data []byte) (*crypto.PGPMessage, error) { return LoadPGPMessage(data) }

// IsSymmetric reports whether data (armored or binary) starts with a
// symmetric-key encrypted session key packet (gpg -c output), as opposed to
// public-key encrypted or signed-only data.
func IsSymmetric(data []byte) bool {
	msg, err := LoadPGPMessage(data)
	if err != nil {
		return false
	}
	packets := packet.NewReader(bytes.NewReader(msg.GetBinary()))
	for {
		p, err := packets.Next()
		if err != nil {
			return false
		}
		switch p.(type) {
		case *packet.SymmetricKeyEncrypted:
			return true
		case *packet.EncryptedKey:
			return false
		case *packet.SymmetricallyEncrypted, *packet.AEADEncrypted,
			*packet.Compressed, *packet.LiteralData, *packet.OnePassSignature:
			return false
		}
	}
}

// SignMessage produces a signed (but not encrypted) OpenPGP message
// containing data, as gpg's plain "-s" (without "-e") does.
func SignMessage(data []byte, filename string, signer *crypto.Key, armor bool) ([]byte, error) {
	entity := signer.GetEntity()

	cfg := &packet.Config{DefaultCompressionAlgo: packet.CompressionZLIB}
	hints := &openpgp.FileHints{FileName: filename, IsBinary: true}

	var buf bytes.Buffer
	w, err := openpgp.Sign(&buf, entity, hints, cfg)
	if err != nil {
		return nil, fmt.Errorf("signing: %w", err)
	}
	if _, err := w.Write(data); err != nil {
		return nil, fmt.Errorf("signing: %w", err)
	}
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("signing: %w", err)
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

// SignDetached produces a detached signature over data using signer.
func SignDetached(data []byte, signer *crypto.Key, armor bool) ([]byte, error) {
	kr, err := PrivateKeyRing(signer)
	if err != nil {
		return nil, err
	}
	sig, err := kr.SignDetached(crypto.NewPlainMessage(data))
	if err != nil {
		return nil, fmt.Errorf("signing: %w", err)
	}
	if armor {
		s, err := armorSignature(sig.GetBinary())
		if err != nil {
			return nil, err
		}
		return []byte(s), nil
	}
	return sig.GetBinary(), nil
}

// VerifyDetached checks a detached signature over data against the given
// public keys. Returns the hex key ID of the signer on success.
func VerifyDetached(data, sigData []byte, verifyKeys []*crypto.Key) (string, error) {
	verifyRing, err := PublicKeyRing(verifyKeys)
	if err != nil {
		return "", err
	}

	var sig *crypto.PGPSignature
	trimmed := strings.TrimSpace(string(sigData))
	if strings.HasPrefix(trimmed, "-----BEGIN PGP SIGNATURE-----") {
		sig, err = crypto.NewPGPSignatureFromArmored(trimmed)
	} else {
		sig = crypto.NewPGPSignature(sigData)
	}
	if err != nil {
		return "", err
	}

	keyID := ""
	if ids, ok := sig.GetHexSignatureKeyIDs(); ok && len(ids) > 0 {
		keyID = ids[0]
	}

	if err := verifyRing.VerifyDetached(crypto.NewPlainMessage(data), sig, crypto.GetUnixTime()); err != nil {
		return keyID, err
	}
	return keyID, nil
}

// ClearSign produces a PGP cleartext-signed message.
func ClearSign(text string, signer *crypto.Key) (string, error) {
	kr, err := PrivateKeyRing(signer)
	if err != nil {
		return "", err
	}
	message := crypto.NewPlainMessageFromString(text)
	signature, err := kr.SignDetached(message)
	if err != nil {
		return "", fmt.Errorf("signing: %w", err)
	}
	return armorClearSigned(string(message.GetBinary()), signature.GetBinary())
}

// VerifyClearSigned verifies a cleartext-signed message and returns its
// text. The returned text is de-canonicalized (CRLF line endings
// converted to LF, and the final line ending — which the clearsign
// canonical form always omits, since it isn't part of what's hashed —
// restored) to match what the text looked like before signing, the same
// way real gpg's own -d/--decrypt reconstructs it; ctm.GetString()
// itself is in the RFC 4880 canonical text form (CRLF, no trailing
// newline) used for hashing, which is what's still fed to VerifyDetached
// below, unaffected by this.
func VerifyClearSigned(armored string, verifyKeys []*crypto.Key) (text, keyID string, err error) {
	verifyRing, err := PublicKeyRing(verifyKeys)
	if err != nil {
		return "", "", err
	}
	ctm, err := crypto.NewClearTextMessageFromArmored(armored)
	if err != nil {
		return "", "", err
	}
	message := crypto.NewPlainMessageFromString(ctm.GetString())
	sig := crypto.NewPGPSignature(ctm.GetBinarySignature())
	if ids, ok := sig.GetHexSignatureKeyIDs(); ok && len(ids) > 0 {
		keyID = ids[0]
	}
	err = verifyRing.VerifyDetached(message, sig, crypto.GetUnixTime())
	return deCanonicalizeClearsignText(ctm.GetString()), keyID, err
}

// deCanonicalizeClearsignText converts a clearsign block's canonical
// (CRLF, no final line ending) text back to plain LF text terminated by
// a trailing newline, matching real gpg's own -d/--decrypt output byte
// for byte (verified against it) — including that a trailing newline is
// always added, since the canonical form can't distinguish "the
// original text ended with one" from "it didn't".
func deCanonicalizeClearsignText(canonical string) string {
	text := strings.ReplaceAll(canonical, "\r\n", "\n")
	if !strings.HasSuffix(text, "\n") {
		text += "\n"
	}
	return text
}

// SymmetricEncrypt password-encrypts data (gpg -c).
func SymmetricEncrypt(data []byte, filename string, password []byte, armor bool) ([]byte, error) {
	msg := crypto.NewPlainMessage(data)
	if filename != "" {
		msg.Filename = filename
	}
	pgpMsg, err := crypto.EncryptMessageWithPassword(msg, password)
	if err != nil {
		return nil, fmt.Errorf("encrypting: %w", err)
	}
	if armor {
		s, err := armorMessage(pgpMsg.GetBinary())
		if err != nil {
			return nil, err
		}
		return []byte(s), nil
	}
	return pgpMsg.GetBinary(), nil
}

// SymmetricDecrypt decrypts a password-encrypted message.
func SymmetricDecrypt(data []byte, password []byte) ([]byte, string, error) {
	pgpMsg, err := loadPGPMessage(data)
	if err != nil {
		return nil, "", err
	}
	plain, err := crypto.DecryptMessageWithPassword(pgpMsg, password)
	if err != nil {
		return nil, "", fmt.Errorf("decrypting: %w", err)
	}
	return plain.GetBinary(), plain.GetFilename(), nil
}
