package opsutil

import (
	"bytes"
	"fmt"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/ProtonMail/gopenpgp/v2/crypto"
	"github.com/oza6ut0ne/gpg-go/internal/gpgagent"
)

// EncryptWithHiddenRecipients encrypts data for visible and hidden
// recipients, optionally signing it with signer (an unlocked private
// key, may be nil). A hidden recipient's key ID is replaced with the
// OpenPGP wildcard (all zero) key ID in its session-key packet, as gpg's
// -R/--hidden-recipient does, so the ciphertext alone does not reveal
// who it was encrypted to.
//
// GopenPGP/go-crypto's own high-level Encrypt does not expose this
// per-recipient option. This builds the session-key (PKESK) packets
// itself using the same lower-level primitive go-crypto's own encrypt()
// uses internally, but delegates the tricky part — framing the
// compressed, (optionally) signed, symmetrically-encrypted data packet —
// to GopenPGP's own well-tested crypto.SessionKey encryption, by fixing
// the session key ourselves and reusing it for both parts.
func EncryptWithHiddenRecipients(
	data []byte, filename string,
	visible, hidden []*crypto.Key,
	signer *crypto.Key, armor bool,
) ([]byte, error) {
	if len(visible)+len(hidden) == 0 {
		return nil, fmt.Errorf("no recipients specified")
	}

	sk, err := crypto.GenerateSessionKey()
	if err != nil {
		return nil, fmt.Errorf("encrypting: %w", err)
	}
	cipher, err := sk.GetCipherFunc()
	if err != nil {
		return nil, fmt.Errorf("encrypting: %w", err)
	}

	cfg := &packet.Config{Time: func() time.Time { return time.Now() }}
	keyBytes, err := serializeRecipientKeys(sk, cipher, visible, hidden, cfg)
	if err != nil {
		return nil, err
	}

	msg := crypto.NewPlainMessage(data)
	if filename != "" {
		msg.Filename = filename
	}

	var dataPacket []byte
	if signer != nil {
		signRing, err := PrivateKeyRing(signer)
		if err != nil {
			return nil, err
		}
		dataPacket, err = sk.EncryptAndSign(msg, signRing)
		if err != nil {
			return nil, fmt.Errorf("encrypting: %w", err)
		}
	} else {
		dataPacket, err = sk.EncryptWithCompression(msg)
		if err != nil {
			return nil, fmt.Errorf("encrypting: %w", err)
		}
	}

	full := append(keyBytes, dataPacket...)
	if armor {
		s, err := armorMessage(full)
		if err != nil {
			return nil, err
		}
		return []byte(s), nil
	}
	return full, nil
}

// serializeRecipientKeys builds the PKESK packets for visible and hidden
// recipients of session key sk, in that order — the same per-recipient
// PKESK construction EncryptWithHiddenRecipients uses, factored out so
// AgentEncryptAndSign (below) can build the same recipient-key packets
// without duplicating this loop.
func serializeRecipientKeys(sk *crypto.SessionKey, cipher packet.CipherFunction, visible, hidden []*crypto.Key, cfg *packet.Config) ([]byte, error) {
	var keyBuf bytes.Buffer
	writeRecipient := func(k *crypto.Key, hide bool) error {
		pk, ok := k.GetEntity().EncryptionKey(cfg.Now())
		if !ok {
			return fmt.Errorf("key %s has no usable encryption subkey", k.GetFingerprint())
		}
		return packet.SerializeEncryptedKeyAEADwithHiddenOption(&keyBuf, pk.PublicKey, cipher, false, sk.Key, hide, cfg)
	}
	for _, k := range visible {
		if err := writeRecipient(k, false); err != nil {
			return nil, err
		}
	}
	for _, k := range hidden {
		if err := writeRecipient(k, true); err != nil {
			return nil, err
		}
	}
	return keyBuf.Bytes(), nil
}

// AgentEncryptAndSign encrypts data for visible and hidden recipients —
// the same semantics as EncryptWithHiddenRecipients — while signing it
// with a key gpg-agent holds (signer identifies which of pub's keys:
// primary or a subkey), rather than needing local private key material.
// This is what makes -se (sign-and-encrypt) usable with a smartcard-only
// signing key.
//
// Like EncryptWithHiddenRecipients, this fixes the session key and
// builds the PKESK packets itself, but unlike it, the compressed+signed
// data packet also can't be delegated to GopenPGP's own
// SessionKey.EncryptAndSign (which requires locally-held private key
// material to sign with) — so this instead drives go-crypto's own
// lower-level SerializeSymmetricallyEncrypted/SerializeCompressed
// directly, writing the one-pass-signature+literal+signature sequence
// (built via writeAgentSignedPayload, the same one -s/AgentSignEmbedded
// uses) into the compression writer exactly as go-crypto's own
// writeAndSign does internally, to get its close-ordering right without
// re-deriving it from scratch.
func AgentEncryptAndSign(
	data []byte, filename string,
	visible, hidden []*crypto.Key,
	pub *crypto.Key, signer *packet.PublicKey, keygrip, keyDesc string, client *gpgagent.Client,
	armor bool,
) ([]byte, error) {
	if len(visible)+len(hidden) == 0 {
		return nil, fmt.Errorf("no recipients specified")
	}

	sk, err := crypto.GenerateSessionKey()
	if err != nil {
		return nil, fmt.Errorf("encrypting: %w", err)
	}
	cipher, err := sk.GetCipherFunc()
	if err != nil {
		return nil, fmt.Errorf("encrypting: %w", err)
	}

	cfg := &packet.Config{Time: func() time.Time { return time.Now() }}
	keyBytes, err := serializeRecipientKeys(sk, cipher, visible, hidden, cfg)
	if err != nil {
		return nil, err
	}

	var dataBuf bytes.Buffer
	seipd, err := packet.SerializeSymmetricallyEncrypted(&dataBuf, cipher, false, packet.CipherSuite{Cipher: cipher}, sk.Key, cfg)
	if err != nil {
		return nil, fmt.Errorf("encrypting: %w", err)
	}
	compressWriter, err := packet.SerializeCompressed(seipd, packet.CompressionZLIB, nil)
	if err != nil {
		return nil, fmt.Errorf("encrypting: %w", err)
	}

	if _, err := writeAgentSignedPayload(compressWriter, data, pub.GetEntity(), signer, filename, keygrip, keyDesc, client); err != nil {
		return nil, fmt.Errorf("encrypting: %w", err)
	}
	if err := compressWriter.Close(); err != nil {
		return nil, fmt.Errorf("encrypting: %w", err)
	}

	full := append(keyBytes, dataBuf.Bytes()...)
	if armor {
		s, err := armorMessage(full)
		if err != nil {
			return nil, err
		}
		return []byte(s), nil
	}
	return full, nil
}
