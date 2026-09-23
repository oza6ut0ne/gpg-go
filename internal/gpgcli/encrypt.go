package gpgcli

import (
	"fmt"
	"path/filepath"

	"github.com/ProtonMail/gopenpgp/v2/crypto"
	"github.com/oza6ut0ne/gpg-go/internal/keystore"
	"github.com/oza6ut0ne/gpg-go/internal/opsutil"
)

func cmdEncrypt(o *Options) error {
	var inputPath string
	if len(o.Args) > 0 {
		inputPath = o.Args[0]
	}
	data, err := readInput(inputPath)
	if err != nil {
		return err
	}

	store, err := openStore(o)
	if err != nil {
		return err
	}

	recipients, hiddenRecipients, err := resolveEncryptionRecipients(o, store.PublicKeys())
	if err != nil {
		return err
	}

	var filename string
	if inputPath != "" && inputPath != "-" {
		filename = filepath.Base(inputPath)
	}

	var ciphertext []byte
	switch {
	case o.Sign:
		ciphertext, err = encryptAndSign(o, store, recipients, hiddenRecipients, data, filename)
	case len(hiddenRecipients) > 0:
		ciphertext, err = opsutil.EncryptWithHiddenRecipients(data, filename, recipients, hiddenRecipients, nil, o.Armor)
	default:
		ciphertext, err = opsutil.Encrypt(data, filename, recipients, nil, o.Armor)
	}
	if err != nil {
		return err
	}

	suffix := ".gpg"
	if o.Armor {
		suffix = ".asc"
	}
	outPath := outputPath(o, inputPath, suffix)
	return writeOutput(o, outPath, ciphertext, 0o644)
}

// encryptAndSign handles -se (sign-and-encrypt): preferring a signing
// key gpg-agent already holds — required for a smartcard-only signing
// key, which has no local private material to fall back to — and
// otherwise falling back to this tool's own private-keys-v1.d handling.
func encryptAndSign(o *Options, store *keystore.Store, recipients, hiddenRecipients []*crypto.Key, data []byte, filename string) ([]byte, error) {
	pub, err := pickSigner(o, store.SecretKeys())
	if err != nil {
		return nil, err
	}
	label := signerLabel(o, pub)

	if client, signer, grip, ok := agentSigningTarget(o, pub); ok {
		defer client.Close()
		client.SetPassphraseFunc(agentPassphraseFunc(o, label))
		desc := opsutil.AgentKeyDesc(label, "Sign and encrypt a message")
		ciphertext, err := opsutil.AgentEncryptAndSign(data, filename, recipients, hiddenRecipients, pub, signer, grip, desc, client, o.Armor)
		if err != nil {
			return nil, fmt.Errorf("signing via gpg-agent: %w", err)
		}
		return ciphertext, nil
	}

	signerKey, err := unlockKey(o, store, pub, label)
	if err != nil {
		return nil, err
	}
	if len(hiddenRecipients) > 0 {
		return opsutil.EncryptWithHiddenRecipients(data, filename, recipients, hiddenRecipients, signerKey, o.Armor)
	}
	return opsutil.Encrypt(data, filename, recipients, signerKey, o.Armor)
}
