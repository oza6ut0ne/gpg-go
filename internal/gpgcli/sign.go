package gpgcli

import (
	"fmt"
	"path/filepath"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/ProtonMail/gopenpgp/v2/crypto"
	"github.com/oza6ut0ne/gpg-go/internal/gpgagent"
	"github.com/oza6ut0ne/gpg-go/internal/keystore"
	"github.com/oza6ut0ne/gpg-go/internal/opsutil"
)

func cmdSign(o *Options) error {
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
	pub, err := pickSigner(o, store.SecretKeys())
	if err != nil {
		return err
	}

	var filename string
	if inputPath != "" && inputPath != "-" {
		filename = filepath.Base(inputPath)
	}

	signed, err := signEmbedded(o, store, pub, data, filename)
	if err != nil {
		return err
	}

	suffix := ".gpg"
	if o.Armor {
		suffix = ".asc"
	}
	outPath := outputPath(o, inputPath, suffix)
	return writeOutput(o, outPath, signed, 0o644)
}

// agentSigningTarget finds a signing-capable key for pub that gpg-agent
// currently holds: pub's go-crypto-preferred signing key first (the same
// key local signing would pick), then any other signing-capable subkey.
// This fallback matters for smartcard-backed keys, since the agent may
// only be able to reach some of a key's signing candidates (e.g. no card
// inserted for one of several card-linked subkeys). ok=false means the
// agent is unreachable or holds none of pub's signing keys; the caller
// owns closing client whenever ok is true.
func agentSigningTarget(o *Options, pub *crypto.Key) (client *gpgagent.Client, signer *packet.PublicKey, grip string, ok bool) {
	e := pub.GetEntity()
	var candidates []*packet.PublicKey
	if best, isOk := e.SigningKeyById(time.Now(), 0); isOk {
		candidates = append(candidates, best.PublicKey)
	}
	for _, sub := range e.Subkeys {
		if sub.Sig == nil || !sub.Sig.FlagSign {
			continue
		}
		dup := false
		for _, c := range candidates {
			if c == sub.PublicKey {
				dup = true
				break
			}
		}
		if !dup {
			candidates = append(candidates, sub.PublicKey)
		}
	}

	for _, cand := range candidates {
		if !opsutil.AgentSigningSupported(cand) {
			continue
		}
		g, gok := opsutil.KeygripForPublicKey(cand)
		if !gok {
			continue
		}
		if client == nil {
			client = dialAgent(o)
			if client == nil {
				return nil, nil, "", false
			}
		}
		if have, _ := client.HaveKey(g); have {
			return client, cand, g, true
		}
	}
	if client != nil {
		client.Close()
	}
	return nil, nil, "", false
}

// signEmbedded produces an inline-signed (not detached) message over
// data, preferring a key gpg-agent already holds and falling back to
// this tool's own private-keys-v1.d handling.
func signEmbedded(o *Options, store *keystore.Store, pub *crypto.Key, data []byte, filename string) ([]byte, error) {
	label := signerLabel(o, pub)
	if client, signer, grip, ok := agentSigningTarget(o, pub); ok {
		defer client.Close()
		client.SetPassphraseFunc(agentPassphraseFunc(o, label))
		desc := opsutil.AgentKeyDesc(label, "Sign a message")
		sig, err := opsutil.AgentSignEmbedded(data, pub, signer, filename, grip, desc, client, o.Armor)
		if err != nil {
			return nil, fmt.Errorf("signing via gpg-agent: %w", err)
		}
		return sig, nil
	}

	signer, err := unlockKey(o, store, pub, label)
	if err != nil {
		return nil, err
	}
	return opsutil.SignMessage(data, filename, signer, o.Armor)
}

func cmdDetachSign(o *Options) error {
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
	pub, err := pickSigner(o, store.SecretKeys())
	if err != nil {
		return err
	}

	sig, err := signDetached(o, store, pub, data)
	if err != nil {
		return err
	}

	suffix := ".sig"
	if o.Armor {
		suffix = ".asc"
	}
	outPath := outputPath(o, inputPath, suffix)
	return writeOutput(o, outPath, sig, 0o644)
}

// signDetached produces a detached signature over data with pub,
// preferring a key gpg-agent already holds (which lets the agent's own
// passphrase cache, or a smartcard, do the work) and falling back to
// this tool's own private-keys-v1.d handling when the agent is
// unreachable, doesn't have the key, or doesn't support its algorithm.
func signDetached(o *Options, store *keystore.Store, pub *crypto.Key, data []byte) ([]byte, error) {
	label := signerLabel(o, pub)
	if client, signer, grip, ok := agentSigningTarget(o, pub); ok {
		defer client.Close()
		client.SetPassphraseFunc(agentPassphraseFunc(o, label))
		desc := opsutil.AgentKeyDesc(label, "Sign a message")
		sig, err := opsutil.AgentSignDetached(data, pub, signer, grip, desc, client, o.Armor)
		if err != nil {
			return nil, fmt.Errorf("signing via gpg-agent: %w", err)
		}
		return sig, nil
	}

	signer, err := unlockKey(o, store, pub, label)
	if err != nil {
		return nil, err
	}
	return opsutil.SignDetached(data, signer, o.Armor)
}

func cmdClearSign(o *Options) error {
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
	pub, err := pickSigner(o, store.SecretKeys())
	if err != nil {
		return err
	}

	signed, err := clearSign(o, store, pub, string(data))
	if err != nil {
		return err
	}

	outPath := outputPath(o, inputPath, ".asc")
	return writeOutput(o, outPath, []byte(signed), 0o644)
}

// clearSign produces a cleartext-signed message over text, preferring a
// key gpg-agent already holds and falling back to this tool's own
// private-keys-v1.d handling.
func clearSign(o *Options, store *keystore.Store, pub *crypto.Key, text string) (string, error) {
	label := signerLabel(o, pub)
	if client, signer, grip, ok := agentSigningTarget(o, pub); ok {
		defer client.Close()
		client.SetPassphraseFunc(agentPassphraseFunc(o, label))
		desc := opsutil.AgentKeyDesc(label, "Sign a message")
		s, err := opsutil.AgentClearSign(text, pub, signer, grip, desc, client)
		if err != nil {
			return "", fmt.Errorf("signing via gpg-agent: %w", err)
		}
		return s, nil
	}

	signer, err := unlockKey(o, store, pub, label)
	if err != nil {
		return "", err
	}
	return opsutil.ClearSign(text, signer)
}
