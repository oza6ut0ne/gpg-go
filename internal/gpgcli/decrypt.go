package gpgcli

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/ProtonMail/gopenpgp/v2/crypto"
	"github.com/oza6ut0ne/gpg-go/internal/gpgagent"
	"github.com/oza6ut0ne/gpg-go/internal/keystore"
	"github.com/oza6ut0ne/gpg-go/internal/opsutil"
)

// isWildcardKeyID reports whether id (as produced by
// PGPMessage.GetHexEncryptionKeyIDs) is the OpenPGP wildcard key ID
// (all zero bytes), used for a hidden/anonymous recipient.
func isWildcardKeyID(id string) bool {
	return strings.Trim(id, "0") == ""
}

func cmdDecrypt(o *Options) error {
	var inputPath string
	if len(o.Args) > 0 {
		inputPath = o.Args[0]
	}
	data, err := readInput(inputPath)
	if err != nil {
		return err
	}

	if opsutil.IsSymmetric(data) {
		return decryptSymmetric(o, data)
	}

	store, err := openStore(o)
	if err != nil {
		return err
	}

	// Real gpg's -d also accepts a detached signature or a clearsigned
	// message, not just an encrypted (or signed-but-not-encrypted) one —
	// it verifies and, for a clearsigned message, still writes out the
	// text (even with a BAD signature); a lone detached signature has no
	// content to write, only its verification report.
	if isDetachedSignature(data) {
		content, err := readInput(deriveDataFilename(inputPath))
		if err != nil {
			return err
		}
		keyID, err := opsutil.VerifyDetached(content, data, store.PublicKeys())
		printVerifyResult(o, keyID, err)
		return err
	}
	if trimmed := strings.TrimSpace(string(data)); strings.HasPrefix(trimmed, "-----BEGIN PGP SIGNED MESSAGE-----") {
		text, keyID, verr := opsutil.VerifyClearSigned(trimmed, store.PublicKeys())
		printVerifyResult(o, keyID, verr)
		outPath := ""
		if o.Output != "" {
			outPath = o.Output
		}
		if err := writeOutput(o, outPath, []byte(text), 0o644); err != nil {
			return err
		}
		return verr
	}

	pgpMsg, err := opsutil.LoadPGPMessage(data)
	if err != nil {
		return err
	}

	ids, hasIDs := pgpMsg.GetHexEncryptionKeyIDs()
	if hasIDs && len(ids) > 0 {
		var candidates []*crypto.Key
		hasWildcard := false
		for _, id := range ids {
			if isWildcardKeyID(id) {
				// A hidden/anonymous recipient (gpg's -R): the real key
				// ID was replaced with the OpenPGP wildcard, so it
				// cannot be looked up directly.
				hasWildcard = true
				continue
			}
			candidates = append(candidates, keystore.Find(store.SecretKeys(), id)...)
		}
		candidates = dedupeKeys(candidates)

		// Try gpg-agent (e.g. a smartcard) before any local fallback.
		agentCandidates := agentDecryptCandidates(candidates, hasWildcard, store.SecretKeys())
		if len(agentCandidates) > 0 {
			if res, handled, err := tryAgentDecryptECDH(o, store, pgpMsg.GetBinary(), pgpMsg, agentCandidates); handled {
				if err != nil {
					return err
				}
				return finishDecrypt(o, res)
			}
		}

		var secretKeys []*crypto.Key
		switch {
		case len(candidates) > 0:
			for _, k := range candidates {
				unlocked, err := unlockKey(o, store, k, keystore.LongKeyID(k.GetFingerprint()))
				if err != nil {
					return err
				}
				secretKeys = append(secretKeys, unlocked)
			}
		case hasWildcard:
			// Try every available secret key in turn, exactly as real
			// gpg does when it cannot tell which key a message is
			// encrypted to.
			for _, k := range store.SecretKeys() {
				unlocked, err := unlockKey(o, store, k, keystore.LongKeyID(k.GetFingerprint()))
				if err != nil {
					continue
				}
				secretKeys = append(secretKeys, unlocked)
			}
			if len(secretKeys) == 0 {
				return fmt.Errorf("no secret key available to decrypt this hidden-recipient message")
			}
		default:
			return fmt.Errorf("no secret key available to decrypt this message (recipient key IDs: %v)", ids)
		}

		var verifyKeys []*crypto.Key
		if sigIDs, ok := pgpMsg.GetHexSignatureKeyIDs(); ok && len(sigIDs) > 0 {
			for _, id := range sigIDs {
				verifyKeys = append(verifyKeys, keystore.Find(store.PublicKeys(), id)...)
			}
		}

		res, err := opsutil.DecryptMessage(pgpMsg, secretKeys, verifyKeys)
		if err != nil {
			return err
		}
		return finishDecrypt(o, res)
	}

	res, err := opsutil.DecryptMessage(pgpMsg, nil, nil)
	if err != nil {
		return err
	}
	return finishDecrypt(o, res)
}

// agentDecryptCandidates computes which secret keys are worth trying via
// gpg-agent before any local private-keys-v1.d fallback: the named
// recipient(s) resolved by real key ID, plus (only if a hidden/wildcard
// recipient is also present — as gpg.conf's own "hidden-recipient"
// setting can add alongside a plain -r for the very same key) every
// secret key we hold, since a hidden recipient's real key ID is unknown.
// This must run unconditionally (not skipped just because hasWildcard is
// true), since agent-only keys — e.g. a smartcard — have no local
// fallback to fall back to.
func agentDecryptCandidates(namedCandidates []*crypto.Key, hasWildcard bool, allSecretKeys []*crypto.Key) []*crypto.Key {
	if !hasWildcard {
		return namedCandidates
	}
	return dedupeKeys(append(append([]*crypto.Key{}, namedCandidates...), allSecretKeys...))
}

// tryAgentDecryptECDH attempts to decrypt using gpg-agent for one of
// candidates' Curve25519 ECDH subkeys, if gpg-agent is reachable and
// holds a matching key. handled=false means the caller should fall back
// to this tool's own private-keys-v1.d handling (agent unreachable, or
// none of the candidates' subkeys are agent-backed/ECDH); handled=true
// with a non-nil error means the agent attempt itself failed and should
// be reported rather than silently falling back.
func tryAgentDecryptECDH(o *Options, store *keystore.Store, data []byte, pgpMsg *crypto.PGPMessage, candidates []*crypto.Key) (*opsutil.DecryptResult, bool, error) {
	var client *gpgagent.Client
	defer func() {
		if client != nil {
			client.Close()
		}
	}()

	for _, k := range candidates {
		for _, sub := range k.GetEntity().Subkeys {
			if !opsutil.AgentDecryptSupported(sub.PublicKey) {
				continue
			}
			grip, ok := opsutil.KeygripForPublicKey(sub.PublicKey)
			if !ok {
				continue
			}
			if client == nil {
				client = dialAgent(o)
				if client == nil {
					return nil, false, nil
				}
			}
			have, _ := client.HaveKey(grip)
			if !have {
				continue
			}

			label := keystore.LongKeyID(k.GetFingerprint())
			client.SetPassphraseFunc(agentPassphraseFunc(o, label))
			desc := opsutil.AgentKeyDesc(label, "Decrypt a message")
			sk, err := opsutil.AgentDecryptSessionKeyECDH(data, sub.PublicKey, grip, desc, client)
			if errors.Is(err, opsutil.ErrPKESKNotFound) {
				// No PKESK is addressed to this subkey's real key ID —
				// it may still be a hidden recipient (gpg's -R), whose
				// real ID is never disclosed, so brute-force every
				// wildcard PKESK in the message against it before giving
				// up on this candidate. A message with no wildcard PKESK
				// at all makes this a cheap no-op (no agent calls).
				sk, err = opsutil.AgentDecryptSessionKeyECDHWildcard(data, sub.PublicKey, grip, desc, client)
				if errors.Is(err, opsutil.ErrPKESKNotFound) {
					continue
				}
			}
			if err != nil {
				return nil, true, fmt.Errorf("decrypting via gpg-agent: %w", err)
			}

			split, err := pgpMsg.SplitMessage()
			if err != nil {
				return nil, true, fmt.Errorf("decrypting via gpg-agent: %w", err)
			}

			// Verify an embedded signature (if any) against every public
			// key we have, reporting the actual signer key ID the same
			// way DecryptMessage does for the local-decrypt path — so
			// finishDecrypt's "Good/BAD signature" report also fires for
			// an agent-decrypted (e.g. smartcard) -se message.
			res, err := opsutil.DecryptDataPacketWithSessionKey(sk, split.GetBinaryDataPacket(), store.PublicKeys())
			if err != nil {
				return nil, true, fmt.Errorf("decrypting via gpg-agent: %w", err)
			}
			return res, true, nil
		}
	}
	return nil, false, nil
}

func finishDecrypt(o *Options, res *opsutil.DecryptResult) error {
	reportSignatureStatus(o, res.SignedByID, res.Verified, res.SigError)

	outPath := outputPath(o, "", "")
	if o.Output != "" {
		outPath = o.Output
	}
	return writeOutput(o, outPath, res.Plaintext, 0o644)
}

func decryptSymmetric(o *Options, data []byte) error {
	pass, err := ResolvePassphrase(o, "Enter passphrase: ")
	if err != nil {
		return err
	}
	plain, _, err := opsutil.SymmetricDecrypt(data, pass)
	if err != nil {
		return err
	}
	outPath := ""
	if o.Output != "" {
		outPath = o.Output
	}
	return writeOutput(o, outPath, plain, 0o644)
}

func dedupeKeys(keys []*crypto.Key) []*crypto.Key {
	seen := map[string]bool{}
	var out []*crypto.Key
	for _, k := range keys {
		fpr := k.GetFingerprint()
		if !seen[fpr] {
			seen[fpr] = true
			out = append(out, k)
		}
	}
	return out
}

func reportSignatureStatus(o *Options, keyID string, verified bool, sigErr error) {
	if keyID == "" {
		return
	}
	if sigErr != nil {
		fmt.Fprintf(os.Stderr, "gpg: BAD signature from key %s: %v\n", keyID, sigErr)
		return
	}
	if verified {
		fmt.Fprintf(os.Stderr, "gpg: Good signature from key %s\n", keyID)
		return
	}
	if !o.Quiet {
		fmt.Fprintf(os.Stderr, "gpg: signature from key %s present but not verified (public key not in keyring)\n", keyID)
	}
}
