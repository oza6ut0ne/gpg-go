package gnupgcompat

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	pgpcrypto "github.com/ProtonMail/gopenpgp/v2/crypto"
	"github.com/oza6ut0ne/gpg-go/internal/gpgagent"
	"github.com/oza6ut0ne/gpg-go/internal/keystore"
	"github.com/oza6ut0ne/gpg-go/internal/opsutil"
)

// buildRealGPGHomedir generates a passphrase-locked ed25519+cv25519 key
// with real gpg (so it, and its gpg-agent, are the ground truth), and
// returns the homedir, its keystore, and the key's own uid string.
func buildRealGPGHomedir(t *testing.T, passphrase string) (dir string, store *keystore.Store, uid string) {
	t.Helper()
	gpgPath := requireGPG(t)
	dir = t.TempDir()
	writeLoopbackAgentConf(t, dir)

	batch := fmt.Sprintf(`%%echo Generating a test key
Key-Type: eddsa
Key-Curve: ed25519
Subkey-Type: ecdh
Subkey-Curve: cv25519
Name-Real: Agent Test
Name-Email: agenttest@example.com
Expire-Date: 0
Passphrase: %s
%%commit
%%echo done
`, passphrase)
	batchPath := filepath.Join(dir, "genkey.batch")
	if err := os.WriteFile(batchPath, []byte(batch), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(gpgPath, "--homedir", dir, "--batch", "--pinentry-mode", "loopback", "--gen-key", batchPath)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("gpg --gen-key failed: %v\n%s", err, out.String())
	}

	store, err := keystore.Open(dir)
	if err != nil {
		t.Fatalf("keystore.Open: %v", err)
	}
	return dir, store, "Agent Test <agenttest@example.com>"
}

// TestAttachSecretMultiSubkeyNoPanic is a regression test for a panic
// ("unknown decrypter type in NewDecrypterPrivateKey") that occurred
// when a key had a dedicated EdDSA *signing* subkey in addition to its
// ECDH encryption subkey (a common real-world GnuPG layout: separate
// certify/encrypt/sign subkeys). attachOne used to dispatch EdDSA
// subkeys to NewDecrypterPrivateKey whenever isPrimary was false, but
// go-crypto's NewDecrypterPrivateKey has no case for *eddsa.PrivateKey
// at all, since EdDSA is sign-only.
func TestAttachSecretMultiSubkeyNoPanic(t *testing.T) {
	gpgPath := requireGPG(t)
	dir := t.TempDir()
	writeLoopbackAgentConf(t, dir)
	const passphrase = "hunter2"

	batch := `%echo Generating a test key
Key-Type: eddsa
Key-Curve: ed25519
Key-Usage: cert
Subkey-Type: ecdh
Subkey-Curve: cv25519
Subkey-Usage: encrypt
Name-Real: Multi Subkey Test
Name-Email: multisub@example.com
Expire-Date: 0
Passphrase: ` + passphrase + `
%commit
%echo done
`
	batchPath := filepath.Join(dir, "genkey.batch")
	if err := os.WriteFile(batchPath, []byte(batch), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(gpgPath, "--homedir", dir, "--batch", "--pinentry-mode", "loopback", "--gen-key", batchPath)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("gpg --gen-key failed: %v\n%s", err, out.String())
	}

	fprOut, err := exec.Command(gpgPath, "--homedir", dir, "-k", "--with-colons").Output()
	if err != nil {
		t.Fatalf("gpg -k: %v", err)
	}
	var fpr string
	for _, line := range bytes.Split(fprOut, []byte("\n")) {
		if bytes.HasPrefix(line, []byte("fpr:")) {
			fields := bytes.Split(line, []byte(":"))
			fpr = string(fields[9])
			break
		}
	}
	if fpr == "" {
		t.Fatalf("could not find fingerprint in:\n%s", fprOut)
	}

	// Add a dedicated EdDSA signing subkey, distinct from the ECDH
	// encryption subkey generated above — this is the layout that
	// triggered the panic.
	out.Reset()
	cmd = exec.Command(gpgPath, "--homedir", dir, "--batch", "--yes", "--pinentry-mode", "loopback",
		"--passphrase", passphrase, "--quick-add-key", fpr, "ed25519", "sign")
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("gpg --quick-add-key failed: %v\n%s", err, out.String())
	}

	store, err := keystore.Open(dir)
	if err != nil {
		t.Fatalf("keystore.Open: %v", err)
	}
	secs := keystore.Find(store.SecretKeys(), "multisub@example.com")
	if len(secs) != 1 {
		t.Fatalf("expected 1 matching secret key, got %d", len(secs))
	}
	pub := secs[0]
	if n := len(pub.GetEntity().Subkeys); n != 2 {
		t.Fatalf("expected 2 subkeys (encrypt + sign), got %d", n)
	}

	// This used to panic ("unknown decrypter type in
	// NewDecrypterPrivateKey") on the EdDSA signing subkey.
	attached, err := store.AttachSecret(pub, []byte(passphrase))
	if err != nil {
		t.Fatalf("AttachSecret: %v", err)
	}

	e := attached.GetEntity()
	if e.PrivateKey == nil {
		t.Fatal("primary key has no private key material attached")
	}
	var sawEncryptSubkey, sawSignSubkey bool
	for _, sub := range e.Subkeys {
		if sub.PrivateKey == nil {
			t.Fatalf("subkey %x has no private key material attached", sub.PublicKey.Fingerprint)
		}
		if sub.Sig != nil && (sub.Sig.FlagEncryptCommunications || sub.Sig.FlagEncryptStorage) {
			sawEncryptSubkey = true
		}
		if sub.Sig != nil && sub.Sig.FlagSign {
			sawSignSubkey = true
			// Verify the attached EdDSA signing subkey actually works.
			message := []byte("multi-subkey regression test\n")
			sig, err := opsutil.SignDetached(message, attached, true)
			if err != nil {
				t.Fatalf("SignDetached with attached signing subkey: %v", err)
			}
			dir2 := t.TempDir()
			msgPath := filepath.Join(dir2, "msg.txt")
			sigPath := msgPath + ".asc"
			if err := os.WriteFile(msgPath, message, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(sigPath, sig, 0o600); err != nil {
				t.Fatal(err)
			}
			verifyOut, err := exec.Command(gpgPath, "--homedir", dir, "--verify", sigPath, msgPath).CombinedOutput()
			t.Logf("gpg --verify:\n%s", verifyOut)
			if err != nil {
				t.Fatalf("real gpg failed to verify signature made with attached subkey: %v", err)
			}
		}
	}
	if !sawEncryptSubkey {
		t.Fatal("expected to find an encrypt-capable subkey")
	}
	if !sawSignSubkey {
		t.Fatal("expected to find a sign-capable subkey")
	}
}

func TestAgentSignAndDecrypt(t *testing.T) {
	requireGPG(t)
	const passphrase = "hunter2"
	dir, store, uid := buildRealGPGHomedir(t, passphrase)

	pubs := keystore.Find(store.PublicKeys(), uid)
	if len(pubs) != 1 {
		t.Fatalf("expected 1 matching key, got %d", len(pubs))
	}
	pub := pubs[0]
	e := pub.GetEntity()

	primaryGrip, ok := opsutil.KeygripForPublicKey(e.PrimaryKey)
	if !ok {
		t.Fatal("could not compute primary keygrip")
	}
	if len(e.Subkeys) != 1 {
		t.Fatalf("expected 1 subkey, got %d", len(e.Subkeys))
	}
	subGrip, ok := opsutil.KeygripForPublicKey(e.Subkeys[0].PublicKey)
	if !ok {
		t.Fatal("could not compute subkey keygrip")
	}

	client, err := gpgagent.NewClient(dir)
	if err != nil {
		t.Fatalf("gpgagent.NewClient: %v", err)
	}
	defer client.Close()
	client.SetPassphraseFunc(func() ([]byte, error) { return []byte(passphrase), nil })

	if have, err := client.HaveKey(primaryGrip); err != nil || !have {
		t.Fatalf("HaveKey(primary) = %v, %v", have, err)
	}

	t.Run("sign", func(t *testing.T) {
		message := []byte("hello from the agent test\n")
		sig, err := opsutil.AgentSignDetached(message, pub, e.PrimaryKey, primaryGrip, "test signing", client, true)
		if err != nil {
			t.Fatalf("AgentSignDetached: %v", err)
		}

		dir2 := t.TempDir()
		msgPath := filepath.Join(dir2, "msg.txt")
		sigPath := msgPath + ".asc"
		if err := os.WriteFile(msgPath, message, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(sigPath, sig, 0o600); err != nil {
			t.Fatal(err)
		}

		out, err := exec.Command("gpg", "--homedir", dir, "--verify", sigPath, msgPath).CombinedOutput()
		t.Logf("gpg --verify:\n%s", out)
		if err != nil {
			t.Fatalf("real gpg failed to verify the agent-produced signature: %v", err)
		}
		if !bytes.Contains(out, []byte("Good signature")) {
			t.Fatalf("expected a Good signature, got:\n%s", out)
		}
	})

	t.Run("decrypt", func(t *testing.T) {
		plaintext := []byte("secret payload for agent decrypt test\n")
		msgPath := filepath.Join(t.TempDir(), "in.txt")
		if err := os.WriteFile(msgPath, plaintext, 0o600); err != nil {
			t.Fatal(err)
		}
		encPath := msgPath + ".enc"
		out, err := exec.Command("gpg", "--homedir", dir, "--batch", "--yes", "--trust-model", "always",
			"-r", "agenttest@example.com", "-o", encPath, "--encrypt", msgPath).CombinedOutput()
		if err != nil {
			t.Fatalf("gpg --encrypt failed: %v\n%s", err, out)
		}
		ciphertext, err := os.ReadFile(encPath)
		if err != nil {
			t.Fatal(err)
		}

		subPub := e.Subkeys[0].PublicKey
		client.SetPassphraseFunc(func() ([]byte, error) { return []byte(passphrase), nil })
		sk, err := opsutil.AgentDecryptSessionKeyECDH(ciphertext, subPub, subGrip, "test decrypt", client)
		if err != nil {
			t.Fatalf("AgentDecryptSessionKeyECDH: %v", err)
		}

		pgpMsg, err := opsutil.LoadPGPMessage(ciphertext)
		if err != nil {
			t.Fatal(err)
		}
		split, err := pgpMsg.SplitMessage()
		if err != nil {
			t.Fatalf("SplitMessage: %v", err)
		}
		plain, err := sk.Decrypt(split.GetBinaryDataPacket())
		if err != nil {
			t.Fatalf("SessionKey.Decrypt: %v", err)
		}
		if !bytes.Equal(plain.GetBinary(), plaintext) {
			t.Fatalf("decrypted mismatch: got %q want %q", plain.GetBinary(), plaintext)
		}
	})
}

// TestAgentDecryptWildcardOnly is a regression test for decrypting a
// message that has ONLY a hidden-recipient (wildcard key ID) PKESK for
// an agent-backed key — no real-ID PKESK left over to fall back on, as
// happens for a plain -R (or gpg.conf's "hidden-recipient" combined with
// cmdEncrypt's own -r/-R dedup, which drops the redundant real PKESK
// once the same key is deduped to hidden). Before
// AgentDecryptSessionKeyECDHWildcard, gpg-agent-based decryption could
// only match a PKESK by its exact (non-hidden) key ID, so this case was
// undecryptable for a smartcard-only key.
func TestAgentDecryptWildcardOnly(t *testing.T) {
	requireGPG(t)
	const passphrase = "hunter2"
	dir, store, uid := buildRealGPGHomedir(t, passphrase)

	pubs := keystore.Find(store.PublicKeys(), uid)
	if len(pubs) != 1 {
		t.Fatalf("expected 1 matching key, got %d", len(pubs))
	}
	pub := pubs[0]
	e := pub.GetEntity()
	if len(e.Subkeys) != 1 {
		t.Fatalf("expected 1 subkey, got %d", len(e.Subkeys))
	}
	subPub := e.Subkeys[0].PublicKey
	subGrip, ok := opsutil.KeygripForPublicKey(subPub)
	if !ok {
		t.Fatal("could not compute subkey keygrip")
	}

	plaintext := []byte("wildcard-only agent decrypt test\n")
	ciphertext, err := opsutil.EncryptWithHiddenRecipients(plaintext, "", nil, []*pgpcrypto.Key{pub}, nil, false)
	if err != nil {
		t.Fatalf("EncryptWithHiddenRecipients: %v", err)
	}

	pgpMsg, err := opsutil.LoadPGPMessage(ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	ids, ok := pgpMsg.GetHexEncryptionKeyIDs()
	if !ok || len(ids) != 1 || ids[0] != "0000000000000000" {
		t.Fatalf("expected exactly one wildcard-ID PKESK, got %v", ids)
	}

	client, err := gpgagent.NewClient(dir)
	if err != nil {
		t.Fatalf("gpgagent.NewClient: %v", err)
	}
	defer client.Close()
	client.SetPassphraseFunc(func() ([]byte, error) { return []byte(passphrase), nil })

	// The exact-key-ID lookup must report "not found" for this message
	// (there is no real-ID PKESK at all) — not a hard error — so callers
	// know to fall back to the wildcard brute force.
	if _, err := opsutil.AgentDecryptSessionKeyECDH(ciphertext, subPub, subGrip, "test decrypt", client); !errors.Is(err, opsutil.ErrPKESKNotFound) {
		t.Fatalf("AgentDecryptSessionKeyECDH: expected ErrPKESKNotFound, got %v", err)
	}

	sk, err := opsutil.AgentDecryptSessionKeyECDHWildcard(ciphertext, subPub, subGrip, "test decrypt", client)
	if err != nil {
		t.Fatalf("AgentDecryptSessionKeyECDHWildcard: %v", err)
	}
	split, err := pgpMsg.SplitMessage()
	if err != nil {
		t.Fatalf("SplitMessage: %v", err)
	}
	plain, err := sk.Decrypt(split.GetBinaryDataPacket())
	if err != nil {
		t.Fatalf("SessionKey.Decrypt: %v", err)
	}
	if !bytes.Equal(plain.GetBinary(), plaintext) {
		t.Fatalf("decrypted mismatch: got %q want %q", plain.GetBinary(), plaintext)
	}
}

// TestAgentEncryptAndSign verifies -se (sign-and-encrypt) via gpg-agent:
// opsutil.AgentEncryptAndSign must produce a message that real gpg both
// decrypts AND verifies the embedded signature of, without any local
// private key material being available for the actual signing
// operation (this test's key is only ever unlocked through the agent).
func TestAgentEncryptAndSign(t *testing.T) {
	gpgPath := requireGPG(t)
	const passphrase = "hunter2"
	dir, store, uid := buildRealGPGHomedir(t, passphrase)

	pubs := keystore.Find(store.PublicKeys(), uid)
	if len(pubs) != 1 {
		t.Fatalf("expected 1 matching key, got %d", len(pubs))
	}
	pub := pubs[0]
	e := pub.GetEntity()

	primaryGrip, ok := opsutil.KeygripForPublicKey(e.PrimaryKey)
	if !ok {
		t.Fatal("could not compute primary keygrip")
	}

	client, err := gpgagent.NewClient(dir)
	if err != nil {
		t.Fatalf("gpgagent.NewClient: %v", err)
	}
	defer client.Close()
	client.SetPassphraseFunc(func() ([]byte, error) { return []byte(passphrase), nil })

	plaintext := []byte("sign-and-encrypt via agent test\n")
	ciphertext, err := opsutil.AgentEncryptAndSign(plaintext, "msg.txt", []*pgpcrypto.Key{pub}, nil, pub, e.PrimaryKey, primaryGrip, "test se", client, true)
	if err != nil {
		t.Fatalf("AgentEncryptAndSign: %v", err)
	}

	dir2 := t.TempDir()
	encPath := filepath.Join(dir2, "msg.asc")
	if err := os.WriteFile(encPath, ciphertext, 0o600); err != nil {
		t.Fatal(err)
	}

	out, err := exec.Command(gpgPath, "--homedir", dir, "--batch", "--yes", "--pinentry-mode", "loopback",
		"--passphrase", passphrase, "--decrypt", encPath).CombinedOutput()
	t.Logf("gpg --decrypt:\n%s", out)
	if err != nil {
		t.Fatalf("real gpg failed to decrypt/verify the agent-produced -se message: %v", err)
	}
	if !bytes.Contains(out, []byte("Good signature")) {
		t.Fatalf("expected a Good signature, got:\n%s", out)
	}
	if !bytes.Contains(out, plaintext) {
		t.Fatalf("expected decrypted output to contain the plaintext, got:\n%s", out)
	}

	// Regression check: decrypting this same -se message through
	// gpg-go's own agent-decrypt path (opsutil.DecryptDataPacketWithSessionKey,
	// which cmdDecrypt's tryAgentDecryptECDH uses) must also report the
	// embedded signature's status — SignedByID populated and
	// Verified=true — the same way opsutil.DecryptMessage already does
	// for the local-decrypt path, so cmdDecrypt's "Good signature from
	// key ..." stderr report (via reportSignatureStatus) fires for an
	// agent-decrypted (e.g. smartcard) -se message too.
	subPub := e.Subkeys[0].PublicKey
	subGrip, ok := opsutil.KeygripForPublicKey(subPub)
	if !ok {
		t.Fatal("could not compute subkey keygrip")
	}
	pgpMsg, err := opsutil.LoadPGPMessage(ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	sk, err := opsutil.AgentDecryptSessionKeyECDH(pgpMsg.GetBinary(), subPub, subGrip, "test decrypt", client)
	if err != nil {
		t.Fatalf("AgentDecryptSessionKeyECDH: %v", err)
	}
	split, err := pgpMsg.SplitMessage()
	if err != nil {
		t.Fatalf("SplitMessage: %v", err)
	}
	res, err := opsutil.DecryptDataPacketWithSessionKey(sk, split.GetBinaryDataPacket(), []*pgpcrypto.Key{pub})
	if err != nil {
		t.Fatalf("DecryptDataPacketWithSessionKey: %v", err)
	}
	wantID := fmt.Sprintf("%016x", e.PrimaryKey.KeyId)
	if res.SignedByID != wantID {
		t.Fatalf("SignedByID = %q, want %q", res.SignedByID, wantID)
	}
	if !res.Verified {
		t.Fatalf("expected Verified=true, got SigError=%v", res.SigError)
	}
	if !bytes.Equal(res.Plaintext, plaintext) {
		t.Fatalf("decrypted mismatch: got %q want %q", res.Plaintext, plaintext)
	}
}
