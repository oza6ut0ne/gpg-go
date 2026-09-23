package gpgcli

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/ProtonMail/gopenpgp/v2/crypto"
	"github.com/oza6ut0ne/gpg-go/internal/gpgagent"
	"github.com/oza6ut0ne/gpg-go/internal/keystore"
	"github.com/oza6ut0ne/gpg-go/internal/opsutil"
)

// TestAgentDecryptCandidates is a fast, no-gpg-required regression test
// for the part of the wildcard-vs-agent bug that's pure logic: whether a
// hidden recipient present alongside a named one broadens the set of
// keys tried via gpg-agent to every secret key we hold (since a hidden
// recipient's real key ID is unknown), rather than skipping the agent
// entirely. See TestCmdDecryptViaAgentHiddenAndRealRecipient for the
// full, real-gpg-backed end-to-end version of this same bug.
func TestAgentDecryptCandidates(t *testing.T) {
	pub1 := genTestPub(t, "A", "a@example.com")
	pub2 := genTestPub(t, "B", "b@example.com")
	all := []*crypto.Key{pub1, pub2}
	named := []*crypto.Key{pub1}

	if got := agentDecryptCandidates(named, false, all); len(got) != 1 || got[0] != pub1 {
		t.Fatalf("no wildcard: expected only the named candidate, got %d keys", len(got))
	}
	if got := agentDecryptCandidates(named, true, all); len(got) != 2 {
		t.Fatalf("hidden recipient present: expected every secret key to be tried, got %d keys", len(got))
	}
}

func requireGPGForTest(t *testing.T) string {
	t.Helper()
	path, err := exec.LookPath("gpg")
	if err != nil {
		t.Skip("gpg not installed, skipping real-GnuPG interop test")
	}
	return path
}

// writeLoopbackAgentConf writes a gpg-agent.conf enabling
// allow-loopback-pinentry into dir before gpg-agent starts for it, so it
// honors --pinentry-mode loopback instead of falling back to a real
// pinentry (a GUI/TTY prompt) — gpg-agent refuses loopback requests by
// default unless the agent itself opts in via this setting.
func writeLoopbackAgentConf(t *testing.T, dir string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "gpg-agent.conf"), []byte("allow-loopback-pinentry\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestCmdDecryptViaAgentHiddenAndRealRecipient is a regression test for
// two bugs found while adding smartcard support (where local
// private-keys-v1.d material is never available, so agent decryption
// must work correctly on its own):
//
//  1. cmdDecrypt only tried gpg-agent when the message had no hidden
//     (wildcard-key-ID) recipient at all. A message with BOTH a real and
//     a hidden PKESK for the very same key — e.g. from another tool, or
//     an older gpg-go, that doesn't dedupe a key given as both a plain
//     -r and a hidden -R the way cmdEncrypt now does — used to make
//     cmdDecrypt fall through to local-only brute force and fail for an
//     agent/card-only key.
//  2. tryAgentDecryptECDH was handed the raw (possibly still-armored)
//     input bytes instead of the de-armored PGPMessage bytes, so its raw
//     packet walker choked on an armored file with "invalid packet tag
//     byte 0x2d" (the '-' of "-----BEGIN PGP MESSAGE-----").
func TestCmdDecryptViaAgentHiddenAndRealRecipient(t *testing.T) {
	gpgPath := requireGPGForTest(t)
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
Name-Real: Decrypt Agent Test
Name-Email: decryptagent@example.com
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

	plaintext := []byte("hidden+real recipient decrypt test\n")
	plainPath := filepath.Join(dir, "in.txt")
	if err := os.WriteFile(plainPath, plaintext, 0o600); err != nil {
		t.Fatal(err)
	}

	// Build the fixture with a real + hidden PKESK for the very same
	// key. cmdEncrypt itself now dedupes this case (the same key given
	// as both -r and -R collapses to one PKESK, last-specified-wins), so
	// this calls opsutil.EncryptWithHiddenRecipients directly to still
	// produce the dual-PKESK shape — which a message from elsewhere
	// (another tool, or an older gpg-go) could still legitimately send,
	// and which cmdDecrypt must still handle correctly.
	preEncStore, err := openStore(&Options{Homedir: dir})
	if err != nil {
		t.Fatalf("openStore: %v", err)
	}
	preEncMatches := keystore.Find(preEncStore.PublicKeys(), "decryptagent@example.com")
	if len(preEncMatches) != 1 {
		t.Fatalf("expected 1 matching public key, got %d", len(preEncMatches))
	}

	encPath := plainPath + ".asc"
	ciphertext, err := opsutil.EncryptWithHiddenRecipients(plaintext, "", preEncMatches, preEncMatches, nil, true)
	if err != nil {
		t.Fatalf("EncryptWithHiddenRecipients: %v", err)
	}
	if err := os.WriteFile(encPath, ciphertext, 0o600); err != nil {
		t.Fatal(err)
	}

	// Confirm the fixture actually has both a real and a hidden PKESK,
	// otherwise this test wouldn't be exercising the bug at all. gpg
	// exits non-zero here because it also tries (and, lacking a
	// passphrase, fails) to decrypt the data packet for display — the
	// packet listing itself is still printed to stdout first, which is
	// all this check needs. --pinentry-mode loopback is required (not
	// just --batch) for that failed attempt to fail immediately: without
	// it, gpg-agent still launches a real pinentry to ask for the
	// passphrase — regardless of --batch, which only stops gpg ITSELF
	// from prompting — and that pinentry then hangs forever with no
	// terminal/display to use (or, on a machine that has one, pops up a
	// real dialog, which is exactly what this is guarding against).
	packetsOut, _ := exec.Command(gpgPath, "--homedir", dir, "--batch", "--pinentry-mode", "loopback", "--list-packets", encPath).CombinedOutput()
	if bytes.Count(packetsOut, []byte("pubkey enc packet")) != 2 {
		t.Fatalf("expected 2 pubkey enc packets (real + hidden), got:\n%s", packetsOut)
	}
	if !bytes.Contains(packetsOut, []byte("keyid 0000000000000000")) {
		t.Fatalf("expected one PKESK addressed to the wildcard key ID, got:\n%s", packetsOut)
	}

	o := &Options{
		Homedir:          dir,
		Batch:            true,
		Yes:              true,
		PinentryLoopback: true,
		PassphraseSet:    true,
		Passphrase:       passphrase,
	}
	store, err := openStore(o)
	if err != nil {
		t.Fatalf("openStore: %v", err)
	}
	encData, err := os.ReadFile(encPath)
	if err != nil {
		t.Fatal(err)
	}

	// Call tryAgentDecryptECDH directly and require handled=true (the
	// agent path actually ran and produced the result) rather than just
	// checking cmdDecrypt's overall success — with this fixture's key
	// unlockable locally too (we supplied its passphrase), cmdDecrypt
	// could otherwise "pass" via its local-unlock fallback even with
	// both bugs reintroduced, silently defeating this regression test.
	// store.SecretKeys() (not just the resolved real-ID candidate)
	// matches what cmdDecrypt now passes whenever a hidden recipient is
	// present, since a hidden recipient's real key ID is unknown.
	pgpMsg, err := opsutil.LoadPGPMessage(encData)
	if err != nil {
		t.Fatalf("LoadPGPMessage: %v", err)
	}
	res, handled, err := tryAgentDecryptECDH(o, store, pgpMsg.GetBinary(), pgpMsg, store.SecretKeys())
	if err != nil {
		t.Fatalf("tryAgentDecryptECDH: %v", err)
	}
	if !handled {
		t.Fatal("tryAgentDecryptECDH: handled=false, want true (agent should have decrypted this)")
	}
	if !bytes.Equal(res.Plaintext, plaintext) {
		t.Fatalf("decrypted mismatch: got %q want %q", res.Plaintext, plaintext)
	}

	// Also check the full cmdDecrypt entry point end to end (armored
	// input, dual-PKESK message) for overall integration coverage.
	outPath := filepath.Join(dir, "out.txt")
	o.Args = []string{encPath}
	o.Output = outPath
	if err := cmdDecrypt(o); err != nil {
		t.Fatalf("cmdDecrypt: %v", err)
	}
	got, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("reading decrypted output: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("decrypted mismatch: got %q want %q", got, plaintext)
	}
}

// TestCmdDecryptReportsSignatureForAgentSe is a regression test for:
// decrypting a signed-and-encrypted (-se) message through the
// gpg-agent-decrypt path (tryAgentDecryptECDH, e.g. for a smartcard-only
// key) must report the embedded signature's status the same way the
// local-decrypt path already does, so cmdDecrypt's finishDecrypt prints
// "gpg: Good signature from key ..." to stderr — matching real gpg —
// instead of silently saying nothing because SignedByID was left empty.
func TestCmdDecryptReportsSignatureForAgentSe(t *testing.T) {
	gpgPath := requireGPGForTest(t)
	dir := t.TempDir()
	writeLoopbackAgentConf(t, dir)
	const passphrase = "hunter2"

	batch := `%echo Generating a test key
Key-Type: eddsa
Key-Curve: ed25519
Subkey-Type: ecdh
Subkey-Curve: cv25519
Name-Real: Se Sig Report Test
Name-Email: sesigreport@example.com
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

	store, err := openStore(&Options{Homedir: dir})
	if err != nil {
		t.Fatalf("openStore: %v", err)
	}
	pubs := keystore.Find(store.PublicKeys(), "sesigreport@example.com")
	if len(pubs) != 1 {
		t.Fatalf("expected 1 matching key, got %d", len(pubs))
	}
	pub := pubs[0]
	e := pub.GetEntity()

	client, err := gpgagent.NewClient(dir)
	if err != nil {
		t.Fatalf("gpgagent.NewClient: %v", err)
	}
	defer client.Close()
	client.SetPassphraseFunc(func() ([]byte, error) { return []byte(passphrase), nil })

	primaryGrip, ok := opsutil.KeygripForPublicKey(e.PrimaryKey)
	if !ok {
		t.Fatal("could not compute primary keygrip")
	}

	plaintext := []byte("se signature report test\n")
	ciphertext, err := opsutil.AgentEncryptAndSign(plaintext, "", []*crypto.Key{pub}, nil, pub, e.PrimaryKey, primaryGrip, "test se", client, false)
	if err != nil {
		t.Fatalf("AgentEncryptAndSign: %v", err)
	}

	pgpMsg, err := opsutil.LoadPGPMessage(ciphertext)
	if err != nil {
		t.Fatal(err)
	}

	o := &Options{Homedir: dir, PinentryLoopback: true, PassphraseSet: true, Passphrase: passphrase}
	res, handled, err := tryAgentDecryptECDH(o, store, pgpMsg.GetBinary(), pgpMsg, []*crypto.Key{pub})
	if err != nil {
		t.Fatalf("tryAgentDecryptECDH: %v", err)
	}
	if !handled {
		t.Fatal("tryAgentDecryptECDH: handled=false, want true")
	}
	wantID := fmt.Sprintf("%016x", e.PrimaryKey.KeyId)
	if res.SignedByID != wantID {
		t.Fatalf("SignedByID = %q, want %q (gpg would print nothing for the empty case, unlike real gpg)", res.SignedByID, wantID)
	}
	if !res.Verified {
		t.Fatalf("expected Verified=true, got SigError=%v", res.SigError)
	}
	if !bytes.Equal(res.Plaintext, plaintext) {
		t.Fatalf("decrypted mismatch: got %q want %q", res.Plaintext, plaintext)
	}
}

// TestCmdDecryptClearSignedAndDetached is a regression test for -d
// (cmdDecrypt) also handling a clearsigned message and a lone detached
// signature, the same way real gpg's own --decrypt does: verifying and
// (for a clearsigned message) still writing out the text.
//
// It also covers a byte-for-byte regression found while adding this:
// go-crypto's clearsign.Decode returns the message body in RFC 4880's
// canonical text form (CRLF line endings, and — since it isn't part of
// what's hashed — no final line ending at all), which is not what the
// original text looked like. Blindly returning that form from -d, as
// opposed to converting CRLF back to LF and restoring the trailing
// newline (verified against real gpg's own -d output), would silently
// corrupt the output.
func TestCmdDecryptClearSignedAndDetached(t *testing.T) {
	gpgPath := requireGPGForTest(t)
	dir := t.TempDir()
	writeLoopbackAgentConf(t, dir)

	batch := `%echo Generating a test key
Key-Type: eddsa
Key-Curve: ed25519
Subkey-Type: ecdh
Subkey-Curve: cv25519
Name-Real: Clearsign Detached Test
Name-Email: clearsigntest@example.com
Expire-Date: 0
%no-protection
%commit
%echo done
`
	batchPath := filepath.Join(dir, "genkey.batch")
	if err := os.WriteFile(batchPath, []byte(batch), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(gpgPath, "--homedir", dir, "--batch", "--gen-key", batchPath)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("gpg --gen-key failed: %v\n%s", err, out.String())
	}

	// Deliberately no trailing newline and multiple lines, to exercise
	// both the missing-final-line-ending and CRLF-vs-LF parts of the
	// canonical-text regression at once.
	plaintext := []byte("line one\nline two\nline three")
	plainPath := filepath.Join(dir, "in.txt")
	if err := os.WriteFile(plainPath, plaintext, 0o600); err != nil {
		t.Fatal(err)
	}

	clearsignPath := plainPath + ".clearsigned.asc"
	out.Reset()
	cmd = exec.Command(gpgPath, "--homedir", dir, "--batch", "--yes", "--clearsign", "-o", clearsignPath, plainPath)
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("gpg --clearsign failed: %v\n%s", err, out.String())
	}

	// Ground truth: what real gpg's own -d reconstructs from the exact
	// same clearsigned file.
	wantText, err := exec.Command(gpgPath, "--homedir", dir, "--batch", "-d", clearsignPath).Output()
	if err != nil {
		t.Fatalf("gpg -d (ground truth): %v", err)
	}

	sigPath := plainPath + ".sig"
	out.Reset()
	cmd = exec.Command(gpgPath, "--homedir", dir, "--batch", "--yes", "-b", "-o", sigPath, plainPath)
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("gpg -b failed: %v\n%s", err, out.String())
	}

	o := &Options{Homedir: dir, Yes: true}

	t.Run("clearsigned", func(t *testing.T) {
		outPath := filepath.Join(dir, "clearsign.out")
		oc := *o
		oc.Args = []string{clearsignPath}
		oc.Output = outPath
		if err := cmdDecrypt(&oc); err != nil {
			t.Fatalf("cmdDecrypt: %v", err)
		}
		got, err := os.ReadFile(outPath)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, wantText) {
			t.Fatalf("clearsign text mismatch:\ngot:  %q\nwant: %q (real gpg -d)", got, wantText)
		}
	})

	t.Run("clearsigned tampered still writes text but errors", func(t *testing.T) {
		tampered := bytes.Replace(mustReadFile(t, clearsignPath), []byte("line two"), []byte("line TWO"), 1)
		tamperedPath := filepath.Join(dir, "tampered.asc")
		if err := os.WriteFile(tamperedPath, tampered, 0o600); err != nil {
			t.Fatal(err)
		}
		outPath := filepath.Join(dir, "tampered.out")
		oc := *o
		oc.Args = []string{tamperedPath}
		oc.Output = outPath
		if err := cmdDecrypt(&oc); err == nil {
			t.Fatal("expected a signature error for the tampered message")
		}
		got, err := os.ReadFile(outPath)
		if err != nil {
			t.Fatalf("expected the (tampered) text to still be written, like real gpg does: %v", err)
		}
		if len(got) == 0 {
			t.Fatal("expected non-empty tampered text output")
		}
	})

	t.Run("detached signature, single arg", func(t *testing.T) {
		od := *o
		od.Args = []string{sigPath}
		if err := cmdDecrypt(&od); err != nil {
			t.Fatalf("cmdDecrypt: %v", err)
		}
	})
}

func mustReadFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
