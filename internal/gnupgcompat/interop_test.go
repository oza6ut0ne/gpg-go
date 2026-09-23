// Package gnupgcompat holds end-to-end tests that exercise kbx +
// agentkey + opsutil together against a real `gpg` binary, to prove
// interoperability with actual GnuPG rather than just internal
// self-consistency. These tests are skipped if `gpg` isn't on PATH.
package gnupgcompat

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp/ecdh"
	"github.com/ProtonMail/go-crypto/openpgp/eddsa"
	"github.com/oza6ut0ne/gpg-go/internal/agentkey"
	"github.com/oza6ut0ne/gpg-go/internal/kbx"
	"github.com/oza6ut0ne/gpg-go/internal/opsutil"
)

func requireGPG(t *testing.T) string {
	t.Helper()
	path, err := exec.LookPath("gpg")
	if err != nil {
		t.Skip("gpg not installed, skipping real-GnuPG interop test")
	}
	return path
}

// writeLoopbackAgentConf writes a gpg-agent.conf enabling
// allow-loopback-pinentry into dir. gpg-agent refuses a client's
// --pinentry-mode loopback / OPTION pinentry-mode=loopback request by
// default and falls back to launching a real pinentry (a GUI or TTY
// prompt) unless the agent itself has opted in via this setting — which
// only takes effect if it's in place before gpg-agent starts for dir,
// so callers must write this before running any gpg/gpg-agent command
// against a fresh homedir.
func writeLoopbackAgentConf(t *testing.T, dir string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "gpg-agent.conf"), []byte("allow-loopback-pinentry\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// buildHomedir generates a fresh ed25519+cv25519 key entirely with our
// own code and writes a from-scratch, real-GnuPG-compatible homedir
// (pubring.kbx + private-keys-v1.d) for it.
func buildHomedir(t *testing.T, dir string, passphrase []byte) {
	t.Helper()
	writeLoopbackAgentConf(t, dir)

	key, err := opsutil.GenerateKey("Interop Test", "", "interop@example.com", "ed25519", 0, 0)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	e := key.GetEntity()

	pub, err := key.ToPublic()
	if err != nil {
		t.Fatalf("ToPublic: %v", err)
	}
	keyblock, err := pub.GetPublicKey()
	if err != nil {
		t.Fatalf("GetPublicKey: %v", err)
	}

	blob, err := kbx.NewOpenPGPBlob(keyblock)
	if err != nil {
		t.Fatalf("NewOpenPGPBlob: %v", err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := kbx.WriteFile(filepath.Join(dir, "pubring.kbx"), []*kbx.Blob{blob}); err != nil {
		t.Fatalf("kbx.WriteFile: %v", err)
	}

	privDir := filepath.Join(dir, "private-keys-v1.d")
	if err := os.MkdirAll(privDir, 0o700); err != nil {
		t.Fatal(err)
	}

	// Primary: EdDSA signing key.
	primaryPub := e.PrimaryKey.PublicKey.(*eddsa.PublicKey)
	primaryPriv := e.PrivateKey.PrivateKey.(*eddsa.PrivateKey)
	grip, ok := opsutil.KeygripForPublicKey(e.PrimaryKey)
	if !ok {
		t.Fatal("could not compute primary keygrip")
	}
	primaryK := agentkey.BuildUnprotected("ecc",
		[]agentkey.Param{
			{Name: "curve", Value: []byte("Ed25519")},
			{Name: "flags", Value: []byte("eddsa")},
			{Name: "q", Value: primaryPub.MarshalPoint()},
		},
		[]agentkey.Param{{Name: "d", Value: primaryPriv.MarshalByteSecret()}},
	)
	protectedPrimary, err := primaryK.Protect(passphrase)
	if err != nil {
		t.Fatalf("Protect primary: %v", err)
	}
	if err := agentkey.WriteFile(filepath.Join(privDir, grip+".key"), protectedPrimary); err != nil {
		t.Fatal(err)
	}

	// Subkey: ECDH (Curve25519) encryption key.
	sub := e.Subkeys[0]
	subPub := sub.PublicKey.PublicKey.(*ecdh.PublicKey)
	subPriv := sub.PrivateKey.PrivateKey.(*ecdh.PrivateKey)
	subGrip, ok := opsutil.KeygripForPublicKey(sub.PublicKey)
	if !ok {
		t.Fatal("could not compute subkey keygrip")
	}
	subK := agentkey.BuildUnprotected("ecc",
		[]agentkey.Param{
			{Name: "curve", Value: []byte("Curve25519")},
			{Name: "flags", Value: []byte("djb-tweak")},
			{Name: "q", Value: subPub.MarshalPoint()},
		},
		[]agentkey.Param{{Name: "d", Value: subPriv.MarshalByteSecret()}},
	)
	protectedSub, err := subK.Protect(passphrase)
	if err != nil {
		t.Fatalf("Protect subkey: %v", err)
	}
	if err := agentkey.WriteFile(filepath.Join(privDir, subGrip+".key"), protectedSub); err != nil {
		t.Fatal(err)
	}
}

func runGPG(t *testing.T, gpgPath, homedir string, args ...string) (string, error) {
	t.Helper()
	full := append([]string{"--homedir", homedir}, args...)
	cmd := exec.Command(gpgPath, full...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	t.Logf("gpg %v =>\n%s", args, out.String())
	return out.String(), err
}

func TestFromScratchHomedirInteropWithRealGPG(t *testing.T) {
	gpgPath := requireGPG(t)
	dir := t.TempDir()
	buildHomedir(t, dir, []byte("interoptest123"))

	if _, err := runGPG(t, gpgPath, dir, "-k"); err != nil {
		t.Fatalf("gpg -k failed: %v", err)
	}
	if out, err := runGPG(t, gpgPath, dir, "-K", "--with-keygrip"); err != nil {
		t.Fatalf("gpg -K failed: %v", err)
	} else if !bytes.Contains([]byte(out), []byte("sec ")) {
		t.Fatalf("expected a 'sec' line, got:\n%s", out)
	}

	msgPath := filepath.Join(dir, "msg.txt")
	if err := os.WriteFile(msgPath, []byte("hello from gpg-go\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	sigPath := msgPath + ".asc"
	_, err := runGPG(t, gpgPath, dir,
		"--batch", "--pinentry-mode", "loopback", "--passphrase", "interoptest123",
		"--local-user", "interop@example.com",
		"--armor", "--detach-sign", "-o", sigPath, msgPath)
	if err != nil {
		t.Fatalf("gpg --detach-sign failed: %v", err)
	}

	if _, err := runGPG(t, gpgPath, dir, "--verify", sigPath, msgPath); err != nil {
		t.Fatalf("gpg --verify failed: %v", err)
	}

	encPath := msgPath + ".enc.asc"
	_, err = runGPG(t, gpgPath, dir,
		"--batch", "--yes", "--trust-model", "always",
		"-r", "interop@example.com", "--armor", "--encrypt",
		"-o", encPath, msgPath)
	if err != nil {
		t.Fatalf("gpg --encrypt failed: %v", err)
	}

	decOut, err := runGPG(t, gpgPath, dir,
		"--batch", "--pinentry-mode", "loopback", "--passphrase", "interoptest123",
		"--decrypt", encPath)
	if err != nil {
		t.Fatalf("gpg --decrypt failed: %v", err)
	}
	if !bytes.Contains([]byte(decOut), []byte("hello from gpg-go")) {
		t.Fatalf("decrypted output missing expected text:\n%s", decOut)
	}
}
