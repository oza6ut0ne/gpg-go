package agentkey

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

const testPassphrase = "hunter2"

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

// realGeneratedKeyPath generates a real ed25519+cv25519 key with real gpg
// (skipping the test if gpg isn't installed) and returns the path to its
// primary private-keys-v1.d/*.key file, to validate this package against
// an authentic gpg-agent-protected file rather than only our own writer.
func realGeneratedKeyPath(t *testing.T) string {
	t.Helper()
	gpgPath, err := exec.LookPath("gpg")
	if err != nil {
		t.Skip("gpg not installed, skipping real-GnuPG fixture test")
	}

	dir := t.TempDir()
	writeLoopbackAgentConf(t, dir)
	batch := fmt.Sprintf(`%%echo Generating a test key
Key-Type: eddsa
Key-Curve: ed25519
Subkey-Type: ecdh
Subkey-Curve: cv25519
Name-Real: Test User
Name-Email: test@example.com
Expire-Date: 0
Passphrase: %s
%%commit
%%echo done
`, testPassphrase)
	batchPath := filepath.Join(dir, "genkey.batch")
	if err := os.WriteFile(batchPath, []byte(batch), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(gpgPath, "--homedir", dir, "--batch", "--pinentry-mode", "loopback", "--gen-key", batchPath)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("gpg --gen-key failed: %v\n%s", err, out.String())
	}

	entries, err := os.ReadDir(filepath.Join(dir, "private-keys-v1.d"))
	if err != nil || len(entries) == 0 {
		t.Fatalf("no private-keys-v1.d entries produced: %v", err)
	}

	// Two files are produced (primary + subkey); the primary (EdDSA,
	// signing) key is identifiable by algo once parsed, so just try each.
	for _, ent := range entries {
		p := filepath.Join(dir, "private-keys-v1.d", ent.Name())
		k, err := ReadFile(p)
		if err != nil {
			t.Fatalf("ReadFile(%s): %v", p, err)
		}
		for _, c := range k.Clear {
			if c.Name == "flags" && string(c.Value) == "eddsa" {
				return p
			}
		}
	}
	t.Fatal("no EdDSA (primary) key file found")
	return ""
}

func TestUnprotectRealGPGAgentFile(t *testing.T) {
	realKeyPath := realGeneratedKeyPath(t)
	k, err := ReadFile(realKeyPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if !k.IsProtected() {
		t.Fatal("expected a protected key")
	}
	if k.Algo != "ecc" {
		t.Fatalf("algo = %q", k.Algo)
	}

	unlocked, err := k.Unprotect([]byte(testPassphrase))
	if err != nil {
		t.Fatalf("Unprotect: %v", err)
	}

	q := unlocked.Find("q")
	d := unlocked.Find("d")
	if len(q) == 0 || len(d) == 0 {
		t.Fatalf("missing q/d: q=%x d=%x", q, d)
	}

	// q is the OpenPGP-native point (0x40 prefix + 32-byte compact
	// Ed25519 public key). Confirm d (32-byte seed) actually produces
	// that exact public key via Go's ed25519.
	if len(d) != 32 {
		t.Fatalf("expected 32-byte seed, got %d", len(d))
	}
	priv := ed25519.NewKeyFromSeed(d)
	pub := priv.Public().(ed25519.PublicKey)
	wantPub := q[1:] // strip 0x40 prefix
	if !bytes.Equal(pub, wantPub) {
		t.Fatalf("derived pubkey %x != q (stripped) %x", pub, wantPub)
	}

	// Wrong passphrase must fail.
	if _, err := k.Unprotect([]byte("wrongpass")); err == nil {
		t.Fatal("expected error for wrong passphrase")
	}
}

func TestRoundTripProtect(t *testing.T) {
	realKeyPath := realGeneratedKeyPath(t)
	k, err := ReadFile(realKeyPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	unlocked, err := k.Unprotect([]byte(testPassphrase))
	if err != nil {
		t.Fatalf("Unprotect: %v", err)
	}

	reprotected, err := unlocked.Protect([]byte("newpass123"))
	if err != nil {
		t.Fatalf("Protect: %v", err)
	}

	data := reprotected.Serialize()

	reparsed, err := Parse(data)
	if err != nil {
		t.Fatalf("re-parse: %v", err)
	}
	reunlocked, err := reparsed.Unprotect([]byte("newpass123"))
	if err != nil {
		t.Fatalf("re-unlock: %v", err)
	}
	if !bytes.Equal(reunlocked.Find("d"), unlocked.Find("d")) {
		t.Fatal("round-tripped d does not match original")
	}
	if !bytes.Equal(reunlocked.Find("q"), unlocked.Find("q")) {
		t.Fatal("round-tripped q does not match original")
	}
}
