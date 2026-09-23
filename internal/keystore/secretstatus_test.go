package keystore

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ProtonMail/gopenpgp/v2/crypto"
	"github.com/oza6ut0ne/gpg-go/internal/opsutil"
	"github.com/oza6ut0ne/gpg-go/internal/sexp"
)

// TestSecretKeyStatus is a regression test for -K's gpg-style "#"
// (no private-keys-v1.d entry at all — the secret key is known but
// unavailable) and ">" (a smartcard stub) status markers.
func TestSecretKeyStatus(t *testing.T) {
	dir := t.TempDir()
	store, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	full, err := opsutil.GenerateKey("Marker Test", "", "marktest@example.com", "ed25519", 0, 0)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if err := store.AddSecretKey(full, nil); err != nil {
		t.Fatalf("AddSecretKey: %v", err)
	}

	pub, err := full.ToPublic()
	if err != nil {
		t.Fatalf("ToPublic: %v", err)
	}
	e := pub.GetEntity()
	if len(e.Subkeys) != 1 {
		t.Fatalf("expected 1 subkey, got %d", len(e.Subkeys))
	}
	subPub := e.Subkeys[0].PublicKey

	primaryGrip, ok := opsutil.KeygripForPublicKey(e.PrimaryKey)
	if !ok {
		t.Fatal("could not compute primary keygrip")
	}
	subGrip, ok := opsutil.KeygripForPublicKey(subPub)
	if !ok {
		t.Fatal("could not compute subkey keygrip")
	}

	// Baseline: ordinary local secret material just written by
	// AddSecretKey -> no marker.
	if status := store.SecretKeyStatus(e.PrimaryKey); status != 0 {
		t.Fatalf("primary: expected no marker, got %q", string(status))
	}
	if status := store.SecretKeyStatus(subPub); status != 0 {
		t.Fatalf("subkey: expected no marker, got %q", string(status))
	}

	// Simulate the primary's secret key having been removed entirely —
	// no private-keys-v1.d entry at all, as real gpg does for e.g. a
	// card-only setup where the primary secret was never kept locally.
	if err := os.Remove(filepath.Join(dir, "private-keys-v1.d", primaryGrip+".key")); err != nil {
		t.Fatal(err)
	}
	if status := store.SecretKeyStatus(e.PrimaryKey); status != '#' {
		t.Fatalf("primary after removal: expected '#', got %q", string(status))
	}

	// Simulate the subkey being a smartcard stub. Real gpg-agent writes
	// these as a bare canonical S-expression with no "Created:"/"Key:"
	// text wrapper (unlike ordinary private-keys-v1.d entries, and
	// verified against a real card-registered key) — this must still be
	// classified correctly rather than falling back to '#' because the
	// "Key: " marker Tag() looks for isn't there.
	stub := sexp.L(sexp.S("shadowed-private-key"), sexp.S("stub")).Canonical()
	if err := os.WriteFile(filepath.Join(dir, "private-keys-v1.d", subGrip+".key"), stub, 0o600); err != nil {
		t.Fatal(err)
	}
	if status := store.SecretKeyStatus(subPub); status != '>' {
		t.Fatalf("subkey as card stub: expected '>', got %q", string(status))
	}
}

// TestPrintKeyListStatusMarkerAlignment is a regression test for the
// exact column alignment of -K's "#"/">" status markers, verified
// against real gpg's own output for a card-backed key: the marker
// (or, when there is none, a plain space) directly follows "sec"/"ssb"
// with no space in between, then exactly two more spaces before the
// algorithm name — e.g. "sec#  ed25519" / "ssb>  cv25519" / (unmarked)
// "sec   ed25519", all six characters wide before the algorithm name.
func TestPrintKeyListStatusMarkerAlignment(t *testing.T) {
	dir := t.TempDir()
	store, err := Open(dir)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	full, err := opsutil.GenerateKey("Align Test", "", "aligntest@example.com", "ed25519", 0, 0)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if err := store.AddSecretKey(full, nil); err != nil {
		t.Fatalf("AddSecretKey: %v", err)
	}
	pub, err := full.ToPublic()
	if err != nil {
		t.Fatalf("ToPublic: %v", err)
	}

	var sb strings.Builder
	PrintKeyList(&sb, []*crypto.Key{pub}, true, ListOptions{SecretStatus: store.SecretKeyStatus})
	out := sb.String()

	if !strings.Contains(out, "sec   ed25519") {
		t.Fatalf("expected unmarked 'sec   ed25519' (3 spaces), got:\n%s", out)
	}
	if !strings.Contains(out, "ssb   cv25519") {
		t.Fatalf("expected unmarked 'ssb   cv25519' (3 spaces), got:\n%s", out)
	}

	e := pub.GetEntity()
	primaryGrip, _ := opsutil.KeygripForPublicKey(e.PrimaryKey)
	subGrip, _ := opsutil.KeygripForPublicKey(e.Subkeys[0].PublicKey)
	if err := os.Remove(filepath.Join(dir, "private-keys-v1.d", primaryGrip+".key")); err != nil {
		t.Fatal(err)
	}
	stub := sexp.L(sexp.S("shadowed-private-key"), sexp.S("stub")).Canonical()
	if err := os.WriteFile(filepath.Join(dir, "private-keys-v1.d", subGrip+".key"), stub, 0o600); err != nil {
		t.Fatal(err)
	}

	sb.Reset()
	PrintKeyList(&sb, []*crypto.Key{pub}, true, ListOptions{SecretStatus: store.SecretKeyStatus})
	out = sb.String()
	if !strings.Contains(out, "sec#  ed25519") {
		t.Fatalf("expected 'sec#  ed25519' (marker + 2 spaces), got:\n%s", out)
	}
	if !strings.Contains(out, "ssb>  cv25519") {
		t.Fatalf("expected 'ssb>  cv25519' (marker + 2 spaces), got:\n%s", out)
	}
}
