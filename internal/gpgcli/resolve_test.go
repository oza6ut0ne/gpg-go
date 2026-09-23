package gpgcli

import (
	"testing"

	"github.com/ProtonMail/gopenpgp/v2/crypto"
	"github.com/oza6ut0ne/gpg-go/internal/opsutil"
)

func genTestPub(t *testing.T, name, email string) *crypto.Key {
	t.Helper()
	full, err := opsutil.GenerateKey(name, "", email, "ed25519", 0, 0)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pub, err := full.ToPublic()
	if err != nil {
		t.Fatalf("ToPublic: %v", err)
	}
	return pub
}

// TestResolveEncryptionRecipientsDedup is a regression test for: when
// the same key is named by both a -r/--recipient and a
// -R/--hidden-recipient spec (e.g. an explicit -r overriding gpg.conf's
// own "hidden-recipient" default, or vice versa), it must be encrypted
// to exactly once, as whichever of visible/hidden was specified LAST —
// never as two separate (redundant, and needlessly fingerprintable)
// PKESK packets for the same key.
func TestResolveEncryptionRecipientsDedup(t *testing.T) {
	pubA := genTestPub(t, "A", "a@example.com")
	pubB := genTestPub(t, "B", "b@example.com")
	pub := []*crypto.Key{pubA, pubB}

	t.Run("hidden spec after visible wins hidden", func(t *testing.T) {
		o := &Options{RecipientSpecs: []RecipientSpec{
			{Query: "a@example.com", Hidden: false},
			{Query: "a@example.com", Hidden: true},
		}}
		recipients, hidden, err := resolveEncryptionRecipients(o, pub)
		if err != nil {
			t.Fatalf("resolveEncryptionRecipients: %v", err)
		}
		if len(recipients) != 0 {
			t.Fatalf("expected 0 visible recipients, got %d", len(recipients))
		}
		if len(hidden) != 1 || hidden[0].GetFingerprint() != pubA.GetFingerprint() {
			t.Fatalf("expected exactly 1 hidden recipient (A), got %v", hidden)
		}
	})

	t.Run("visible spec after hidden wins visible", func(t *testing.T) {
		o := &Options{RecipientSpecs: []RecipientSpec{
			{Query: "a@example.com", Hidden: true},
			{Query: "a@example.com", Hidden: false},
		}}
		recipients, hidden, err := resolveEncryptionRecipients(o, pub)
		if err != nil {
			t.Fatalf("resolveEncryptionRecipients: %v", err)
		}
		if len(hidden) != 0 {
			t.Fatalf("expected 0 hidden recipients, got %d", len(hidden))
		}
		if len(recipients) != 1 || recipients[0].GetFingerprint() != pubA.GetFingerprint() {
			t.Fatalf("expected exactly 1 visible recipient (A), got %v", recipients)
		}
	})

	t.Run("distinct keys both kept, no cross-dedup", func(t *testing.T) {
		o := &Options{RecipientSpecs: []RecipientSpec{
			{Query: "a@example.com", Hidden: false},
			{Query: "b@example.com", Hidden: true},
			{Query: "a@example.com", Hidden: true},
		}}
		recipients, hidden, err := resolveEncryptionRecipients(o, pub)
		if err != nil {
			t.Fatalf("resolveEncryptionRecipients: %v", err)
		}
		if len(recipients) != 0 {
			t.Fatalf("expected 0 visible recipients, got %d", len(recipients))
		}
		if len(hidden) != 2 {
			t.Fatalf("expected both A and B hidden (A overridden to hidden, B always hidden), got %d", len(hidden))
		}
	})

	t.Run("no specs is an error", func(t *testing.T) {
		if _, _, err := resolveEncryptionRecipients(&Options{}, pub); err == nil {
			t.Fatal("expected an error for no recipients specified")
		}
	})

	t.Run("unknown recipient is an error", func(t *testing.T) {
		o := &Options{RecipientSpecs: []RecipientSpec{{Query: "nobody@example.com"}}}
		if _, _, err := resolveEncryptionRecipients(o, pub); err == nil {
			t.Fatal("expected an error for an unresolvable recipient")
		}
	})
}
