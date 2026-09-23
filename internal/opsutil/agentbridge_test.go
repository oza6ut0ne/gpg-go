package opsutil

import (
	"bytes"
	"testing"

	openpgp "github.com/ProtonMail/go-crypto/openpgp"
)

// TestAttachSecretKeysPreservesSubkeyTag is a regression test: earlier,
// packet.NewDecrypterPrivateKey built a fresh embedded PublicKey with
// IsSubkey defaulting to false, so serializing an attached subkey wrote
// a bogus second *primary* secret key packet instead of a secret subkey
// packet, splitting the export into two unrelated-looking keys.
func TestAttachSecretKeysPreservesSubkeyTag(t *testing.T) {
	full, err := GenerateKey("Subkey Tag Test", "", "subkeytag@example.com", "ed25519", 0, 0)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	pub, err := full.ToPublic()
	if err != nil {
		t.Fatalf("ToPublic: %v", err)
	}

	components, err := ExtractPrivateComponents(full)
	if err != nil {
		t.Fatalf("ExtractPrivateComponents: %v", err)
	}
	if len(components) != 2 {
		t.Fatalf("expected 2 components (primary+subkey), got %d", len(components))
	}

	lookup := func(gripHex string) (*SecretParams, bool) {
		for _, c := range components {
			if c.Keygrip == gripHex {
				k := c.Key
				return &SecretParams{D: k.Find("d"), P: k.Find("p"), Q: k.Find("q")}, true
			}
		}
		return nil, false
	}

	attached, ok, err := AttachSecretKeys(pub, lookup)
	if err != nil || !ok {
		t.Fatalf("AttachSecretKeys: ok=%v err=%v", ok, err)
	}

	data, err := attached.Serialize()
	if err != nil {
		t.Fatalf("Serialize: %v", err)
	}

	entities, err := openpgp.ReadKeyRing(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("ReadKeyRing: %v", err)
	}
	if len(entities) != 1 {
		t.Fatalf("expected exactly 1 entity after re-parsing, got %d (subkey likely mis-tagged as a primary key)", len(entities))
	}
	e := entities[0]
	if len(e.Subkeys) != 1 {
		t.Fatalf("expected exactly 1 subkey, got %d", len(e.Subkeys))
	}
	if !e.Subkeys[0].PublicKey.IsSubkey {
		t.Fatal("re-parsed subkey does not have IsSubkey set")
	}
	if e.Subkeys[0].PrivateKey == nil {
		t.Fatal("re-parsed subkey has no private key material")
	}
}
