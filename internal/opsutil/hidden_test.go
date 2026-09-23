package opsutil

import (
	"bytes"
	"testing"

	"github.com/ProtonMail/gopenpgp/v2/crypto"
)

// TestEncryptWithHiddenRecipientsRoundTrip is a regression test: an
// earlier hand-rolled packet-assembly implementation double-closed the
// compressed/encrypted data writer chain, corrupting the SEIPD packet's
// length so that real gpg (and this tool) would decrypt correctly but
// then choke on trailing garbage bytes.
func TestEncryptWithHiddenRecipientsRoundTrip(t *testing.T) {
	alice, err := GenerateKey("Alice", "", "alice@example.com", "ed25519", 0, 0)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	bob, err := GenerateKey("Bob", "", "bob@example.com", "ed25519", 0, 0)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	alicePub, _ := alice.ToPublic()
	bobPub, _ := bob.ToPublic()

	plaintext := []byte("hello, hidden world\n")

	for _, tc := range []struct {
		name    string
		visible []*crypto.Key
		hidden  []*crypto.Key
		signer  *crypto.Key
	}{
		{"hidden-only", nil, []*crypto.Key{alicePub}, nil},
		{"mixed", []*crypto.Key{bobPub}, []*crypto.Key{alicePub}, nil},
		{"hidden-and-signed", nil, []*crypto.Key{alicePub}, alice},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ct, err := EncryptWithHiddenRecipients(plaintext, "", tc.visible, tc.hidden, tc.signer, false)
			if err != nil {
				t.Fatalf("EncryptWithHiddenRecipients: %v", err)
			}

			pgpMsg, err := LoadPGPMessage(ct)
			if err != nil {
				t.Fatalf("LoadPGPMessage: %v", err)
			}

			// Every recipient in this test is either hidden (Alice) or,
			// when present, visible (Bob); decrypting with Alice's own
			// key must work regardless of which recipient slot it was
			// encrypted into, exercising exactly the wildcard-keyID path
			// the CLI's decrypt fallback also relies on.
			res, err := DecryptMessage(pgpMsg, []*crypto.Key{alice}, []*crypto.Key{alicePub})
			if err != nil {
				t.Fatalf("DecryptMessage: %v", err)
			}
			if !bytes.Equal(res.Plaintext, plaintext) {
				t.Fatalf("plaintext mismatch: got %q want %q", res.Plaintext, plaintext)
			}
			if tc.signer != nil && !res.Verified {
				t.Fatalf("expected signature to verify, sigError=%v", res.SigError)
			}
		})
	}
}
