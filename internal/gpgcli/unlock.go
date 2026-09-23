package gpgcli

import (
	"fmt"

	"github.com/ProtonMail/gopenpgp/v2/crypto"
	"github.com/oza6ut0ne/gpg-go/internal/keystore"
)

// unlockKey attaches and (if necessary) unlocks the private key material
// for k, which must be a key known to store (as returned by
// store.SecretKeys() or store.PublicKeys()). It prompts for a passphrase
// via ResolvePassphrase only if store reports the key as protected.
func unlockKey(o *Options, store *keystore.Store, k *crypto.Key, promptLabel string) (*crypto.Key, error) {
	protected, err := store.SecretIsProtected(k)
	if err != nil {
		return nil, err
	}

	var pass []byte
	if protected {
		pass, err = ResolvePassphrase(o, fmt.Sprintf("Enter passphrase for %s: ", promptLabel))
		if err != nil {
			return nil, err
		}
	}

	unlocked, err := store.AttachSecret(k, pass)
	if err != nil {
		return nil, fmt.Errorf("unlocking key %s: %w", promptLabel, err)
	}
	return unlocked, nil
}
