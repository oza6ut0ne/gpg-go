package gpgcli

import (
	"fmt"

	"github.com/ProtonMail/gopenpgp/v2/crypto"
	"github.com/oza6ut0ne/gpg-go/internal/keystore"
)

// resolveEncryptionRecipients resolves every -r/--recipient and
// -R/--hidden-recipient query to a public key and splits them into
// visible and hidden recipient lists. If the same key is named by more
// than one spec (typically the same key given as both a plain -r and a
// hidden -R, e.g. gpg.conf's own "hidden-recipient" combined with an
// explicit command-line -r for the same key), only the LAST spec that
// resolves to it counts — both for whether it ends up hidden or visible,
// and to guarantee it is encrypted to exactly once rather than getting a
// redundant extra PKESK.
func resolveEncryptionRecipients(o *Options, pub []*crypto.Key) (recipients, hidden []*crypto.Key, err error) {
	if len(o.RecipientSpecs) == 0 {
		return nil, nil, fmt.Errorf("no recipients specified; use -r/--recipient or -R/--hidden-recipient NAME")
	}

	type resolved struct {
		key    *crypto.Key
		hidden bool
	}
	var order []string
	byFingerprint := map[string]*resolved{}

	for _, spec := range o.RecipientSpecs {
		matches := keystore.Find(pub, spec.Query)
		switch len(matches) {
		case 0:
			return nil, nil, fmt.Errorf("no public key found for recipient %q", spec.Query)
		case 1:
			// ok
		default:
			return nil, nil, fmt.Errorf("recipient %q is ambiguous (%d matching keys)", spec.Query, len(matches))
		}
		k := matches[0]
		fpr := k.GetFingerprint()
		if _, seen := byFingerprint[fpr]; !seen {
			order = append(order, fpr)
		}
		byFingerprint[fpr] = &resolved{key: k, hidden: spec.Hidden}
	}

	for _, fpr := range order {
		r := byFingerprint[fpr]
		if r.hidden {
			hidden = append(hidden, r.key)
		} else {
			recipients = append(recipients, r.key)
		}
	}
	return recipients, hidden, nil
}

// pickSigner selects WHICH key to sign with (by --local-user, or the
// sole secret key in the keyring if there is only one), without
// unlocking or attaching its private material — callers that can use
// gpg-agent directly need only the public key and its label.
func pickSigner(o *Options, sec []*crypto.Key) (*crypto.Key, error) {
	if o.LocalUser != "" {
		matches := keystore.Find(sec, o.LocalUser)
		switch len(matches) {
		case 0:
			return nil, fmt.Errorf("no secret key found for %q", o.LocalUser)
		case 1:
			return matches[0], nil
		default:
			return nil, fmt.Errorf("local user %q is ambiguous (%d matching keys)", o.LocalUser, len(matches))
		}
	}
	switch len(sec) {
	case 0:
		return nil, fmt.Errorf("no secret key available; generate one with --gen-key")
	case 1:
		return sec[0], nil
	default:
		return nil, fmt.Errorf("multiple secret keys available; specify one with -u/--local-user")
	}
}

// signerLabel returns a human-readable label for prompts/pinentry
// descriptions: the key's own primary user ID if available, else its
// long key ID.
func signerLabel(o *Options, k *crypto.Key) string {
	if o.LocalUser != "" {
		return o.LocalUser
	}
	return "default key"
}
