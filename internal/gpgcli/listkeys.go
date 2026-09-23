package gpgcli

import (
	"fmt"
	"strings"

	"github.com/ProtonMail/gopenpgp/v2/crypto"
	"github.com/oza6ut0ne/gpg-go/internal/gnupghome"
	"github.com/oza6ut0ne/gpg-go/internal/keystore"
)

func cmdListKeys(o *Options, secret bool) error {
	store, err := openStore(o)
	if err != nil {
		return err
	}

	all := store.PublicKeys()
	if secret {
		all = store.SecretKeys()
	}

	keys := filterByQueries(all, o.Args)

	dir, _ := gnupghome.Resolve(o.Homedir)
	path := gnupghome.KbxPath(dir)
	fmt.Println(path)
	fmt.Println(strings.Repeat("-", len(path)))

	if len(keys) == 0 {
		return nil
	}

	var sb strings.Builder
	keystore.PrintKeyList(&sb, keys, secret, keystore.ListOptions{
		ShowSubkeyFingerprint: o.Fingerprint || o.WithSubkeyFingerprints,
		WithKeygrip:           o.WithKeygrip,
	})
	fmt.Print(sb.String())
	return nil
}

// filterByQueries returns the union of keys matching each query string; if
// no queries are given, all keys are returned.
func filterByQueries(all []*crypto.Key, queries []string) []*crypto.Key {
	if len(queries) == 0 {
		return all
	}
	seen := map[string]bool{}
	var out []*crypto.Key
	for _, q := range queries {
		for _, k := range keystore.Find(all, q) {
			fpr := k.GetFingerprint()
			if !seen[fpr] {
				seen[fpr] = true
				out = append(out, k)
			}
		}
	}
	return out
}
