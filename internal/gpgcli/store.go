package gpgcli

import (
	"github.com/oza6ut0ne/gpg-go/internal/gnupghome"
	"github.com/oza6ut0ne/gpg-go/internal/keystore"
)

// openStore resolves the home directory from options and opens (creating if
// needed) the local keystore.
func openStore(o *Options) (*keystore.Store, error) {
	dir, err := gnupghome.Resolve(o.Homedir)
	if err != nil {
		return nil, err
	}
	if err := gnupghome.Ensure(dir); err != nil {
		return nil, err
	}
	return keystore.Open(dir)
}
