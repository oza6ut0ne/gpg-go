package gpgcli

import (
	"fmt"
	"os"

	"github.com/ProtonMail/gopenpgp/v2/crypto"
	"github.com/oza6ut0ne/gpg-go/internal/keystore"
)

func cmdDeleteKey(o *Options, deletePub, deleteSec bool) error {
	if len(o.Args) != 1 {
		return fmt.Errorf("usage: --delete-key/--delete-secret-key NAME")
	}
	query := o.Args[0]

	store, err := openStore(o)
	if err != nil {
		return err
	}

	var match *crypto.Key
	if deleteSec {
		matches := keystore.Find(store.SecretKeys(), query)
		match, err = uniqueKey(matches, query)
	} else {
		matches := keystore.Find(store.PublicKeys(), query)
		match, err = uniqueKey(matches, query)
	}
	if err != nil {
		return err
	}
	fpr := match.GetFingerprint()

	removedSec := false
	if deleteSec {
		removedSec, err = store.DeleteSecretKey(match)
		if err != nil {
			return err
		}
	}
	removedPub := false
	if deletePub {
		removedPub = store.DeletePublic(fpr)
		if err := store.SavePublic(); err != nil {
			return err
		}
	}

	if !removedPub && !removedSec {
		return fmt.Errorf("key %q not found", query)
	}
	if !o.Quiet {
		fmt.Fprintf(os.Stderr, "gpg: key %s deleted\n", keystore.LongKeyID(fpr))
	}
	return nil
}

func uniqueKey(matches []*crypto.Key, query string) (*crypto.Key, error) {
	switch len(matches) {
	case 0:
		return nil, fmt.Errorf("key %q not found", query)
	case 1:
		return matches[0], nil
	default:
		return nil, fmt.Errorf("ambiguous key specifier %q matches %d keys", query, len(matches))
	}
}
