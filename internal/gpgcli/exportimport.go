package gpgcli

import (
	"fmt"
	"os"
	"strings"

	"github.com/ProtonMail/gopenpgp/v2/crypto"
	"github.com/oza6ut0ne/gpg-go/internal/keystore"
)

func cmdExport(o *Options, secret bool) error {
	store, err := openStore(o)
	if err != nil {
		return err
	}

	all := store.PublicKeys()
	if secret {
		all = store.SecretKeys()
	}
	keys := filterByQueries(all, o.Args)
	if len(keys) == 0 {
		if !o.Quiet {
			fmt.Fprintln(os.Stderr, "gpg: no keys matched, nothing exported")
		}
		return nil
	}

	if secret {
		var unlocked []*crypto.Key
		for _, k := range keys {
			protected, err := store.SecretIsProtected(k)
			if err != nil {
				return err
			}
			var pass []byte
			if protected {
				pass, err = ResolvePassphrase(o, fmt.Sprintf("Enter passphrase to export %s: ", keystore.LongKeyID(k.GetFingerprint())))
				if err != nil {
					return err
				}
			}
			priv, err := store.AttachSecret(k, pass)
			if err != nil {
				return fmt.Errorf("exporting %s: %w", keystore.LongKeyID(k.GetFingerprint()), err)
			}
			if len(pass) > 0 {
				priv, err = priv.Lock(pass)
				if err != nil {
					return err
				}
			}
			unlocked = append(unlocked, priv)
		}
		keys = unlocked
	}

	var sb strings.Builder
	for _, k := range keys {
		armored, err := k.Armor()
		if err != nil {
			return err
		}
		sb.WriteString(armored)
		sb.WriteString("\n")
	}
	data := []byte(sb.String())
	if !o.Armor {
		data, err = dearmorConcatenated(keys)
		if err != nil {
			return err
		}
	}

	mode := os.FileMode(0o644)
	if secret {
		mode = 0o600
	}
	return writeOutput(o, o.Output, data, mode)
}

func dearmorConcatenated(keys []*crypto.Key) ([]byte, error) {
	var buf []byte
	for _, k := range keys {
		ser, err := k.Serialize()
		if err != nil {
			return nil, err
		}
		buf = append(buf, ser...)
	}
	return buf, nil
}

func cmdImport(o *Options) error {
	var path string
	if len(o.Args) > 0 {
		path = o.Args[0]
	}
	data, err := readInput(path)
	if err != nil {
		return err
	}

	keys, err := keystore.ParseKeys(data)
	if err != nil {
		return err
	}
	if len(keys) == 0 {
		return fmt.Errorf("no keys found in input")
	}

	store, err := openStore(o)
	if err != nil {
		return err
	}

	var newPub, newSec, updated int
	for _, k := range keys {
		if k.IsPrivate() {
			unlocked := k
			if locked, err := k.IsLocked(); err != nil {
				return err
			} else if locked {
				pass, err := ResolvePassphrase(o, fmt.Sprintf("Enter passphrase to import %s: ", keystore.LongKeyID(k.GetFingerprint())))
				if err != nil {
					return err
				}
				unlocked, err = k.Unlock(pass)
				if err != nil {
					return fmt.Errorf("importing secret key: %w", err)
				}
				if err := store.AddSecretKey(unlocked, pass); err != nil {
					return fmt.Errorf("importing secret key: %w", err)
				}
			} else if err := store.AddSecretKey(unlocked, nil); err != nil {
				return fmt.Errorf("importing secret key: %w", err)
			}
			newSec++
		} else {
			isNew, err := store.AddPublic(k)
			if err != nil {
				return fmt.Errorf("importing public key: %w", err)
			}
			if isNew {
				newPub++
			} else {
				updated++
			}
		}
	}

	if err := store.SavePublic(); err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "gpg: Total number processed: %d\n", len(keys))
	if newPub > 0 {
		fmt.Fprintf(os.Stderr, "gpg:               imported: %d\n", newPub)
	}
	if newSec > 0 {
		fmt.Fprintf(os.Stderr, "gpg:       secret keys imported: %d\n", newSec)
	}
	if updated > 0 {
		fmt.Fprintf(os.Stderr, "gpg:              unchanged: %d\n", updated)
	}
	return nil
}
