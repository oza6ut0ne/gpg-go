package gpgcli

import (
	"bytes"
	"fmt"
	"os"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/ProtonMail/gopenpgp/v2/crypto"
	"github.com/oza6ut0ne/gpg-go/internal/keystore"
	"github.com/oza6ut0ne/gpg-go/internal/opsutil"
)

func cmdVerify(o *Options) error {
	store, err := openStore(o)
	if err != nil {
		return err
	}

	switch len(o.Args) {
	case 0:
		data, err := readInput("")
		if err != nil {
			return err
		}
		return verifySelfContained(o, store, data)

	case 1:
		data, err := readInput(o.Args[0])
		if err != nil {
			return err
		}
		if isDetachedSignature(data) {
			content, err := readInput(deriveDataFilename(o.Args[0]))
			if err != nil {
				return err
			}
			return verifyDetached(o, store, data, content)
		}
		return verifySelfContained(o, store, data)

	default:
		sigData, err := readInput(o.Args[0])
		if err != nil {
			return err
		}
		content, err := readInput(o.Args[1])
		if err != nil {
			return err
		}
		return verifyDetached(o, store, sigData, content)
	}
}

// deriveDataFilename guesses the original data file name for a detached
// signature file (foo.sig / foo.asc -> foo), or "" to read from stdin.
func deriveDataFilename(sigPath string) string {
	for _, suffix := range []string{".sig", ".asc", ".gpg"} {
		if strings.HasSuffix(sigPath, suffix) {
			base := strings.TrimSuffix(sigPath, suffix)
			if _, err := os.Stat(base); err == nil {
				return base
			}
		}
	}
	return ""
}

func isDetachedSignature(data []byte) bool {
	trimmed := strings.TrimSpace(string(data))
	if strings.HasPrefix(trimmed, "-----BEGIN PGP SIGNATURE-----") {
		return true
	}
	if strings.HasPrefix(trimmed, "-----BEGIN PGP") {
		return false
	}
	p, err := packet.NewReader(bytes.NewReader(data)).Next()
	if err != nil {
		return false
	}
	_, ok := p.(*packet.Signature)
	return ok
}

func verifyDetached(o *Options, store *keystore.Store, sigData, content []byte) error {
	keyID, err := opsutil.VerifyDetached(content, sigData, store.PublicKeys())
	printVerifyResult(o, keyID, err)
	return err
}

func verifySelfContained(o *Options, store *keystore.Store, data []byte) error {
	trimmed := strings.TrimSpace(string(data))
	if strings.HasPrefix(trimmed, "-----BEGIN PGP SIGNED MESSAGE-----") {
		_, keyID, err := opsutil.VerifyClearSigned(trimmed, store.PublicKeys())
		printVerifyResult(o, keyID, err)
		return err
	}

	pgpMsg, err := opsutil.LoadPGPMessage(data)
	if err != nil {
		return err
	}
	ids, _ := pgpMsg.GetHexSignatureKeyIDs()
	var verifyKeys []*crypto.Key
	for _, id := range ids {
		verifyKeys = append(verifyKeys, keystore.Find(store.PublicKeys(), id)...)
	}

	res, err := opsutil.DecryptMessage(pgpMsg, nil, verifyKeys)
	if err != nil {
		return err
	}
	var keyID string
	if len(ids) > 0 {
		keyID = ids[0]
	}
	if res.SigError != nil {
		printVerifyResult(o, keyID, res.SigError)
		return res.SigError
	}
	if !res.Verified {
		return fmt.Errorf("no matching public key found to verify signature")
	}
	printVerifyResult(o, keyID, nil)
	return nil
}

func printVerifyResult(o *Options, keyID string, err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "gpg: BAD signature from key %s: %v\n", keyID, err)
		return
	}
	fmt.Fprintf(os.Stderr, "gpg: Good signature from key %s\n", keyID)
}
