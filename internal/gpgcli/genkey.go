package gpgcli

import (
	"fmt"
	"os"
	"strings"

	"github.com/ProtonMail/gopenpgp/v2/crypto"
	"github.com/oza6ut0ne/gpg-go/internal/keystore"
	"github.com/oza6ut0ne/gpg-go/internal/opsutil"
)

func cmdGenKey(o *Options) error {
	if o.Batch {
		return fmt.Errorf("--gen-key is interactive; use --quick-gen-key in --batch mode")
	}

	fmt.Println("Please select what kind of key you want:")
	fmt.Println("   (1) Ed25519/Cv25519 (default, recommended)")
	fmt.Println("   (2) RSA and RSA")
	choice, err := prompt("Your selection? ")
	if err != nil {
		return err
	}

	algo := "ed25519"
	bits := 0
	if strings.TrimSpace(choice) == "2" {
		algo = "rsa"
		sizeStr, err := prompt("What keysize do you want? (2048/3072/4096) [3072] ")
		if err != nil {
			return err
		}
		bits = AtoiOrZero(strings.TrimSpace(sizeStr))
		if bits == 0 {
			bits = 3072
		}
	}

	expireStr, err := prompt("Key is valid for? (0 = key does not expire) [0] ")
	if err != nil {
		return err
	}
	expireSecs, err := opsutil.ParseExpire(strings.TrimSpace(expireStr))
	if err != nil {
		return err
	}

	name, err := prompt("Real name: ")
	if err != nil {
		return err
	}
	email, err := prompt("Email address: ")
	if err != nil {
		return err
	}
	comment, err := prompt("Comment: ")
	if err != nil {
		return err
	}

	uid := formatUID(name, comment, email)
	fmt.Printf("You selected this USER-ID:\n    %q\n", uid)
	confirm, err := prompt("Change (N)ame, (C)omment, (E)mail, or (O)kay/(Q)uit? [O] ")
	if err != nil {
		return err
	}
	if v := strings.ToUpper(strings.TrimSpace(confirm)); v == "Q" {
		return fmt.Errorf("key generation cancelled")
	}

	pass1, err := readPassphraseInteractive("Enter passphrase (empty for no passphrase): ")
	if err != nil {
		return err
	}
	if len(pass1) > 0 {
		pass2, err := readPassphraseInteractive("Repeat passphrase: ")
		if err != nil {
			return err
		}
		if string(pass1) != string(pass2) {
			return fmt.Errorf("passphrases do not match")
		}
	}

	return generateAndStore(o, name, comment, email, algo, bits, expireSecs, pass1)
}

func cmdQuickGenKey(o *Options) error {
	if len(o.Args) < 1 {
		return fmt.Errorf("usage: --quick-gen-key USER-ID [ALGO [USAGE [EXPIRE]]]")
	}
	name, comment, email := opsutil.ParseUserID(o.Args[0])

	algo := "default"
	if len(o.Args) >= 2 {
		algo = o.Args[1]
	}
	// o.Args[2] (USAGE) is accepted for gpg compatibility but both our
	// supported algorithms already produce a sign+certify primary key and
	// an encryption subkey, so it has no further effect here.
	expireSpec := "0"
	if len(o.Args) >= 4 {
		expireSpec = o.Args[3]
	}
	expireSecs, err := opsutil.ParseExpire(expireSpec)
	if err != nil {
		return err
	}

	var pass []byte
	if o.PassphraseSet || o.PassphraseFile != "" {
		pass, err = ResolvePassphrase(o, "")
		if err != nil {
			return err
		}
	} else if !o.Batch {
		pass, err = readPassphraseInteractive("Enter passphrase (empty for no passphrase): ")
		if err != nil {
			return err
		}
	}

	return generateAndStore(o, name, comment, email, algo, 0, expireSecs, pass)
}

func formatUID(name, comment, email string) string {
	uid := name
	if comment != "" {
		uid = fmt.Sprintf("%s (%s)", uid, comment)
	}
	if email != "" {
		uid = fmt.Sprintf("%s <%s>", uid, email)
	}
	return uid
}

func generateAndStore(o *Options, name, comment, email, algo string, bits int, expireSecs uint32, passphrase []byte) error {
	key, err := opsutil.GenerateKey(name, comment, email, algo, bits, expireSecs)
	if err != nil {
		return err
	}

	store, err := openStore(o)
	if err != nil {
		return err
	}
	if err := store.AddSecretKey(key, passphrase); err != nil {
		return err
	}
	if err := store.SavePublic(); err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "gpg: key %s marked as ultimately trusted\n", keystore.LongKeyID(key.GetFingerprint()))
	fmt.Println("public and secret key created and signed.")
	fmt.Println()
	printGeneratedSummary(key)
	return nil
}

func printGeneratedSummary(key *crypto.Key) {
	var sb strings.Builder
	keystore.PrintKeyList(&sb, []*crypto.Key{key}, false, keystore.ListOptions{})
	fmt.Print(sb.String())
}
