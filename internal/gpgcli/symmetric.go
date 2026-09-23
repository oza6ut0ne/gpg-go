package gpgcli

import (
	"fmt"
	"path/filepath"

	"github.com/oza6ut0ne/gpg-go/internal/opsutil"
)

func cmdSymmetric(o *Options) error {
	var inputPath string
	if len(o.Args) > 0 {
		inputPath = o.Args[0]
	}
	data, err := readInput(inputPath)
	if err != nil {
		return err
	}

	pass, err := ResolvePassphrase(o, "Enter passphrase: ")
	if err != nil {
		return err
	}
	if !o.PassphraseSet && o.PassphraseFile == "" && !o.Batch {
		confirm, err := readPassphraseInteractive("Repeat passphrase: ")
		if err != nil {
			return err
		}
		if string(confirm) != string(pass) {
			return fmt.Errorf("passphrases do not match")
		}
	}

	var filename string
	if inputPath != "" && inputPath != "-" {
		filename = filepath.Base(inputPath)
	}

	ciphertext, err := opsutil.SymmetricEncrypt(data, filename, pass, o.Armor)
	if err != nil {
		return err
	}

	suffix := ".gpg"
	if o.Armor {
		suffix = ".asc"
	}
	outPath := outputPath(o, inputPath, suffix)
	return writeOutput(o, outPath, ciphertext, 0o644)
}
