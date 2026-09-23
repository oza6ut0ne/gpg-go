// Command gpg-go is a gpg-compatible command-line tool built on top of
// GopenPGP (ProtonMail/gopenpgp) and go-crypto (ProtonMail/go-crypto),
// mirroring the most commonly used gpg options and behavior.
package main

import (
	"fmt"
	"os"

	"github.com/oza6ut0ne/gpg-go/internal/gpgcli"
)

func main() {
	if err := gpgcli.Run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "gpg-go: %v\n", err)
		os.Exit(1)
	}
}
