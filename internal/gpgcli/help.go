package gpgcli

import "fmt"

const version = "0.0.1"

func printVersion() {
	fmt.Printf("gpg-go (GopenPGP-based gpg-compatible tool) %s\n", version)
	fmt.Println("Backed by ProtonMail/gopenpgp v2 and go-crypto.")
}

func printHelp() {
	fmt.Print(`Usage: gpg-go [options] [files]

Key management:
  --gen-key                          generate a new key pair (interactive)
  --full-generate-key                same as --gen-key
  --quick-gen-key USER-ID [ALGO [USAGE [EXPIRE]]]
                                      generate a key non-interactively
  -k, --list-keys [NAMES...]         list public keys
  -K, --list-secret-keys [NAMES...]  list secret keys
  --fingerprint                      show fingerprints when listing
  --with-subkey-fingerprints         show subkey fingerprints when listing
  --with-keygrip                     show keygrips when listing
  --export [NAMES...]                export public key(s)
  --export-secret-keys [NAMES...]    export secret key(s)
  --import FILE                      import keys from FILE (or stdin)
  --delete-key NAME                  delete a public key
  --delete-secret-key NAME           delete a secret key
  --delete-secret-and-public-key NAME
                                      delete both public and secret key

Encryption / signing:
  -e, --encrypt                      encrypt data
  -s, --sign                         make a signature (or sign+encrypt with -e)
  -b, --detach-sign                  make a detached signature
  --clearsign                        make a cleartext signature
  -c, --symmetric                    encrypt with a passphrase
  -d, --decrypt                      decrypt data
  --verify [SIGFILE] [FILE]          verify a signature

Common options:
  -a, --armor                        create ASCII armored output
  -o, --output FILE                  write output to FILE
  -r, --recipient NAME                encrypt for NAME (repeatable)
  -R, --hidden-recipient NAME          encrypt for NAME, hiding its key ID (repeatable)
  -u, --local-user NAME               use NAME as the signing key
  --homedir DIR                      use DIR as the home directory
  --options FILE                     read options from FILE instead of homedir/gpg.conf
  --no-options                       do not read any options file
  --passphrase STRING                use STRING as the passphrase
  --passphrase-file FILE             read the passphrase from FILE
  --pinentry-mode loopback           read the passphrase without a pinentry
  --batch                            never interact, fail if input is needed
  --yes                              assume "yes" on overwrite prompts
  -q, --quiet / -v, --verbose        less / more output
  --list-packets FILE                dump the low-level OpenPGP packet structure of FILE
  --version                          show version information
  --help                             show this help
`)
}
