package gpgcli

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"strings"
	"syscall"

	"golang.org/x/term"
)

// ResolvePassphrase returns the passphrase to use for a private-key or
// symmetric operation, honoring --passphrase / --passphrase-file, or
// prompting interactively (unless --batch is set, in which case a missing
// passphrase is an error).
func ResolvePassphrase(o *Options, prompt string) ([]byte, error) {
	if o.PassphraseFile != "" {
		data, err := os.ReadFile(o.PassphraseFile)
		if err != nil {
			return nil, fmt.Errorf("reading passphrase file: %w", err)
		}
		return bytes.TrimRight(data, "\r\n"), nil
	}
	if o.PassphraseSet {
		return []byte(o.Passphrase), nil
	}
	if o.Batch {
		return nil, fmt.Errorf("no passphrase supplied in --batch mode; use --passphrase or --passphrase-file")
	}
	return readPassphraseInteractive(prompt)
}

func readPassphraseInteractive(prompt string) ([]byte, error) {
	fmt.Fprint(os.Stderr, prompt)
	if term.IsTerminal(int(syscall.Stdin)) {
		pw, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return nil, fmt.Errorf("reading passphrase: %w", err)
		}
		return pw, nil
	}
	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	if err != nil && line == "" {
		return nil, fmt.Errorf("reading passphrase: %w", err)
	}
	return []byte(strings.TrimRight(line, "\r\n")), nil
}

// prompt is a small helper for interactive yes/no or free-text questions
// used by key generation.
func prompt(question string) (string, error) {
	fmt.Fprint(os.Stderr, question)
	reader := bufio.NewReader(os.Stdin)
	line, err := reader.ReadString('\n')
	if err != nil && line == "" {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}
