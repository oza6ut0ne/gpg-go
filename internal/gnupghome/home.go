// Package gnupghome resolves and prepares the tool's home directory, where
// the public/secret keyrings are stored. Resolution order and the default
// path (~/.gnupg) match gpg's own --homedir / GNUPGHOME behavior exactly,
// so this tool reads and writes the same real GnuPG keyring by default.
package gnupghome

import (
	"fmt"
	"os"
	"path/filepath"
)

const defaultDirName = ".gnupg"

// Resolve returns the home directory to use, given an explicit --homedir
// flag value (may be empty). Resolution order matches gpg: explicit flag,
// then $GNUPGHOME, then the default.
func Resolve(flagValue string) (string, error) {
	if flagValue != "" {
		return flagValue, nil
	}
	if env := os.Getenv("GNUPGHOME"); env != "" {
		return env, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("determining home directory: %w", err)
	}
	return filepath.Join(home, defaultDirName), nil
}

// Ensure creates the home directory (mode 0700) if it does not exist yet.
func Ensure(dir string) error {
	info, err := os.Stat(dir)
	if os.IsNotExist(err) {
		return os.MkdirAll(dir, 0o700)
	}
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("%s exists and is not a directory", dir)
	}
	return os.Chmod(dir, 0o700)
}

// KbxPath returns the path of the public keybox file.
func KbxPath(dir string) string {
	return filepath.Join(dir, "pubring.kbx")
}

// PrivateKeysDir returns the path of the private key material directory.
func PrivateKeysDir(dir string) string {
	return filepath.Join(dir, "private-keys-v1.d")
}
