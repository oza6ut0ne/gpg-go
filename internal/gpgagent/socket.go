package gpgagent

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// ErrNotAvailable indicates gpg-agent's socket could not be found or
// connected to (it is not running, or this environment has no gpgconf/
// homedir-socket to locate it).
var ErrNotAvailable = errors.New("gpgagent: agent not available")

// SocketPath returns the path of gpg-agent's Assuan socket for homedir,
// preferring `gpgconf --list-dirs agent-socket` (which correctly handles
// GnuPG's socket-directory redirection) and falling back to
// homedir/S.gpg-agent.
func SocketPath(homedir string) (string, error) {
	if out, err := exec.Command("gpgconf", "--homedir", homedir, "--list-dirs", "agent-socket").Output(); err == nil {
		if p := strings.TrimSpace(string(out)); p != "" {
			return p, nil
		}
	}
	return resolveSocketFile(filepath.Join(homedir, "S.gpg-agent"))
}

// resolveSocketFile follows GnuPG's socket redirection convention: a
// plain file (instead of being the socket itself) starting with
// "%Assuan%" names the real socket location on its second line.
func resolveSocketFile(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("%w: %s", ErrNotAvailable, err)
	}
	if info.Mode()&os.ModeSocket != 0 {
		return path, nil
	}

	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("%w: %s", ErrNotAvailable, err)
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	if !scanner.Scan() {
		return "", fmt.Errorf("%w: empty socket redirect file", ErrNotAvailable)
	}
	if strings.TrimSpace(scanner.Text()) != "%Assuan%" {
		return "", fmt.Errorf("%w: unrecognized socket redirect file", ErrNotAvailable)
	}
	if !scanner.Scan() {
		return "", fmt.Errorf("%w: malformed socket redirect file", ErrNotAvailable)
	}
	return strings.TrimSpace(scanner.Text()), nil
}

// Dial connects to gpg-agent for homedir and completes the initial
// Assuan handshake.
func Dial(homedir string) (*Conn, error) {
	path, err := SocketPath(homedir)
	if err != nil {
		return nil, err
	}
	c, err := net.Dial("unix", path)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", ErrNotAvailable, err)
	}
	conn, err := newConn(c)
	if err != nil {
		c.Close()
		return nil, err
	}
	return conn, nil
}
