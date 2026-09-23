package gpgagent

import (
	stdcrypto "crypto"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/oza6ut0ne/gpg-go/internal/sexp"
)

// Client is a high-level connection to gpg-agent for performing
// PKSIGN/PKDECRYPT operations with keys it holds.
type Client struct {
	conn           *Conn
	passphraseFunc func() ([]byte, error)
}

// NewClient connects to gpg-agent for homedir and enables loopback
// pinentry mode, so that a locked key's passphrase (see SetPassphrase)
// is supplied directly by this process instead of via an interactive
// pinentry program.
func NewClient(homedir string) (*Client, error) {
	conn, err := Dial(homedir)
	if err != nil {
		return nil, err
	}
	if _, err := conn.Command("OPTION pinentry-mode=loopback", nil); err != nil {
		conn.Close()
		return nil, fmt.Errorf("gpgagent: enabling loopback pinentry: %w", err)
	}
	return &Client{conn: conn}, nil
}

// Close closes the connection to gpg-agent.
func (c *Client) Close() error { return c.conn.Close() }

// SetPassphraseFunc installs a callback gpg-agent's client calls, lazily
// and at most once per operation, only if the targeted key turns out to
// be locked and not already cached by the agent (i.e. it is never
// invoked — and the caller never needs to prompt anyone — when the
// agent already has the key unlocked).
func (c *Client) SetPassphraseFunc(f func() ([]byte, error)) { c.passphraseFunc = f }

func (c *Client) inquireHandler(extra map[string][]byte) InquireFunc {
	return func(keyword string) ([]byte, bool) {
		if keyword == "PASSPHRASE" {
			if c.passphraseFunc == nil {
				return nil, false
			}
			p, err := c.passphraseFunc()
			if err != nil || len(p) == 0 {
				return nil, false
			}
			return p, true
		}
		if v, ok := extra[keyword]; ok {
			return v, true
		}
		return nil, false
	}
}

// HaveKey reports whether gpg-agent holds the private key with the
// given keygrip (uppercase hex).
func (c *Client) HaveKey(keygrip string) (bool, error) {
	_, err := c.conn.Command("HAVEKEY "+strings.ToUpper(keygrip), nil)
	if err == nil {
		return true, nil
	}
	var ae *assuanError
	if errors.As(err, &ae) {
		return false, nil
	}
	return false, err
}

// WrongPassphrase reports whether err indicates gpg-agent rejected the
// supplied passphrase (as opposed to some other failure).
func WrongPassphrase(err error) bool {
	var ae *assuanError
	if !errors.As(err, &ae) {
		return false
	}
	// GPG_ERR_BAD_PASSPHRASE = 11, in the (error source << 24 | code)
	// encoding gpg-agent reports it in.
	return ae.code&0xffffff == 11
}

// hashName maps a crypto.Hash to the name gpg-agent's SETHASH --hash=
// option expects.
func hashName(h stdcrypto.Hash) (string, error) {
	switch h {
	case stdcrypto.SHA1:
		return "sha1", nil
	case stdcrypto.SHA224:
		return "sha224", nil
	case stdcrypto.SHA256:
		return "sha256", nil
	case stdcrypto.SHA384:
		return "sha384", nil
	case stdcrypto.SHA512:
		return "sha512", nil
	case stdcrypto.RIPEMD160:
		return "rmd160", nil
	case stdcrypto.MD5:
		return "md5", nil
	default:
		return "", fmt.Errorf("gpgagent: unsupported hash algorithm %v", h)
	}
}

// isPureEdDSA reports whether algo needs gpg-agent's "SETHASH --inquire"
// form (the to-be-signed data is handed over as-is, since PureEdDSA does
// its own internal hashing rather than accepting a pre-computed digest
// annotated with a hash algorithm). This is NOT used for the legacy
// OpenPGP v4 EdDSA algorithm (22, curve ed25519): real gpg always uses
// the named "SETHASH --hash=<name> <digest>" form for it (confirmed
// against a real gpg trace), and gpg-agent's software-key backend merely
// tolerates --inquire there too — its scdaemon/smartcard dispatch does
// not, and fails PKSIGN with "Not implemented" if asked. --inquire is
// reserved for the v6-native algorithms, which this tool never produces
// or signs with today, but which do require it in principle.
func isPureEdDSA(algo packet.PublicKeyAlgorithm) bool {
	return algo == packet.PubKeyAlgoEd25519 || algo == packet.PubKeyAlgoEd448
}

// Sign asks gpg-agent to sign digest (already hashed the same way the
// resulting OpenPGP signature packet's Hash field declares) with the key
// identified by keygrip, and returns the parsed "(sig-val ...)"
// S-expression gpg-agent replies with.
func (c *Client) Sign(keygrip, keyDesc string, algo packet.PublicKeyAlgorithm, hash stdcrypto.Hash, digest []byte) (*sexp.Node, error) {
	if _, err := c.conn.Command("RESET", nil); err != nil {
		return nil, err
	}
	if _, err := c.conn.Command("SIGKEY "+strings.ToUpper(keygrip), nil); err != nil {
		return nil, err
	}
	if keyDesc != "" {
		if _, err := c.conn.Command("SETKEYDESC "+percentEncodeDesc(keyDesc), nil); err != nil {
			return nil, err
		}
	}

	inquire := c.inquireHandler(map[string][]byte{"TBSDATA": digest})

	if isPureEdDSA(algo) {
		if _, err := c.conn.Command("SETHASH --inquire", inquire); err != nil {
			return nil, err
		}
	} else {
		name, err := hashName(hash)
		if err != nil {
			return nil, err
		}
		cmd := fmt.Sprintf("SETHASH --hash=%s %s", name, hex.EncodeToString(digest))
		if _, err := c.conn.Command(cmd, nil); err != nil {
			return nil, err
		}
	}

	data, err := c.conn.Command("PKSIGN", inquire)
	if err != nil {
		return nil, fmt.Errorf("gpgagent: PKSIGN: %w", err)
	}
	node, _, err := sexp.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("gpgagent: parsing signature result: %w", err)
	}
	return node, nil
}

// Decrypt asks gpg-agent to perform the raw public-key decryption
// operation (RFC 4880 "enc-val" style ciphertext in) for the key
// identified by keygrip, and returns the raw result bytes (parsing of
// the wrapping "(value|data ...)" S-expression is the caller's
// responsibility, since its shape differs by algorithm).
func (c *Client) Decrypt(keygrip, keyDesc string, cipherSexp []byte) ([]byte, error) {
	if _, err := c.conn.Command("RESET", nil); err != nil {
		return nil, err
	}
	if _, err := c.conn.Command("SETKEY "+strings.ToUpper(keygrip), nil); err != nil {
		return nil, err
	}
	if keyDesc != "" {
		if _, err := c.conn.Command("SETKEYDESC "+percentEncodeDesc(keyDesc), nil); err != nil {
			return nil, err
		}
	}

	inquire := c.inquireHandler(map[string][]byte{"CIPHERTEXT": cipherSexp})
	data, err := c.conn.Command("PKDECRYPT", inquire)
	if err != nil {
		return nil, fmt.Errorf("gpgagent: PKDECRYPT: %w", err)
	}
	return data, nil
}
