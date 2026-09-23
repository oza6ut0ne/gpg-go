package agentkey

import (
	"bytes"
	"fmt"
	"os"
	"strconv"

	"github.com/oza6ut0ne/gpg-go/internal/sexp"
)

// secretParamNames returns, for a given algorithm, the set of parameter
// names that hold private key material (and must therefore be encrypted
// when the key is protected), matching gpg-agent's protect_info table.
func secretParamNames(algo string) map[string]bool {
	switch algo {
	case "rsa":
		return map[string]bool{"d": true, "p": true, "q": true, "u": true}
	default: // "ecc" (covers eddsa/ed25519 and ecdh/cv25519 in agent files)
		return map[string]bool{"d": true}
	}
}

// Node serializes the key (protected or not) into its S-expression form.
func (k *Key) Node() *sexp.Node {
	children := []*sexp.Node{sexp.S(k.Algo)}
	for _, p := range k.Clear {
		children = append(children, paramNode(p))
	}

	if k.IsProtected() {
		s2kList := sexp.L(sexp.S("sha1"), sexp.A(k.salt), sexp.S(strconv.Itoa(k.s2kCount)))
		protParams := sexp.L(s2kList, sexp.A(k.nonce))
		protected := sexp.L(sexp.S("protected"), sexp.S(string(k.protectedMode)), protParams, sexp.A(k.ciphertext))
		children = append(children, protected)
		if k.ProtectedAt != "" {
			children = append(children, sexp.L(sexp.S("protected-at"), sexp.S(k.ProtectedAt)))
		}
		return sexp.L(sexp.S("protected-private-key"), sexp.L(children...))
	}

	for _, p := range k.Secret {
		children = append(children, paramNode(p))
	}
	return sexp.L(sexp.S("private-key"), sexp.L(children...))
}

// FromNode parses a (private-key ...) or (protected-private-key ...)
// S-expression tree, as produced by sexp.Parse, into a Key.
func FromNode(node *sexp.Node) (*Key, error) {
	if !node.IsList() || node.Len() != 2 || !node.Get(0).IsAtom() {
		return nil, fmt.Errorf("agentkey: invalid key s-expression")
	}
	tag := node.Get(0).Str()
	if tag != "private-key" && tag != "protected-private-key" {
		return nil, fmt.Errorf("agentkey: unsupported key tag %q", tag)
	}

	algoList := node.Get(1)
	if !algoList.IsList() || algoList.Len() < 1 || !algoList.Get(0).IsAtom() {
		return nil, fmt.Errorf("agentkey: invalid algorithm list")
	}
	algo := algoList.Get(0).Str()
	secretNames := secretParamNames(algo)

	k := &Key{Algo: algo}
	for i := 1; i < algoList.Len(); i++ {
		child := algoList.Get(i)
		if !child.IsList() || child.Len() < 1 || !child.Get(0).IsAtom() {
			return nil, fmt.Errorf("agentkey: unexpected entry in key parameter list")
		}
		name := child.Get(0).Str()

		switch name {
		case "protected":
			if tag != "protected-private-key" {
				return nil, fmt.Errorf("agentkey: unexpected 'protected' entry in cleartext key")
			}
			if child.Len() != 4 || !child.Get(1).IsAtom() {
				return nil, fmt.Errorf("agentkey: malformed 'protected' entry")
			}
			params := child.Get(2)
			if !params.IsList() || params.Len() != 2 {
				return nil, fmt.Errorf("agentkey: malformed protection parameters")
			}
			s2kList := params.Get(0)
			if !s2kList.IsList() || s2kList.Len() != 3 || s2kList.Get(0).Str() != "sha1" {
				return nil, fmt.Errorf("agentkey: unsupported s2k specifier")
			}
			count, err := strconv.Atoi(s2kList.Get(2).Str())
			if err != nil {
				return nil, fmt.Errorf("agentkey: invalid s2k count: %w", err)
			}
			ciphertext := child.Get(3)
			if !ciphertext.IsAtom() {
				return nil, fmt.Errorf("agentkey: malformed ciphertext")
			}
			k.protectedMode = ProtectMode(child.Get(1).Str())
			k.salt = s2kList.Get(1).Atom
			k.s2kCount = count
			k.nonce = params.Get(1).Atom
			k.ciphertext = ciphertext.Atom

		case "protected-at":
			if child.Len() != 2 || !child.Get(1).IsAtom() {
				return nil, fmt.Errorf("agentkey: malformed protected-at entry")
			}
			k.ProtectedAt = child.Get(1).Str()
			k.protectedAtNod = child

		default:
			if child.Len() != 2 || !child.Get(1).IsAtom() {
				return nil, fmt.Errorf("agentkey: malformed parameter %q", name)
			}
			p := Param{Name: name, Value: child.Get(1).Atom}
			if secretNames[name] && tag == "private-key" {
				k.Secret = append(k.Secret, p)
			} else {
				k.Clear = append(k.Clear, p)
			}
		}
	}

	return k, nil
}

// Parse parses the content of a private-keys-v1.d/*.key file (the
// "Created:"/"Key:" name-value container gpg-agent writes) into a Key.
func Parse(data []byte) (*Key, error) {
	const marker = "Key: "
	idx := bytes.Index(data, []byte(marker))
	if idx == -1 {
		return nil, fmt.Errorf("agentkey: no 'Key:' entry found")
	}
	rest := data[idx+len(marker):]
	node, _, err := sexp.Parse(rest)
	if err != nil {
		return nil, fmt.Errorf("agentkey: parsing s-expression: %w", err)
	}
	return FromNode(node)
}

// Serialize renders the key as the content of a private-keys-v1.d/*.key
// file.
func (k *Key) Serialize() []byte {
	var buf bytes.Buffer
	buf.WriteString("Created: ")
	buf.WriteString(nowTimestamp())
	buf.WriteString("\nKey: ")
	buf.Write(k.Node().Advanced())
	buf.WriteString("\n")
	return buf.Bytes()
}

// ReadFile reads and parses a private-keys-v1.d/*.key file.
func ReadFile(path string) (*Key, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(data)
}

// WriteFile writes k to path (mode 0600, creating parent dirs as needed).
func WriteFile(path string, k *Key) error {
	return os.WriteFile(path, k.Serialize(), 0o600)
}
