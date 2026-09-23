// Package sexp implements the small subset of "S-expressions as used by
// libgcrypt/gpg-agent" needed to read and write GnuPG's
// private-keys-v1.d/*.key files: a tree of atoms (raw byte strings) and
// lists, with two on-the-wire syntaxes:
//
//   - canonical: "N:bytes" atoms, "(...)" lists, no whitespace. This is
//     what gpg-agent uses internally (and for the OCB AAD/plaintext
//     framing), and what this package uses for Node.Canonical().
//   - advanced: the human-readable form gpg-agent actually writes to
//     disk, mixing bareword tokens, quoted decimal strings and
//     "#HEX#" binary atoms. Node.Advanced() produces (a non-line-wrapped
//     but otherwise equivalent) rendering of this; Parse understands
//     both forms, plus the base64 "|...|" atom form some writers use.
package sexp

import (
	"bytes"
	"fmt"
	"strconv"
)

// Node is either an atom (Atom != nil, List == nil) or a list
// (List != nil, Atom == nil). A list may be empty (non-nil zero-length
// slice) to distinguish it from an atom.
type Node struct {
	Atom []byte
	List []*Node
}

// A returns an atom node wrapping b (not copied).
func A(b []byte) *Node { return &Node{Atom: b} }

// S returns an atom node from a string, a common case for tokens.
func S(s string) *Node { return &Node{Atom: []byte(s)} }

// L returns a list node containing the given children.
func L(items ...*Node) *Node { return &Node{List: items} }

func (n *Node) IsAtom() bool { return n != nil && n.Atom != nil }
func (n *Node) IsList() bool { return n != nil && n.List != nil }

// Get returns the i-th child of a list node, or nil if out of range or n
// is not a list.
func (n *Node) Get(i int) *Node {
	if !n.IsList() || i < 0 || i >= len(n.List) {
		return nil
	}
	return n.List[i]
}

// Len returns the number of children of a list node (0 for an atom).
func (n *Node) Len() int {
	if !n.IsList() {
		return 0
	}
	return len(n.List)
}

// Str returns the atom's bytes as a string (empty if n is not an atom).
func (n *Node) Str() string {
	if !n.IsAtom() {
		return ""
	}
	return string(n.Atom)
}

// Find returns the first child list whose first element is the atom
// name, e.g. Find("curve") on (ecc (curve Ed25519) (q ...)) returns
// (curve Ed25519).
func (n *Node) Find(name string) *Node {
	if !n.IsList() {
		return nil
	}
	for _, c := range n.List {
		if c.IsList() && c.Get(0).IsAtom() && c.Get(0).Str() == name {
			return c
		}
	}
	return nil
}

// Canonical serializes n into canonical S-expression bytes.
func (n *Node) Canonical() []byte {
	var buf bytes.Buffer
	n.writeCanonical(&buf)
	return buf.Bytes()
}

func (n *Node) writeCanonical(buf *bytes.Buffer) {
	if n.IsAtom() {
		buf.WriteString(strconv.Itoa(len(n.Atom)))
		buf.WriteByte(':')
		buf.Write(n.Atom)
		return
	}
	buf.WriteByte('(')
	for _, c := range n.List {
		c.writeCanonical(buf)
	}
	buf.WriteByte(')')
}

// isPrintableToken reports whether b can be rendered as a bare token in
// advanced form: printable ASCII, no delimiters, and not starting with a
// digit (a leading digit would be ambiguous with canonical-form length
// prefixes / is quoted instead, matching gpg-agent's own printer).
func isPrintableToken(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	if b[0] >= '0' && b[0] <= '9' {
		return false
	}
	for _, c := range b {
		if c < 0x21 || c > 0x7e {
			return false
		}
		switch c {
		case '(', ')', '"', '#', '|', '\\':
			return false
		}
	}
	return true
}

func isPrintableAny(b []byte) bool {
	if len(b) == 0 {
		return true
	}
	for _, c := range b {
		if c < 0x20 || c > 0x7e {
			return false
		}
		if c == '"' || c == '\\' {
			return false
		}
	}
	return true
}

// Advanced serializes n into gpg-agent's "advanced" printable form
// (barewords / quoted digit-strings / #HEX# atoms), on one line.
func (n *Node) Advanced() []byte {
	var buf bytes.Buffer
	n.writeAdvanced(&buf)
	return buf.Bytes()
}

func (n *Node) writeAdvanced(buf *bytes.Buffer) {
	if n.IsAtom() {
		switch {
		case isPrintableToken(n.Atom):
			buf.Write(n.Atom)
		case isPrintableAny(n.Atom):
			buf.WriteByte('"')
			buf.Write(n.Atom)
			buf.WriteByte('"')
		default:
			buf.WriteByte('#')
			fmt.Fprintf(buf, "%X", n.Atom)
			buf.WriteByte('#')
		}
		return
	}
	buf.WriteByte('(')
	for i, c := range n.List {
		if i > 0 {
			buf.WriteByte(' ')
		}
		c.writeAdvanced(buf)
	}
	buf.WriteByte(')')
}
