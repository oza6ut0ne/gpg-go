package sexp

import (
	"fmt"
)

// Parse parses a single S-expression from data (canonical or advanced
// form, or a mix within nested atoms as gpg-agent itself allows) and
// returns the node plus any trailing unconsumed bytes.
func Parse(data []byte) (*Node, []byte, error) {
	p := &parser{data: data}
	p.skipSpace()
	n, err := p.parseNode()
	if err != nil {
		return nil, nil, err
	}
	return n, p.data[p.pos:], nil
}

type parser struct {
	data []byte
	pos  int
}

func (p *parser) skipSpace() {
	for p.pos < len(p.data) {
		switch p.data[p.pos] {
		case ' ', '\t', '\r', '\n':
			p.pos++
		default:
			return
		}
	}
}

func (p *parser) peek() (byte, bool) {
	if p.pos >= len(p.data) {
		return 0, false
	}
	return p.data[p.pos], true
}

func (p *parser) parseNode() (*Node, error) {
	p.skipSpace()
	c, ok := p.peek()
	if !ok {
		return nil, fmt.Errorf("sexp: unexpected end of input")
	}
	switch {
	case c == '(':
		return p.parseList()
	case c == '#':
		return p.parseHex()
	case c == '"':
		return p.parseQuoted()
	case c >= '0' && c <= '9':
		return p.parseCanonicalAtom()
	default:
		return p.parseToken()
	}
}

func (p *parser) parseList() (*Node, error) {
	p.pos++ // consume '('
	items := []*Node{}
	for {
		p.skipSpace()
		c, ok := p.peek()
		if !ok {
			return nil, fmt.Errorf("sexp: unterminated list")
		}
		if c == ')' {
			p.pos++
			return &Node{List: items}, nil
		}
		child, err := p.parseNode()
		if err != nil {
			return nil, err
		}
		items = append(items, child)
	}
}

// parseCanonicalAtom parses "N:bytes".
func (p *parser) parseCanonicalAtom() (*Node, error) {
	start := p.pos
	for p.pos < len(p.data) && p.data[p.pos] >= '0' && p.data[p.pos] <= '9' {
		p.pos++
	}
	if p.pos >= len(p.data) || p.data[p.pos] != ':' {
		return nil, fmt.Errorf("sexp: invalid canonical length at offset %d", start)
	}
	n := 0
	for _, d := range p.data[start:p.pos] {
		n = n*10 + int(d-'0')
	}
	p.pos++ // consume ':'
	if p.pos+n > len(p.data) {
		return nil, fmt.Errorf("sexp: canonical atom length %d exceeds input", n)
	}
	atom := p.data[p.pos : p.pos+n]
	p.pos += n
	return &Node{Atom: atom}, nil
}

// parseHex parses "#HEXHEX...#", ignoring whitespace between digits.
func (p *parser) parseHex() (*Node, error) {
	p.pos++ // consume '#'
	var nibbles []byte
	for {
		if p.pos >= len(p.data) {
			return nil, fmt.Errorf("sexp: unterminated hex atom")
		}
		c := p.data[p.pos]
		if c == '#' {
			p.pos++
			break
		}
		if c == ' ' || c == '\t' || c == '\r' || c == '\n' {
			p.pos++
			continue
		}
		nibbles = append(nibbles, c)
		p.pos++
	}
	if len(nibbles)%2 != 0 {
		return nil, fmt.Errorf("sexp: odd number of hex digits")
	}
	out := make([]byte, len(nibbles)/2)
	for i := 0; i < len(out); i++ {
		hi, err := hexVal(nibbles[2*i])
		if err != nil {
			return nil, err
		}
		lo, err := hexVal(nibbles[2*i+1])
		if err != nil {
			return nil, err
		}
		out[i] = hi<<4 | lo
	}
	return &Node{Atom: out}, nil
}

func hexVal(c byte) (byte, error) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', nil
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, nil
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, nil
	default:
		return 0, fmt.Errorf("sexp: invalid hex digit %q", c)
	}
}

// parseQuoted parses a "..." string atom with minimal backslash escaping.
func (p *parser) parseQuoted() (*Node, error) {
	p.pos++ // consume opening quote
	var out []byte
	for {
		if p.pos >= len(p.data) {
			return nil, fmt.Errorf("sexp: unterminated quoted string")
		}
		c := p.data[p.pos]
		if c == '"' {
			p.pos++
			return &Node{Atom: out}, nil
		}
		if c == '\\' && p.pos+1 < len(p.data) {
			p.pos++
			switch p.data[p.pos] {
			case 'n':
				out = append(out, '\n')
			case 'r':
				out = append(out, '\r')
			case 't':
				out = append(out, '\t')
			default:
				out = append(out, p.data[p.pos])
			}
			p.pos++
			continue
		}
		out = append(out, c)
		p.pos++
	}
}

// parseToken parses a bareword token, up to the next delimiter.
func (p *parser) parseToken() (*Node, error) {
	start := p.pos
	for p.pos < len(p.data) {
		c := p.data[p.pos]
		if c == '(' || c == ')' || c == ' ' || c == '\t' || c == '\r' || c == '\n' {
			break
		}
		p.pos++
	}
	if p.pos == start {
		return nil, fmt.Errorf("sexp: empty token at offset %d", start)
	}
	return &Node{Atom: p.data[start:p.pos]}, nil
}
