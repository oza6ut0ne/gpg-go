// Package gpgagent implements just enough of the Assuan IPC protocol to
// talk to a running gpg-agent: locating its socket, and issuing the
// HAVEKEY/SIGKEY/SETKEY/SETKEYDESC/SETHASH/PKSIGN/PKDECRYPT commands
// needed to sign or decrypt using a key gpg-agent already holds, instead
// of this tool reading and unprotecting private-keys-v1.d itself.
package gpgagent

import (
	"bufio"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// Conn is a raw Assuan connection: one command at a time, line based.
type Conn struct {
	c net.Conn
	r *bufio.Reader
}

// InquireFunc supplies the data to answer a server "INQUIRE keyword"
// request. ok=false cancels the inquiry (sent as "CAN").
type InquireFunc func(keyword string) (data []byte, ok bool)

func newConn(c net.Conn) (*Conn, error) {
	ac := &Conn{c: c, r: bufio.NewReader(c)}
	// The server sends a greeting line ("OK Pleased to meet you" or
	// similar) immediately upon connection.
	line, err := ac.readLine()
	if err != nil {
		return nil, fmt.Errorf("gpgagent: reading greeting: %w", err)
	}
	if !strings.HasPrefix(line, "OK") {
		return nil, fmt.Errorf("gpgagent: unexpected greeting: %q", line)
	}
	return ac, nil
}

func (c *Conn) Close() error { return c.c.Close() }

func (c *Conn) readLine() (string, error) {
	line, err := c.r.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func (c *Conn) writeLine(s string) error {
	_, err := c.c.Write([]byte(s + "\n"))
	return err
}

// Command sends a single Assuan command line and processes the
// response, answering any INQUIRE requests via inquire (which may be
// nil if none are expected). It returns the concatenated bytes of every
// "D" data line received, or an error built from an "ERR" response.
func (c *Conn) Command(cmd string, inquire InquireFunc) ([]byte, error) {
	if err := c.writeLine(cmd); err != nil {
		return nil, err
	}
	return c.readResponse(inquire)
}

func (c *Conn) readResponse(inquire InquireFunc) ([]byte, error) {
	var data []byte
	for {
		line, err := c.readLine()
		if err != nil {
			return nil, err
		}
		switch {
		case line == "OK" || strings.HasPrefix(line, "OK "):
			return data, nil
		case strings.HasPrefix(line, "ERR "):
			return nil, parseErr(line)
		case strings.HasPrefix(line, "D "):
			data = append(data, percentDecode(line[2:])...)
		case line == "D":
			// empty data line
		case strings.HasPrefix(line, "S "), line == "S":
			// status line, ignored
		case strings.HasPrefix(line, "INQUIRE "):
			keyword := strings.TrimPrefix(line, "INQUIRE ")
			if sp := strings.IndexByte(keyword, ' '); sp != -1 {
				keyword = keyword[:sp]
			}
			var answer []byte
			var ok bool
			if inquire != nil {
				answer, ok = inquire(keyword)
			}
			if !ok {
				if err := c.writeLine("CAN"); err != nil {
					return nil, err
				}
				continue
			}
			if err := c.sendData(answer); err != nil {
				return nil, err
			}
		case strings.HasPrefix(line, "#"):
			// comment, ignored
		default:
			// Unknown line type; ignore rather than fail the whole
			// exchange over a status line we don't understand.
		}
	}
}

// sendData writes data as one or more "D " lines followed by "END".
func (c *Conn) sendData(data []byte) error {
	const maxLineData = 900 // stay well under Assuan's line length limit
	encoded := percentEncode(data)
	for len(encoded) > 0 {
		n := len(encoded)
		if n > maxLineData {
			n = maxLineData
		}
		if err := c.writeLine("D " + encoded[:n]); err != nil {
			return err
		}
		encoded = encoded[n:]
	}
	return c.writeLine("END")
}

type assuanError struct {
	code int
	desc string
}

func (e *assuanError) Error() string {
	if e.desc != "" {
		return fmt.Sprintf("gpg-agent: %s (%d)", e.desc, e.code)
	}
	return fmt.Sprintf("gpg-agent: error %d", e.code)
}

func parseErr(line string) error {
	fields := strings.SplitN(strings.TrimPrefix(line, "ERR "), " ", 2)
	code, _ := strconv.Atoi(fields[0])
	desc := ""
	if len(fields) > 1 {
		desc = fields[1]
	}
	return &assuanError{code: code, desc: desc}
}

// percentEncode escapes bytes Assuan requires escaping in data lines:
// '%', CR, LF and other control characters.
func percentEncode(data []byte) string {
	var sb strings.Builder
	for _, b := range data {
		if b == '%' || b == '\r' || b == '\n' || b < 0x20 || b == 0x7f {
			fmt.Fprintf(&sb, "%%%02X", b)
		} else {
			sb.WriteByte(b)
		}
	}
	return sb.String()
}

// percentDecode reverses percentEncode.
func percentDecode(s string) []byte {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			hi, ok1 := hexDigit(s[i+1])
			lo, ok2 := hexDigit(s[i+2])
			if ok1 && ok2 {
				out = append(out, hi<<4|lo)
				i += 2
				continue
			}
		}
		out = append(out, s[i])
	}
	return out
}

func hexDigit(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	default:
		return 0, false
	}
}

// percentEncodeDesc escapes a string for SETKEYDESC: gpg-agent unescapes
// '%' sequences and turns '+' into a space, so literal spaces must be
// percent-encoded (or replaced with '+') and '+'/'%' themselves escaped.
func percentEncodeDesc(s string) string {
	var sb strings.Builder
	for _, b := range []byte(s) {
		switch {
		case b == ' ':
			sb.WriteByte('+')
		case b == '%' || b == '+' || b < 0x20 || b == 0x7f:
			fmt.Fprintf(&sb, "%%%02X", b)
		default:
			sb.WriteByte(b)
		}
	}
	return sb.String()
}
