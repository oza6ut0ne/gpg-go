package keystore

import (
	"bytes"
	"fmt"
	"io"
	"strings"

	openpgp "github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/gopenpgp/v2/crypto"
)

// ParseKeys reads one or more OpenPGP keys (public or secret, locked or
// not) from armored or binary data, auto-detecting the format. If strict
// parsing fails, it retries once after dropping any signature packets
// that are structurally out of place (see sanitizeKeyblock) — a
// real-world keyserver-key quirk that GnuPG tolerates but go-crypto does
// not — before giving up and returning the original error.
func ParseKeys(data []byte) ([]*crypto.Key, error) {
	keys, err := parseKeysStrict(data)
	if err == nil {
		return keys, nil
	}

	binary, derr := toBinary(data)
	if derr != nil {
		return nil, fmt.Errorf("parsing keys: %w", err)
	}
	sanitized, changed, serr := sanitizeKeyblock(binary)
	if serr != nil || !changed {
		return nil, fmt.Errorf("parsing keys: %w", err)
	}
	keys, err2 := parseKeysStrict(sanitized)
	if err2 != nil {
		return nil, fmt.Errorf("parsing keys: %w", err)
	}
	return keys, nil
}

func parseKeysStrict(data []byte) ([]*crypto.Key, error) {
	var entities openpgp.EntityList
	var err error
	if strings.HasPrefix(strings.TrimSpace(string(data)), "-----BEGIN PGP") {
		entities, err = openpgp.ReadArmoredKeyRing(bytes.NewReader(data))
	} else {
		entities, err = openpgp.ReadKeyRing(bytes.NewReader(data))
	}
	if err != nil {
		return nil, fmt.Errorf("parsing keys: %w", err)
	}

	keys := make([]*crypto.Key, 0, len(entities))
	for _, e := range entities {
		k, err := crypto.NewKeyFromEntity(e)
		if err != nil {
			return nil, err
		}
		keys = append(keys, k)
	}
	return keys, nil
}

// toBinary returns data's underlying binary OpenPGP packet stream,
// dearmoring it first if necessary.
func toBinary(data []byte) ([]byte, error) {
	if !strings.HasPrefix(strings.TrimSpace(string(data)), "-----BEGIN PGP") {
		return data, nil
	}
	block, err := armor.Decode(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	return io.ReadAll(block.Body)
}
