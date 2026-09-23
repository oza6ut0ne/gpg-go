package keystore

import (
	"fmt"
	"strings"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/ProtonMail/gopenpgp/v2/crypto"
	"github.com/oza6ut0ne/gpg-go/internal/opsutil"
)

// FormatFingerprint renders a fingerprint the way gpg does: uppercase hex,
// grouped in blocks of 4.
func FormatFingerprint(fpr string) string {
	fpr = strings.ToUpper(fpr)
	var sb strings.Builder
	for i, r := range fpr {
		if i > 0 && i%4 == 0 {
			sb.WriteByte(' ')
		}
		sb.WriteRune(r)
	}
	return sb.String()
}

// LongKeyID returns the 16 hex character key ID (last 8 bytes of the
// fingerprint), as gpg shows in --keyid-format long.
func LongKeyID(fpr string) string {
	fpr = strings.ToUpper(fpr)
	if len(fpr) < 16 {
		return fpr
	}
	return fpr[len(fpr)-16:]
}

func algoName(pk *packet.PublicKey) string {
	bits, _ := pk.BitLength()
	switch pk.PubKeyAlgo {
	case packet.PubKeyAlgoRSA, packet.PubKeyAlgoRSAEncryptOnly, packet.PubKeyAlgoRSASignOnly:
		return fmt.Sprintf("rsa%d", bits)
	case packet.PubKeyAlgoDSA:
		return fmt.Sprintf("dsa%d", bits)
	case packet.PubKeyAlgoElGamal:
		return fmt.Sprintf("elg%d", bits)
	case packet.PubKeyAlgoEdDSA, packet.PubKeyAlgoEd25519:
		return "ed25519"
	case packet.PubKeyAlgoEd448:
		return "ed448"
	case packet.PubKeyAlgoX25519:
		return "cv25519"
	case packet.PubKeyAlgoECDSA:
		curve, err := pk.Curve()
		if err == nil {
			return string(curve)
		}
		return "ecdsa"
	case packet.PubKeyAlgoECDH:
		curve, err := pk.Curve()
		if err == nil {
			if curve == "Curve25519" {
				return "cv25519"
			}
			return string(curve)
		}
		return "ecdh"
	default:
		return fmt.Sprintf("algo%d", pk.PubKeyAlgo)
	}
}

func usageFlags(sig *packet.Signature) string {
	if sig == nil || !sig.FlagsValid {
		return ""
	}
	var f string
	if sig.FlagCertify {
		f += "C"
	}
	if sig.FlagSign {
		f += "S"
	}
	if sig.FlagEncryptCommunications || sig.FlagEncryptStorage {
		f += "E"
	}
	if sig.FlagAuthenticate {
		f += "A"
	}
	return f
}

// ListOptions controls the extra detail PrintKeyList shows per key.
type ListOptions struct {
	// ShowSubkeyFingerprint prints each subkey's own fingerprint line
	// (gpg's --fingerprint given twice, or --with-subkey-fingerprints).
	ShowSubkeyFingerprint bool
	// WithKeygrip prints a "Keygrip = ..." line under the primary key
	// and under every subkey it can be computed for (gpg's
	// --with-keygrip).
	WithKeygrip bool
	// SecretStatus, if non-nil, is consulted for each primary/subkey
	// packet (only meaningful when secret is true) to print gpg's own
	// "#" (no secret key material available) / ">" (on a smartcard)
	// marker right after "sec"/"ssb". A 0 return means no marker.
	SecretStatus func(pk *packet.PublicKey) byte
}

// PrintKeyList prints a gpg-style listing of the given keys.
// If secret is true, uses "sec"/"ssb" labels as gpg does for -K.
func PrintKeyList(w *strings.Builder, keys []*crypto.Key, secret bool, opts ListOptions) {
	pubLabel, subLabel := "pub", "sub"
	if secret {
		pubLabel, subLabel = "sec", "ssb"
	}

	for _, k := range keys {
		e := k.GetEntity()
		primary := e.PrimaryKey
		ident := e.PrimaryIdentity()

		created := primary.CreationTime.Format("2006-01-02")
		usage := usageFlags(ident.SelfSignature)
		line := fmt.Sprintf("%s  %s %s", keyLabel(pubLabel, secret, opts, primary), algoName(primary), created)
		if usage != "" {
			line += " [" + usage + "]"
		}
		if ident.SelfSignature != nil && ident.SelfSignature.KeyLifetimeSecs != nil && *ident.SelfSignature.KeyLifetimeSecs > 0 {
			exp := primary.CreationTime.Add(time.Duration(*ident.SelfSignature.KeyLifetimeSecs) * time.Second)
			line += fmt.Sprintf(" [expires: %s]", exp.Format("2006-01-02"))
		}
		fmt.Fprintln(w, line)
		fmt.Fprintf(w, "      %s\n", FormatFingerprint(k.GetFingerprint()))
		if opts.WithKeygrip {
			printKeygrip(w, primary)
		}

		for _, id := range e.Identities {
			fmt.Fprintf(w, "uid           %s\n", id.Name)
		}

		for _, sub := range e.Subkeys {
			subCreated := sub.PublicKey.CreationTime.Format("2006-01-02")
			subUsage := usageFlags(sub.Sig)
			subLine := fmt.Sprintf("%s  %s %s", keyLabel(subLabel, secret, opts, sub.PublicKey), algoName(sub.PublicKey), subCreated)
			if subUsage != "" {
				subLine += " [" + subUsage + "]"
			}
			fmt.Fprintln(w, subLine)
			if opts.ShowSubkeyFingerprint {
				fmt.Fprintf(w, "      %s\n", FormatFingerprint(fmt.Sprintf("%x", sub.PublicKey.Fingerprint)))
			}
			if opts.WithKeygrip {
				printKeygrip(w, sub.PublicKey)
			}
		}
		fmt.Fprintln(w)
	}
}

// keyLabel returns label ("sec"/"ssb"/"pub"/"sub") with gpg's own status
// marker ('#' for no available secret material, '>' for a smartcard)
// appended when applicable, or a plain trailing space when there's
// none — so the column that follows always starts at the same offset
// whether or not a marker is shown.
func keyLabel(label string, secret bool, opts ListOptions, pk *packet.PublicKey) string {
	marker := byte(' ')
	if secret && opts.SecretStatus != nil {
		if m := opts.SecretStatus(pk); m != 0 {
			marker = m
		}
	}
	return label + string(marker)
}

func printKeygrip(w *strings.Builder, pk *packet.PublicKey) {
	grip, ok := opsutil.KeygripForPublicKey(pk)
	if !ok {
		return
	}
	fmt.Fprintf(w, "      Keygrip = %s\n", grip)
}
