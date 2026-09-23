package opsutil

import (
	"github.com/ProtonMail/gopenpgp/v2/armor"
	"github.com/ProtonMail/gopenpgp/v2/constants"
)

// armorMessage armors data as a PGP MESSAGE block without the
// "Version:"/"Comment:" headers GopenPGP adds by default — real gpg's
// own armored output has neither, and this tool matches that.
func armorMessage(data []byte) (string, error) {
	return armor.ArmorWithTypeAndCustomHeaders(data, constants.PGPMessageHeader, "", "")
}

// armorSignature armors data as a detached PGP SIGNATURE block without
// GopenPGP's default "Version:"/"Comment:" headers.
func armorSignature(data []byte) (string, error) {
	return armor.ArmorWithTypeAndCustomHeaders(data, constants.PGPSignatureHeader, "", "")
}

// armorClearSigned builds a cleartext-signed ("-----BEGIN PGP SIGNED
// MESSAGE-----") block, matching GopenPGP's own
// ClearTextMessage.GetArmored byte for byte except that the embedded
// signature omits GopenPGP's default "Version:"/"Comment:" headers
// (which GetArmored has no way to suppress, since it always calls
// armor.ArmorWithType with the built-in defaults).
func armorClearSigned(text string, sig []byte) (string, error) {
	armSig, err := armorSignature(sig)
	if err != nil {
		return "", err
	}
	return "-----BEGIN PGP SIGNED MESSAGE-----\r\nHash: SHA512\r\n\r\n" + text + "\r\n" + armSig, nil
}
