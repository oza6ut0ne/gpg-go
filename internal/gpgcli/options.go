// Package gpgcli implements the command-line interface: argument parsing
// compatible with gpg's flag names, and dispatch to the actual operations.
package gpgcli

// Options holds every flag recognized by the parser plus the leftover
// positional arguments (files, user IDs, etc., depending on the operation).
type Options struct {
	Operation string // see the opXxx constants below

	Armor   bool
	Output  string
	Homedir string

	// RecipientSpecs records every -r/--recipient and -R/--hidden-recipient
	// query in the exact order given (gpg.conf entries followed by
	// command-line ones), so that the same key given as both a visible
	// and a hidden recipient can be resolved by last-specified-wins
	// rather than being encrypted to twice.
	RecipientSpecs []RecipientSpec
	LocalUser      string

	Detach    bool
	ClearSign bool
	Sign      bool // -s combined with -e, or standalone

	Passphrase       string
	PassphraseFile   string
	PassphraseSet    bool
	PinentryLoopback bool

	Batch   bool
	Yes     bool
	Quiet   bool
	Verbose bool

	Fingerprint            bool // --fingerprint modifier / repeat-to-show-subkeys
	WithSubkeyFingerprints bool // --with-subkey-fingerprints (fingerprint on subkeys without needing --fingerprint on the primary)
	WithKeygrip            bool // --with-keygrip

	// key generation
	Algo   string
	Bits   int
	Expire string

	Args []string
}

// RecipientSpec is a single -r/--recipient or -R/--hidden-recipient
// query, tagged with whether it was given as hidden.
type RecipientSpec struct {
	Query  string
	Hidden bool
}

// Operation identifiers.
const (
	opNone         = ""
	opEncrypt      = "encrypt"
	opSign         = "sign"
	opDetachSign   = "detach-sign"
	opClearSign    = "clearsign"
	opSymmetric    = "symmetric"
	opDecrypt      = "decrypt"
	opVerify       = "verify"
	opListPublic   = "list-keys"
	opListSecret   = "list-secret-keys"
	opExport       = "export"
	opExportSecret = "export-secret-keys"
	opImport       = "import"
	opGenKey       = "gen-key"
	opQuickGenKey  = "quick-gen-key"
	opDeleteKey    = "delete-key"
	opDeleteSecret = "delete-secret-key"
	opDeleteBoth   = "delete-secret-and-public-key"
	opVersion      = "version"
	opHelp         = "help"
	opListPackets  = "list-packets"
)
