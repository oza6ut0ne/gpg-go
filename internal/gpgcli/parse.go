package gpgcli

import (
	"fmt"
	"strconv"
	"strings"
)

// longFlag describes a single --long-option.
type longFlag struct {
	hasArg bool
	apply  func(o *Options, val string) error
}

func setOp(op string) func(o *Options, val string) error {
	return func(o *Options, val string) error {
		o.Operation = op
		return nil
	}
}

// ignoredWithArg / ignoredNoArg cover common gpg options this tool does not
// implement but should not choke on when present in real-world invocations.
var ignoredNoArg = map[string]bool{
	"no-tty": true, "expert": true, "no-options": true,
	"no-greeting": true, "no-secmem-warning": true, "textmode": true,
	"no-armor": true, "openpgp": true, "with-colons": false,
}

var ignoredWithArg = map[string]bool{
	"trust-model": true, "keyid-format": true, "charset": true,
	"display-charset": true, "status-fd": true, "command-fd": true,
	"default-new-key-algo": true, "cipher-algo": true, "digest-algo": true,
	"compress-algo": true, "s2k-mode": true, "s2k-cipher-algo": true,
	"s2k-digest-algo": true, "comment": true, "options": true,
}

func longFlags() map[string]longFlag {
	m := map[string]longFlag{
		"homedir":          {true, func(o *Options, v string) error { o.Homedir = v; return nil }},
		"armor":            {false, func(o *Options, v string) error { o.Armor = true; return nil }},
		"output":           {true, func(o *Options, v string) error { o.Output = v; return nil }},
		"recipient":        {true, func(o *Options, v string) error { o.RecipientSpecs = append(o.RecipientSpecs, RecipientSpec{Query: v}); return nil }},
		"hidden-recipient": {true, func(o *Options, v string) error { o.RecipientSpecs = append(o.RecipientSpecs, RecipientSpec{Query: v, Hidden: true}); return nil }},
		"local-user":       {true, func(o *Options, v string) error { o.LocalUser = v; return nil }},
		"default-key":      {true, func(o *Options, v string) error { o.LocalUser = v; return nil }},

		"encrypt": {false, setOp(opEncrypt)},
		"sign": {false, func(o *Options, v string) error {
			o.Sign = true
			if o.Operation == opNone {
				o.Operation = opSign
			}
			return nil
		}},
		"detach-sign": {false, func(o *Options, v string) error { o.Detach = true; o.Operation = opDetachSign; return nil }},
		"clearsign":   {false, setOp(opClearSign)},
		"clear-sign":  {false, setOp(opClearSign)},
		"symmetric":   {false, setOp(opSymmetric)},
		"decrypt":     {false, setOp(opDecrypt)},
		"verify":      {false, setOp(opVerify)},

		"list-keys":        {false, setOp(opListPublic)},
		"list-public-keys": {false, setOp(opListPublic)},
		"list-secret-keys": {false, setOp(opListSecret)},
		"fingerprint": {false, func(o *Options, v string) error {
			o.Fingerprint = true
			if o.Operation == opNone {
				o.Operation = opListPublic
			}
			return nil
		}},
		"with-subkey-fingerprints": {false, func(o *Options, v string) error {
			o.WithSubkeyFingerprints = true
			if o.Operation == opNone {
				o.Operation = opListPublic
			}
			return nil
		}},
		"with-fingerprint": {false, func(o *Options, v string) error {
			o.Fingerprint = true
			if o.Operation == opNone {
				o.Operation = opListPublic
			}
			return nil
		}},
		"with-keygrip": {false, func(o *Options, v string) error {
			o.WithKeygrip = true
			if o.Operation == opNone {
				o.Operation = opListPublic
			}
			return nil
		}},

		"export":             {false, setOp(opExport)},
		"export-secret-keys": {false, setOp(opExportSecret)},
		"import":             {false, setOp(opImport)},

		"gen-key":            {false, setOp(opGenKey)},
		"full-generate-key":  {false, setOp(opGenKey)},
		"quick-gen-key":      {false, setOp(opQuickGenKey)},
		"quick-generate-key": {false, setOp(opQuickGenKey)},

		"delete-key":                   {false, setOp(opDeleteKey)},
		"delete-secret-key":            {false, setOp(opDeleteSecret)},
		"delete-secret-and-public-key": {false, setOp(opDeleteBoth)},

		"passphrase":      {true, func(o *Options, v string) error { o.Passphrase = v; o.PassphraseSet = true; return nil }},
		"passphrase-file": {true, func(o *Options, v string) error { o.PassphraseFile = v; return nil }},
		"pinentry-mode":   {true, func(o *Options, v string) error { o.PinentryLoopback = v == "loopback"; return nil }},

		"batch":   {false, func(o *Options, v string) error { o.Batch = true; return nil }},
		"yes":     {false, func(o *Options, v string) error { o.Yes = true; return nil }},
		"quiet":   {false, func(o *Options, v string) error { o.Quiet = true; return nil }},
		"verbose": {false, func(o *Options, v string) error { o.Verbose = true; return nil }},

		"version":      {false, setOp(opVersion)},
		"help":         {false, setOp(opHelp)},
		"list-packets": {false, setOp(opListPackets)},
	}
	return m
}

// shortFlags maps a short letter to a no-arg apply func (boolean flags only,
// so they can be clustered as in "-sea").
func shortBoolFlags() map[byte]func(o *Options) {
	return map[byte]func(o *Options){
		'e': func(o *Options) { o.Operation = opEncrypt },
		's': func(o *Options) {
			o.Sign = true
			if o.Operation == opNone {
				o.Operation = opSign
			}
		},
		'b': func(o *Options) { o.Detach = true; o.Operation = opDetachSign },
		'c': func(o *Options) { o.Operation = opSymmetric },
		'd': func(o *Options) { o.Operation = opDecrypt },
		'a': func(o *Options) { o.Armor = true },
		'k': func(o *Options) { o.Operation = opListPublic },
		'v': func(o *Options) { o.Verbose = true },
		'q': func(o *Options) { o.Quiet = true },
		'h': func(o *Options) { o.Operation = opHelp },
	}
}

// shortArgFlags maps a short letter that always takes a following argument.
func shortArgFlags() map[byte]func(o *Options, v string) {
	return map[byte]func(o *Options, v string){
		'o': func(o *Options, v string) { o.Output = v },
		'r': func(o *Options, v string) { o.RecipientSpecs = append(o.RecipientSpecs, RecipientSpec{Query: v}) },
		'R': func(o *Options, v string) { o.RecipientSpecs = append(o.RecipientSpecs, RecipientSpec{Query: v, Hidden: true}) },
		'u': func(o *Options, v string) { o.LocalUser = v },
	}
}

// Parse parses argv (os.Args[1:]) into an Options struct, first applying
// any directives found in gpg.conf (see config.go), which command-line
// arguments then override.
func Parse(argv []string) (*Options, error) {
	o := &Options{}
	if err := applyConfigFile(o, argv); err != nil {
		return nil, err
	}
	if err := parseInto(o, argv); err != nil {
		return nil, err
	}
	return o, nil
}

func parseInto(o *Options, argv []string) error {
	long := longFlags()
	shortBool := shortBoolFlags()
	shortArg := shortArgFlags()

	i := 0
	for i < len(argv) {
		arg := argv[i]
		switch {
		case arg == "--":
			o.Args = append(o.Args, argv[i+1:]...)
			i = len(argv)

		case arg == "-K":
			o.Operation = opListSecret
			i++

		case strings.HasPrefix(arg, "--"):
			name := arg[2:]
			val := ""
			hasInlineVal := false
			if eq := strings.IndexByte(name, '='); eq != -1 {
				val = name[eq+1:]
				name = name[:eq]
				hasInlineVal = true
			}

			if fl, ok := long[name]; ok {
				if fl.hasArg {
					if !hasInlineVal {
						i++
						if i >= len(argv) {
							return fmt.Errorf("option --%s requires an argument", name)
						}
						val = argv[i]
					}
				}
				if err := fl.apply(o, val); err != nil {
					return err
				}
				i++
				continue
			}
			if ignoredNoArg[name] {
				i++
				continue
			}
			if ignoredWithArg[name] {
				if !hasInlineVal {
					i++
				}
				i++
				continue
			}
			return fmt.Errorf("unknown option: --%s", name)

		case len(arg) >= 2 && arg[0] == '-' && arg != "-":
			chars := arg[1:]
			for j := 0; j < len(chars); j++ {
				c := chars[j]
				if fn, ok := shortArg[c]; ok {
					var val string
					if j+1 < len(chars) {
						val = chars[j+1:]
					} else {
						i++
						if i >= len(argv) {
							return fmt.Errorf("option -%c requires an argument", c)
						}
						val = argv[i]
					}
					fn(o, val)
					j = len(chars)
					continue
				}
				if fn, ok := shortBool[c]; ok {
					fn(o)
					continue
				}
				return fmt.Errorf("unknown option: -%c", c)
			}
			i++

		default:
			o.Args = append(o.Args, arg)
			i++
		}
	}

	return nil
}

// AtoiOrZero parses a numeric string, returning 0 on failure.
func AtoiOrZero(s string) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0
	}
	return n
}
