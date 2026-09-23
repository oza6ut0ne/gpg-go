package gpgcli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/oza6ut0ne/gpg-go/internal/gnupghome"
)

// applyConfigFile loads gpg.conf (or the file named by --options, unless
// --no-options is given) and applies each recognized directive to o,
// before argv itself is parsed — so command-line arguments always take
// precedence, exactly as gpg's own config-file handling does.
//
// Directives this tool does not implement (real-world gpg.conf files
// commonly contain many, across gpg versions/features we don't cover)
// are silently skipped rather than treated as errors; only a malformed
// value for an option we DO implement is reported.
func applyConfigFile(o *Options, argv []string) error {
	homedir, optionsFile, noOptions := prescanForConfig(argv)
	if noOptions {
		return nil
	}

	path := optionsFile
	if path == "" {
		dir, err := gnupghome.Resolve(homedir)
		if err != nil {
			return err
		}
		path = filepath.Join(dir, "gpg.conf")
	}

	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("reading %s: %w", path, err)
	}

	long := longFlags()
	for lineNo, rawLine := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		tokens := tokenizeConfigLine(line)
		if len(tokens) == 0 {
			continue
		}
		name := tokens[0]
		val := ""
		if len(tokens) > 1 {
			val = tokens[1]
		}

		fl, ok := long[name]
		if !ok {
			// Unrecognized, or a no-op/ignored directive: skip.
			continue
		}
		if err := fl.apply(o, val); err != nil {
			return fmt.Errorf("%s:%d: %w", path, lineNo+1, err)
		}
	}
	return nil
}

// prescanForConfig looks for --homedir, --options and --no-options in
// argv without fully parsing it, since the config file's own location
// depends on them.
func prescanForConfig(argv []string) (homedir, optionsFile string, noOptions bool) {
	for i := 0; i < len(argv); i++ {
		a := argv[i]
		switch {
		case a == "--no-options":
			noOptions = true
		case a == "--homedir":
			if i+1 < len(argv) {
				homedir = argv[i+1]
				i++
			}
		case strings.HasPrefix(a, "--homedir="):
			homedir = strings.TrimPrefix(a, "--homedir=")
		case a == "--options":
			if i+1 < len(argv) {
				optionsFile = argv[i+1]
				i++
			}
		case strings.HasPrefix(a, "--options="):
			optionsFile = strings.TrimPrefix(a, "--options=")
		}
	}
	return
}

// tokenizeConfigLine splits a gpg.conf line into whitespace-separated
// tokens, treating "..." as a single token (so a value containing
// spaces can be quoted).
func tokenizeConfigLine(line string) []string {
	var tokens []string
	var cur strings.Builder
	inQuotes := false
	for _, r := range line {
		switch {
		case r == '"':
			inQuotes = !inQuotes
		case (r == ' ' || r == '\t') && !inQuotes:
			if cur.Len() > 0 {
				tokens = append(tokens, cur.String())
				cur.Reset()
			}
		default:
			cur.WriteRune(r)
		}
	}
	if cur.Len() > 0 {
		tokens = append(tokens, cur.String())
	}
	return tokens
}
