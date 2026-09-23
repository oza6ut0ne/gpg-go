package gpgcli

import (
	"fmt"
	"io"
	"os"
)

// readInput reads from path, or from stdin if path is "" or "-".
func readInput(path string) ([]byte, error) {
	if path == "" || path == "-" {
		return io.ReadAll(os.Stdin)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	return data, nil
}

// outputPath computes the destination path for an operation given the
// explicit --output value (if any), the input path (possibly empty/"-" for
// stdin) and the suffix gpg would append (".gpg", ".asc", ".sig", ...).
// An empty return value means "write to stdout".
func outputPath(o *Options, inputPath, suffix string) string {
	if o.Output != "" {
		return o.Output
	}
	if inputPath == "" || inputPath == "-" {
		return ""
	}
	return inputPath + suffix
}

// writeOutput writes data to path (stdout if path == "") after checking for
// accidental overwrite, honoring --yes.
func writeOutput(o *Options, path string, data []byte, mode os.FileMode) error {
	if path == "" {
		_, err := os.Stdout.Write(data)
		return err
	}
	if !o.Yes {
		if _, err := os.Stat(path); err == nil {
			ok, err := confirmOverwrite(o, path)
			if err != nil {
				return err
			}
			if !ok {
				return fmt.Errorf("not overwriting %s", path)
			}
		}
	}
	if err := os.WriteFile(path, data, mode); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	if !o.Quiet {
		fmt.Fprintf(os.Stderr, "gpg: writing to '%s'\n", path)
	}
	return nil
}

func confirmOverwrite(o *Options, path string) (bool, error) {
	if o.Batch {
		return false, nil
	}
	answer, err := prompt(fmt.Sprintf("File '%s' exists. Overwrite? (y/N) ", path))
	if err != nil {
		return false, err
	}
	return answer == "y" || answer == "Y" || answer == "yes", nil
}
