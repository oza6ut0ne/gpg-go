package gpgcli

import (
	"os"

	"github.com/oza6ut0ne/gpg-go/internal/pgpdump"
)

func cmdListPackets(o *Options) error {
	var inputPath string
	if len(o.Args) > 0 {
		inputPath = o.Args[0]
	}
	data, err := readInput(inputPath)
	if err != nil {
		return err
	}
	return pgpdump.Dump(os.Stdout, data)
}
