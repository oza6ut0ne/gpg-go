package gpgcli

import (
	"github.com/oza6ut0ne/gpg-go/internal/gnupghome"
	"github.com/oza6ut0ne/gpg-go/internal/gpgagent"
)

// dialAgent connects to gpg-agent for the resolved homedir, or returns
// nil if it isn't reachable — not an error condition, since every
// call site falls back to this tool's own private-keys-v1.d handling.
func dialAgent(o *Options) *gpgagent.Client {
	dir, err := gnupghome.Resolve(o.Homedir)
	if err != nil {
		return nil
	}
	client, err := gpgagent.NewClient(dir)
	if err != nil {
		return nil
	}
	return client
}

// agentPassphraseFunc builds a lazy passphrase callback for a
// gpgagent.Client: it is only invoked (and only then does it prompt or
// consult --passphrase/--passphrase-file) if gpg-agent actually asks,
// i.e. the key is locked and not already cached by the agent.
func agentPassphraseFunc(o *Options, label string) func() ([]byte, error) {
	return func() ([]byte, error) {
		return ResolvePassphrase(o, "Enter passphrase for "+label+": ")
	}
}
