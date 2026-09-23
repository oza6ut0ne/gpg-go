# gpg-go

A `gpg`-compatible command-line tool. Cryptographic operations are backed by
[ProtonMail/gopenpgp](https://github.com/ProtonMail/gopenpgp) (and, underneath
it, `ProtonMail/go-crypto`). Option names and behavior match real GnuPG as
closely as possible, but only the subset of functionality used in everyday
work is implemented (see "Implementation coverage" below for details).

## Install

```sh
go install github.com/oza6ut0ne/gpg-go@latest
```

This installs the `gpg-go` binary into `$(go env GOPATH)/bin` (or
`$(go env GOBIN)` if set) — make sure that directory is on your `PATH`.

### Build from source

```sh
go build -o gpg-go .
```

## Home directory

Resolution order and defaults exactly match real gpg (**by default it reads
and writes the real `~/.gnupg` directly**):

- `--homedir DIR`
- the `GNUPGHOME` environment variable
- otherwise `~/.gnupg`

The on-disk format is also the same binary layout as real GnuPG 2.1+:

- `pubring.kbx` — GnuPG's Keybox format (implemented to match the
  `kbx/keybox-blob.c` spec: a header blob + OpenPGP blobs + a SHA-1 checksum)
- `private-keys-v1.d/<KEYGRIP>.key` — secret-key files in the same format
  gpg-agent uses. Passphrase protection uses the same
  `openpgp-s2k3-ocb-aes` gpg-agent does (an AES-128 key derived via RFC4880
  Iterated+Salted S2K/SHA-1, with OCB authenticated encryption), and file
  names are libgcrypt-compatible keygrips (SHA-1 of `n` for RSA; SHA-1 over
  the curve parameters for EdDSA/ECDH-Curve25519)

It also reads `$homedir/gpg.conf` the same way real gpg does (command-line
flags override gpg.conf's contents, and options that can be repeated, like
`-r`/`--recipient`, are accumulated from both). `--options FILE` points at a
different file, and `--no-options` disables reading one at all. Directives
this tool doesn't implement are silently ignored, so pointing it at a real
GnuPG `gpg.conf` as-is won't break anything.

Because of all this, it can read and write the very same keys as a real
`gpg`/`gpg-agent` (actual interop with real GnuPG 2.4.x has been verified:
generation, listing, export/import, encryption, decryption, signing, and
verification have all been checked against the real `gpg` command in both
directions). Supported algorithms are Ed25519 + Cv25519 (the default) and
RSA. Keys made with other algorithms (e.g. NIST curves) can be read as public
keys, but attaching their secret material is not supported.

### gpg-agent integration (smartcard support)

`-b/--detach-sign`, `-s`, `--clearsign`, `-se` (sign-and-encrypt), and
`-d/--decrypt` (for Curve25519 keys) all check, before decrypting
`private-keys-v1.d` themselves, whether a running **real gpg-agent**
(talked to directly over the Assuan protocol) already holds the key, and use
it for signing/decryption if so. Signing operations correctly search subkeys
carrying the signing flag as candidates too (the common key layout where a
dedicated signing subkey is used instead of the primary key — and almost
always the case for a smartcard's key). This means:

- No re-entry needed if gpg-agent already has the passphrase (or, for a
  smartcard, the PIN) cached
- **Secret keys stored on an OpenPGP smartcard/token (e.g. a YubiKey)** —
  whose raw key material can never be read out — can still be used for
  signing and decryption. All of `-b`/`-s`/`--clearsign`/`-se`/`-d` have been
  verified against a real YubiKey (Ed25519 + Cv25519)

If gpg-agent can't be found, doesn't hold the target key, or the algorithm
isn't supported (e.g. RSA decryption), this tool automatically falls back to
its own direct `private-keys-v1.d` handling (a smartcard's key has no raw
material in `private-keys-v1.d` at all, so it can't fall back to local
handling — only gpg-agent-based operations are possible for it). EdDSA
signing has no extension point in `go-crypto` for plugging in an external
signer, so this is implemented by first letting a throwaway local key
(unrelated to the actual key in use) do the framing (building subpackets and
the digest), then swapping in the real signature obtained from gpg-agent.
For `-se`, the one-pass-signature/literal/signature sequence built this way
is written directly into go-crypto's own
`SerializeSymmetricallyEncrypted`/`SerializeCompressed`, reproducing
go-crypto's own close ordering for the compression/encryption part exactly
(the same pattern `openpgp.Sign` uses internally via `noOpCloser` to defer
closing). Signing and decrypting with keys actually held by a real gpg-agent
(both software keys and a real YubiKey) has been verified, including that the
result can be verified/decrypted by real `gpg`.

> **Note:** as described above, by default this rewrites the real
> `~/.gnupg`. If you want to try it in a separate directory, specify one
> explicitly with `--homedir` or `GNUPGHOME`. If you're at all concerned,
> back up `~/.gnupg` first.

## Usage examples

```sh
# Key generation (non-interactive, for scripts)
gpg-go --batch --passphrase '' --quick-gen-key "Alice <alice@example.com>" default

# Key generation (interactive)
gpg-go --gen-key

# Listing
gpg-go --list-keys
gpg-go --list-secret-keys

# Export / import
gpg-go --export -a -o alice_pub.asc alice@example.com
gpg-go --import alice_pub.asc

# Encrypt / decrypt
gpg-go -e -a -r alice@example.com -o msg.asc msg.txt
gpg-go -d msg.asc

# Sign and encrypt
gpg-go -se -a -r alice@example.com -u alice -o msg.asc msg.txt

# Detached signature / verify
gpg-go -b -a msg.txt
gpg-go --verify msg.txt.asc msg.txt

# Clearsign / verify
gpg-go --clearsign -o msg.asc msg.txt
gpg-go --verify msg.asc

# Passphrase-based symmetric encryption
gpg-go -c -a -o msg.asc msg.txt
gpg-go -d msg.asc

# Delete a key
gpg-go --delete-key alice@example.com
```

In `--batch` mode, `--passphrase`/`--passphrase-file` is required for
passphrase input (omitting it is an error).

## Implementation coverage

### Key management
`--gen-key` / `--full-generate-key` (interactive), `--quick-gen-key`
(non-interactive; algorithms are `default`/`ed25519` (Ed25519+Cv25519, the
default) and `rsa2048`/`rsa3072`/`rsa4096`, with EXPIRE argument support),
`-k/--list-keys`, `-K/--list-secret-keys` (matches real gpg's own
"sec#"/"ssb#" — no private-keys-v1.d entry at all, e.g. a secret key
removed from the machine — and "sec>"/"ssb>" — a smartcard stub —
status markers), `--fingerprint`,
`--with-subkey-fingerprints`, `--with-keygrip`, `--export`,
`--export-secret-keys`, `--import`, `--delete-key`,
`--delete-secret-key`, `--delete-secret-and-public-key`

### Encryption and signing
`-e/--encrypt` (`-r` may be repeated; combine with `-s` for sign-and-encrypt),
`-s/--sign` (a signed, unencrypted message), `-b/--detach-sign`,
`--clearsign`, `-c/--symmetric`, `-d/--decrypt` (auto-detects public-key vs.
passphrase scheme, and verifies an embedded signature if present; also
accepts a clearsigned message — verifying and still printing the text, even
with a BAD signature, exactly like real gpg — or a lone detached signature
file, whose companion data file is inferred by stripping a `.sig`/`.asc`/
`.gpg` suffix, the same way `--verify` does),
`--verify` (handles detached, clearsigned, and embedded signatures alike)

### Common options
`-a/--armor`, `-o/--output`, `-r/--recipient`,
`-R/--hidden-recipient` (hides the recipient's key ID; encrypts with the
wildcard key ID, so decryption brute-forces the secret keys on hand — this
also works for gpg-agent-based (e.g. smartcard) keys, by brute-forcing the
wildcard PKESK. If the same key is named by both `-r` and `-R` (including
ones coming from gpg.conf), whichever was specified last wins, so it's never
encrypted to twice), `-u/--local-user`
(`--default-key` is a synonym), `--homedir`, `--passphrase`,
`--passphrase-file`, `--pinentry-mode loopback`, `--batch`, `--yes`,
`-q/--quiet`, `-v/--verbose`, `--version`, `-h/--help`, `--list-packets`
(a low-level packet-structure dump — not byte-for-byte identical to real
gpg's format, but offsets, tags, lengths, and the main fields match)

Some options this tool doesn't implement, such as `--trust-model`,
`--keyid-format`, and `--charset`, are parsed but ignored, so scripts that
pass them don't break.

## Not implemented

- Reading/writing the trust database (trustdb.gpg), key signing (cross-
  signing via `--sign-key`)
- Attaching secret key material for algorithms other than RSA and
  Ed25519/Cv25519 (e.g. NIST curves, DSA/Elgamal) — such keys can still be
  read, listed, and used for encryption/verification as public keys
- The `--gen-key` batch parameter file format (the `Key-Type:` etc. DSL)
- gpg-agent-based RSA decryption (RSA signing is supported; decryption falls
  back to direct `private-keys-v1.d` handling. Decryption is not supported
  for an RSA-only smartcard)
- Streaming (the entire input is currently read into memory)

## Dependencies

- `github.com/ProtonMail/gopenpgp/v2`
- `github.com/ProtonMail/go-crypto`
- `golang.org/x/term` (for hidden passphrase input)
