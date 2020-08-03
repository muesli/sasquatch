package sasquatch

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"
)

// An Identity is a private key or other value that can decrypt an opaque file
// key from a recipient stanza.
//
// Unwrap must return ErrIncorrectIdentity for recipient blocks that don't match
// the identity, any other error might be considered fatal.
type Identity interface {
	Type() string
	Unwrap(block *Stanza) (fileKey []byte, err error)
}

// IdentityMatcher can be optionally implemented by an Identity that can
// communicate whether it can decrypt a recipient stanza without decrypting it.
//
// If an Identity implements IdentityMatcher, its Unwrap method will only be
// invoked on blocks for which Match returned nil. Match must return
// ErrIncorrectIdentity for recipient blocks that don't match the identity, any
// other error might be considered fatal.
type IdentityMatcher interface {
	Identity
	Match(block *Stanza) error
}

var ErrIncorrectIdentity = errors.New("incorrect identity for recipient block")

// FindIdentities returns all available identities.
func FindIdentities() []Identity {
	// from disk
	keys, err := FindSSHKeys()
	if err != nil {
		return nil
	}

	ids := []Identity{}
	for _, key := range keys {
		// fmt.Println("parsing", key)
		i, err := ParseIdentitiesFile(key)
		if err != nil {
			// fmt.Println(err)
			continue
		}
		ids = append(ids, i...)
	}

	// from agent
	signers, err := SSHAgentSigners()
	if err != nil {
		return ids
	}

	for _, signer := range signers {
		i, err := NewChallengeIdentity(signer)
		if err != nil {
			continue
		}

		ids = append(ids, i)
	}

	return ids
}

const privateKeySizeLimit = 1 << 24 // 16 MiB

// ParseIdentitiesFile retrieves all identities found in a private key.
func ParseIdentitiesFile(name string) ([]Identity, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %v", err)
	}
	defer f.Close()

	contents, err := ioutil.ReadAll(io.LimitReader(f, privateKeySizeLimit))
	if err != nil {
		return nil, fmt.Errorf("failed to read %q: %v", name, err)
	}
	if len(contents) == privateKeySizeLimit {
		return nil, fmt.Errorf("failed to read %q: file too long", name)
	}

	var ids []Identity
	scanner := bufio.NewScanner(bytes.NewReader(contents))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		if strings.HasPrefix(line, "-----BEGIN") {
			return parseSSHIdentity(name, contents)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read %q: %v", name, err)
	}

	if len(ids) == 0 {
		return nil, fmt.Errorf("no secret keys found in %q", name)
	}
	return ids, nil
}

func parseIdentity(pemBytes []byte) (Identity, error) {
	k, err := ssh.ParseRawPrivateKey(pemBytes)
	if err != nil {
		return nil, err
	}

	switch k := k.(type) {
	case *ed25519.PrivateKey:
		return NewEd25519Identity(*k)
	case *rsa.PrivateKey:
		return NewRSAIdentity(k)
	}

	return nil, fmt.Errorf("unsupported SSH identity type: %T", k)
}

func parseSSHIdentity(name string, pemBytes []byte) ([]Identity, error) {
	id, err := parseIdentity(pemBytes)
	if sshErr, ok := err.(*ssh.PassphraseMissingError); ok {
		pubKey := sshErr.PublicKey
		if pubKey == nil {
			pubKey, err = readPubFile(name)
			if err != nil {
				return nil, err
			}
		}
		passphrasePrompt := func() ([]byte, error) {
			fmt.Fprintf(os.Stderr, "Enter passphrase for %q: ", name)
			pass, err := readPassphrase()
			if err != nil {
				return nil, fmt.Errorf("could not read passphrase for %q: %v", name, err)
			}
			return pass, nil
		}
		i, err := NewEncryptedSSHIdentity(pubKey, pemBytes, passphrasePrompt)
		if err != nil {
			return nil, err
		}
		return []Identity{i}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("malformed SSH identity in %q: %v", name, err)
	}

	return []Identity{id}, nil
}

func readPubFile(name string) (ssh.PublicKey, error) {
	f, err := os.Open(name + ".pub")
	if err != nil {
		return nil, fmt.Errorf(`failed to obtain public key for %q SSH key: %v
    Ensure %q exists, or convert the private key %q to a modern format with "ssh-keygen -p -m RFC4716"`, name, err, name+".pub", name)
	}
	defer f.Close()
	contents, err := ioutil.ReadAll(f)
	if err != nil {
		return nil, fmt.Errorf("failed to read %q: %v", name+".pub", err)
	}
	pubKey, _, _, _, err := ssh.ParseAuthorizedKey(contents)
	if err != nil {
		return nil, fmt.Errorf("failed to parse %q: %v", name+".pub", err)
	}
	return pubKey, nil
}
