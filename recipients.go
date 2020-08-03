package sasquatch

import (
	"fmt"
	"io/ioutil"

	"golang.org/x/crypto/ssh"
)

// A Recipient is a public key or other value that can encrypt an opaque file
// key to a recipient stanza.
type Recipient interface {
	Type() string
	Wrap(fileKey []byte) (*Stanza, error)
}

// FindRecipients returns all available recipients.
func FindRecipients() []Recipient {
	// from disk
	keys, err := FindSSHKeys()
	if err != nil {
		return nil
	}

	ids := []Recipient{}
	for _, key := range keys {
		key += ".pub"
		// fmt.Println("parsing", key)
		c, err := ioutil.ReadFile(key)
		if err != nil {
			fmt.Println(err)
			continue
		}

		r, err := ParseRecipient(string(c))
		if err != nil {
			// fmt.Println(err)
			continue
		}
		ids = append(ids, r)
	}

	// from agent
	signers, err := SSHAgentSigners()
	if err != nil {
		return ids
	}

	for _, signer := range signers {
		i, err := NewChallengeRecipient(signer)
		if err != nil {
			continue
		}

		ids = append(ids, i)
	}

	return ids
}

// ParseRecipient creates a Recipient from an SSH public key.
func ParseRecipient(s string) (Recipient, error) {
	pubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(s))
	if err != nil {
		return nil, fmt.Errorf("malformed SSH recipient: %q: %v", s, err)
	}

	var r Recipient
	switch t := pubKey.Type(); t {
	case "ssh-rsa":
		r, err = NewRSARecipient(pubKey)
	case "ssh-ed25519":
		r, err = NewEd25519Recipient(pubKey)
	default:
		return nil, fmt.Errorf("unknown SSH recipient type: %q", t)
	}
	if err != nil {
		return nil, fmt.Errorf("malformed SSH recipient: %q: %v", s, err)
	}

	return r, nil
}
