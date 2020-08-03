package sasquatch

import (
	"crypto/ed25519"
	"crypto/rsa"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/mitchellh/go-homedir"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// EncryptedSSHIdentity is an IdentityMatcher implementation based on a
// passphrase encrypted SSH private key.
//
// It provides public key based matching and deferred decryption so the
// passphrase is only requested if necessary. If the application knows it will
// unconditionally have to decrypt the private key, it would be simpler to use
// ssh.ParseRawPrivateKeyWithPassphrase directly and pass the result to
// NewEd25519Identity or NewRSAIdentity.
type EncryptedSSHIdentity struct {
	pubKey     ssh.PublicKey
	pemBytes   []byte
	passphrase func() ([]byte, error)

	decrypted Identity
}

// NewEncryptedSSHIdentity returns a new EncryptedSSHIdentity.
//
// pubKey must be the public key associated with the encrypted private key, and
// it must have type "ssh-ed25519" or "ssh-rsa". For OpenSSH encrypted files it
// can be extracted from an ssh.PassphraseMissingError, otherwise in can often
// be found in ".pub" files.
//
// pemBytes must be a valid input to ssh.ParseRawPrivateKeyWithPassphrase.
// passphrase is a callback that will be invoked by Unwrap when the passphrase
// is necessary.
func NewEncryptedSSHIdentity(pubKey ssh.PublicKey, pemBytes []byte, passphrase func() ([]byte, error)) (*EncryptedSSHIdentity, error) {
	switch t := pubKey.Type(); t {
	case "ssh-ed25519", "ssh-rsa":
	default:
		return nil, fmt.Errorf("unsupported SSH key type: %v", t)
	}
	return &EncryptedSSHIdentity{
		pubKey:     pubKey,
		pemBytes:   pemBytes,
		passphrase: passphrase,
	}, nil
}

// Type returns the type of the underlying private key, "ssh-ed25519" or "ssh-rsa".
func (i *EncryptedSSHIdentity) Type() string {
	return i.pubKey.Type()
}

// Unwrap implements Identity. If the private key is still encrypted, it
// will request the passphrase. The decrypted private key will be cached after
// the first successful invocation.
func (i *EncryptedSSHIdentity) Unwrap(block *Stanza) (fileKey []byte, err error) {
	if i.decrypted != nil {
		return i.decrypted.Unwrap(block)
	}

	passphrase, err := i.passphrase()
	if err != nil {
		return nil, fmt.Errorf("failed to obtain passphrase: %v", err)
	}
	k, err := ssh.ParseRawPrivateKeyWithPassphrase(i.pemBytes, passphrase)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt SSH key file: %v", err)
	}

	switch k := k.(type) {
	case *ed25519.PrivateKey:
		i.decrypted, err = NewEd25519Identity(*k)
	case *rsa.PrivateKey:
		i.decrypted, err = NewRSAIdentity(k)
	default:
		return nil, fmt.Errorf("unexpected SSH key type: %T", k)
	}
	if err != nil {
		return nil, fmt.Errorf("invalid SSH key: %v", err)
	}
	if i.decrypted.Type() != i.pubKey.Type() {
		return nil, fmt.Errorf("mismatched SSH key type: got %q, expected %q", i.decrypted.Type(), i.pubKey.Type())
	}

	return i.decrypted.Unwrap(block)
}

// Match implements IdentityMatcher without decrypting the private key, to
// ensure the passphrase is only obtained if necessary.
func (i *EncryptedSSHIdentity) Match(block *Stanza) error {
	if block.Type != i.Type() {
		return ErrIncorrectIdentity
	}
	if len(block.Args) < 1 {
		return fmt.Errorf("invalid %v recipient block", i.Type())
	}

	if block.Args[0] != sshFingerprint(i.pubKey) {
		return ErrIncorrectIdentity
	}
	return nil
}

// FindSSHKeys looks in a user's ~/.ssh dir for possible SSH keys. If no keys
// are found we return an empty slice.
func FindSSHKeys() ([]string, error) {
	path, err := homedir.Expand("~/.ssh")
	if err != nil {
		return nil, err
	}

	m, err := filepath.Glob(filepath.Join(path, "id_*"))
	if err != nil {
		return nil, err
	}

	var found []string
	for _, f := range m {
		switch filepath.Base(f) {
		case "id_dsa":
			fallthrough
		case "id_rsa":
			fallthrough
		case "id_ecdsa":
			fallthrough
		case "id_ed25519":
			found = append(found, f)
		}
	}

	return found, nil
}

// SSHAgentSigners connect to ssh-agent and returns all available signers.
func SSHAgentSigners() ([]ssh.Signer, error) {
	conn, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK"))
	if err != nil {
		return nil, fmt.Errorf("Could not connect to the SSH Agent socket. %s", err)
	}

	sshAgent := agent.NewClient(conn)

	signers, err := sshAgent.Signers()
	if err != nil {
		return nil, fmt.Errorf("Could not retrieve signers from the SSH Agent. %v", err)
	}

	if len(signers) == 0 {
		return nil, fmt.Errorf("There are no SSH keys added to the SSH Agent. Check that you have added keys to the SSH Agent and that SSH Agent Forwarding is enabled if you are using this remotely.")
	}

	return signers, nil
}
