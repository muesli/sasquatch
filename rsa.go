package sasquatch

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"fmt"

	"golang.org/x/crypto/ssh"
)

const oaepLabel = "charm.sh/v1/ssh-rsa"

type RSARecipient struct {
	sshKey ssh.PublicKey
	pubKey *rsa.PublicKey
}

var _ Recipient = &RSARecipient{}

func (*RSARecipient) Type() string { return "ssh-rsa" }

func NewRSARecipient(pk ssh.PublicKey) (*RSARecipient, error) {
	if pk.Type() != "ssh-rsa" {
		return nil, errors.New("SSH public key is not an RSA key")
	}
	r := &RSARecipient{
		sshKey: pk,
	}

	if pk, ok := pk.(ssh.CryptoPublicKey); ok {
		if pk, ok := pk.CryptoPublicKey().(*rsa.PublicKey); ok {
			r.pubKey = pk
		} else {
			return nil, errors.New("unexpected public key type")
		}
	} else {
		return nil, errors.New("pk does not implement ssh.CryptoPublicKey")
	}
	return r, nil
}

func (r *RSARecipient) Wrap(fileKey []byte) (*Stanza, error) {
	l := &Stanza{
		Type: "ssh-rsa",
		Args: []string{sshFingerprint(r.sshKey)},
	}

	wrappedKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader,
		r.pubKey, fileKey, []byte(oaepLabel))
	if err != nil {
		return nil, err
	}
	l.Body = wrappedKey

	return l, nil
}

type RSAIdentity struct {
	k      *rsa.PrivateKey
	sshKey ssh.PublicKey
}

var _ Identity = &RSAIdentity{}

func (*RSAIdentity) Type() string { return "ssh-rsa" }

func NewRSAIdentity(key *rsa.PrivateKey) (*RSAIdentity, error) {
	s, err := ssh.NewSignerFromKey(key)
	if err != nil {
		return nil, err
	}
	i := &RSAIdentity{
		k: key, sshKey: s.PublicKey(),
	}
	return i, nil
}

func (i *RSAIdentity) Unwrap(block *Stanza) ([]byte, error) {
	if block.Type != "ssh-rsa" {
		return nil, ErrIncorrectIdentity
	}
	if len(block.Args) != 1 {
		return nil, errors.New("invalid ssh-rsa recipient block")
	}

	if block.Args[0] != sshFingerprint(i.sshKey) {
		return nil, ErrIncorrectIdentity
	}

	fileKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, i.k,
		block.Body, []byte(oaepLabel))
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt file key: %v", err)
	}
	return fileKey, nil
}
