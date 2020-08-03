package sasquatch

import (
	"crypto/rand"
	"errors"
	"fmt"
	"strconv"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/crypto/ssh"
)

const challengeLabel = "charm.sh/v1/challenge"

type ChallengeRecipient struct {
	signer     ssh.Signer
	workFactor int
}

var _ Recipient = &ChallengeRecipient{}

func (*ChallengeRecipient) Type() string { return "challenge" }

// NewChallengeRecipient returns a new ChallengeRecipient with the provided
// signer.
func NewChallengeRecipient(signer ssh.Signer) (*ChallengeRecipient, error) {
	r := &ChallengeRecipient{
		signer: signer,
		// TODO: automatically scale this to 0.5s (with a min) in the CLI.
		workFactor: 8, // 0.5s on a modern machine
	}
	return r, nil
}

func (r *ChallengeRecipient) Wrap(fileKey []byte) (*Stanza, error) {
	challenge := make([]byte, 64)
	if _, err := rand.Read(challenge[:]); err != nil {
		return nil, err
	}

	sig, err := r.signer.Sign(rand.Reader, challenge)
	if err != nil {
		return nil, err
	}

	salt := make([]byte, 16)
	if _, err := rand.Read(salt[:]); err != nil {
		return nil, err
	}

	logN := r.workFactor
	l := &Stanza{
		Type: "challenge",
		Args: []string{
			sshFingerprint(r.signer.PublicKey()),
			EncodeToString(salt),
			strconv.Itoa(logN),
			EncodeToString(challenge),
		},
	}

	salt = append([]byte(challengeLabel), salt...)
	k, err := scrypt.Key(sig.Blob, salt, 1<<logN, 8, 1, chacha20poly1305.KeySize)
	if err != nil {
		return nil, fmt.Errorf("failed to generate scrypt hash: %v", err)
	}

	wrappedKey, err := aeadEncrypt(k, fileKey)
	if err != nil {
		return nil, err
	}
	l.Body = wrappedKey

	return l, nil
}

// ChallengeIdentity is a challenge-based identity, supporting SSH agents.
type ChallengeIdentity struct {
	signer ssh.Signer
}

var _ Identity = &ChallengeIdentity{}

func (*ChallengeIdentity) Type() string { return "challenge" }

// NewChallengeIdentity returns a new ChallengeIdentity with the provided
// challenge signer.
func NewChallengeIdentity(signer ssh.Signer) (*ChallengeIdentity, error) {
	i := &ChallengeIdentity{
		signer: signer,
	}
	return i, nil
}

func (i *ChallengeIdentity) Unwrap(block *Stanza) ([]byte, error) {
	if block.Type != "challenge" {
		return nil, ErrIncorrectIdentity
	}
	if len(block.Args) != 4 {
		return nil, errors.New("invalid challenge recipient block")
	}

	challenge, err := DecodeString(block.Args[3])
	if err != nil {
		return nil, fmt.Errorf("failed to parse challenge challenge: %v", err)
	}

	sig, err := i.signer.Sign(rand.Reader, challenge)
	if err != nil {
		return nil, err
	}

	salt, err := DecodeString(block.Args[1])
	if err != nil {
		return nil, fmt.Errorf("failed to parse scrypt salt: %v", err)
	}
	if len(salt) != 16 {
		return nil, errors.New("invalid scrypt recipient block")
	}
	logN, err := strconv.Atoi(block.Args[2])
	if err != nil {
		return nil, fmt.Errorf("failed to parse scrypt work factor: %v", err)
	}

	salt = append([]byte(challengeLabel), salt...)
	k, err := scrypt.Key(sig.Blob, salt, 1<<logN, 8, 1, chacha20poly1305.KeySize)
	if err != nil {
		return nil, fmt.Errorf("failed to generate scrypt hash: %v", err)
	}

	fileKey, err := aeadDecrypt(k, block.Body)
	if err != nil {
		return nil, ErrIncorrectIdentity
	}
	return fileKey, nil
}

// Match implements IdentityMatcher without decrypting the payload, to
// ensure the agent is only contacted if necessary.
func (i *ChallengeIdentity) Match(block *Stanza) error {
	if block.Type != i.Type() {
		return ErrIncorrectIdentity
	}
	if len(block.Args) != 4 {
		return fmt.Errorf("invalid %v recipient block", i.Type())
	}

	if block.Args[0] != sshFingerprint(i.signer.PublicKey()) {
		return ErrIncorrectIdentity
	}
	return nil
}
