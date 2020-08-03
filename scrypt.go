package sasquatch

import (
	"crypto/rand"
	"errors"
	"fmt"
	"strconv"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/scrypt"
)

const scryptLabel = "charm.sh/v1/scrypt"

// ScryptRecipient is a password-based recipient.
//
// If a ScryptRecipient is used, it must be the only recipient for the file: it
// can't be mixed with other recipient types and can't be used multiple times
// for the same file.
type ScryptRecipient struct {
	password   []byte
	workFactor int
}

var _ Recipient = &ScryptRecipient{}

func (*ScryptRecipient) Type() string { return "scrypt" }

// NewScryptRecipient returns a new ScryptRecipient with the provided password.
func NewScryptRecipient(password string) (*ScryptRecipient, error) {
	if len(password) == 0 {
		return nil, errors.New("passphrase can't be empty")
	}
	r := &ScryptRecipient{
		password: []byte(password),
		// TODO: automatically scale this to 0.5s (with a min) in the CLI.
		workFactor: 8, // 0.5s on a modern machine
	}
	return r, nil
}

func (r *ScryptRecipient) Wrap(fileKey []byte) (*Stanza, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt[:]); err != nil {
		return nil, err
	}

	logN := r.workFactor
	l := &Stanza{
		Type: "scrypt",
		Args: []string{EncodeToString(salt), strconv.Itoa(logN)},
	}

	salt = append([]byte(scryptLabel), salt...)
	k, err := scrypt.Key(r.password, salt, 1<<logN, 8, 1, chacha20poly1305.KeySize)
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

// ScryptIdentity is a password-based identity.
type ScryptIdentity struct {
	password []byte
}

var _ Identity = &ScryptIdentity{}

func (*ScryptIdentity) Type() string { return "scrypt" }

// NewScryptIdentity returns a new ScryptIdentity with the provided password.
func NewScryptIdentity(password string) (*ScryptIdentity, error) {
	if len(password) == 0 {
		return nil, errors.New("passphrase can't be empty")
	}
	i := &ScryptIdentity{
		password: []byte(password),
	}
	return i, nil
}

func (i *ScryptIdentity) Unwrap(block *Stanza) ([]byte, error) {
	if block.Type != "scrypt" {
		return nil, ErrIncorrectIdentity
	}
	if len(block.Args) != 2 {
		return nil, errors.New("invalid scrypt recipient block")
	}
	salt, err := DecodeString(block.Args[0])
	if err != nil {
		return nil, fmt.Errorf("failed to parse scrypt salt: %v", err)
	}
	if len(salt) != 16 {
		return nil, errors.New("invalid scrypt recipient block")
	}
	logN, err := strconv.Atoi(block.Args[1])
	if err != nil {
		return nil, fmt.Errorf("failed to parse scrypt work factor: %v", err)
	}
	if logN <= 0 {
		return nil, fmt.Errorf("invalid scrypt work factor: %v", logN)
	}

	salt = append([]byte(scryptLabel), salt...)
	k, err := scrypt.Key(i.password, salt, 1<<logN, 8, 1, chacha20poly1305.KeySize)
	if err != nil {
		return nil, fmt.Errorf("failed to generate scrypt hash: %v", err)
	}

	fileKey, err := aeadDecrypt(k, block.Body)
	if err != nil {
		return nil, ErrIncorrectIdentity
	}
	return fileKey, nil
}

type LazyScryptIdentity struct {
	Passphrase func() (string, error)
}

var _ Identity = &LazyScryptIdentity{}

func (i *LazyScryptIdentity) Type() string {
	return "scrypt"
}

func (i *LazyScryptIdentity) Unwrap(block *Stanza) (fileKey []byte, err error) {
	pass, err := i.Passphrase()
	if err != nil {
		return nil, fmt.Errorf("could not read passphrase: %v", err)
	}
	ii, err := NewScryptIdentity(pass)
	if err != nil {
		return nil, err
	}
	fileKey, err = ii.Unwrap(block)
	if err == ErrIncorrectIdentity {
		// The API will just ignore the identity if the passphrase is wrong, and
		// move on, eventually returning "no identity matched a recipient".
		// Since we only supply one identity from the CLI, make it a fatal
		// error with a better message.
		return nil, fmt.Errorf("incorrect passphrase")
	}
	return fileKey, err
}
