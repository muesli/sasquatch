package sasquatch

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"io"
	"math/big"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/ssh"
)

const ed25519Label = "charm.sh/v1/ssh-ed25519"

type Ed25519Recipient struct {
	sshKey         ssh.PublicKey
	theirPublicKey []byte
}

var _ Recipient = &Ed25519Recipient{}

func (*Ed25519Recipient) Type() string { return "ssh-ed25519" }

func NewEd25519Recipient(pk ssh.PublicKey) (*Ed25519Recipient, error) {
	if pk.Type() != "ssh-ed25519" {
		return nil, errors.New("SSH public key is not an Ed25519 key")
	}
	r := &Ed25519Recipient{
		sshKey: pk,
	}

	if pk, ok := pk.(ssh.CryptoPublicKey); ok {
		if pk, ok := pk.CryptoPublicKey().(ed25519.PublicKey); ok {
			r.theirPublicKey = ed25519PublicKeyToCurve25519(pk)
		} else {
			return nil, errors.New("unexpected public key type")
		}
	} else {
		return nil, errors.New("pk does not implement ssh.CryptoPublicKey")
	}
	return r, nil
}

var curve25519P, _ = new(big.Int).SetString("57896044618658097711785492504343953926634992332820282019728792003956564819949", 10)

func ed25519PublicKeyToCurve25519(pk ed25519.PublicKey) []byte {
	// ed25519.PublicKey is a little endian representation of the y-coordinate,
	// with the most significant bit set based on the sign of the x-coordinate.
	bigEndianY := make([]byte, ed25519.PublicKeySize)
	for i, b := range pk {
		bigEndianY[ed25519.PublicKeySize-i-1] = b
	}
	bigEndianY[0] &= 0b0111_1111

	// The Montgomery u-coordinate is derived through the bilinear map
	//
	//     u = (1 + y) / (1 - y)
	//
	// See https://blog.filippo.io/using-ed25519-keys-for-encryption.
	y := new(big.Int).SetBytes(bigEndianY)
	denom := big.NewInt(1)
	denom.ModInverse(denom.Sub(denom, y), curve25519P) // 1 / (1 - y)
	u := y.Mul(y.Add(y, big.NewInt(1)), denom)
	u.Mod(u, curve25519P)

	out := make([]byte, curve25519.PointSize)
	uBytes := u.Bytes()
	for i, b := range uBytes {
		out[len(uBytes)-i-1] = b
	}

	return out
}

func (r *Ed25519Recipient) Wrap(fileKey []byte) (*Stanza, error) {
	ephemeral := make([]byte, curve25519.ScalarSize)
	if _, err := rand.Read(ephemeral); err != nil {
		return nil, err
	}
	ourPublicKey, err := curve25519.X25519(ephemeral, curve25519.Basepoint)
	if err != nil {
		return nil, err
	}

	sharedSecret, err := curve25519.X25519(ephemeral, r.theirPublicKey)
	if err != nil {
		return nil, err
	}

	tweak := make([]byte, curve25519.ScalarSize)
	tH := hkdf.New(sha256.New, nil, r.sshKey.Marshal(), []byte(ed25519Label))
	if _, err := io.ReadFull(tH, tweak); err != nil {
		return nil, err
	}
	sharedSecret, _ = curve25519.X25519(tweak, sharedSecret)

	l := &Stanza{
		Type: "ssh-ed25519",
		Args: []string{sshFingerprint(r.sshKey),
			EncodeToString(ourPublicKey[:])},
	}

	salt := make([]byte, 0, len(ourPublicKey)+len(r.theirPublicKey))
	salt = append(salt, ourPublicKey...)
	salt = append(salt, r.theirPublicKey...)
	h := hkdf.New(sha256.New, sharedSecret, salt, []byte(ed25519Label))
	wrappingKey := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(h, wrappingKey); err != nil {
		return nil, err
	}

	wrappedKey, err := aeadEncrypt(wrappingKey, fileKey)
	if err != nil {
		return nil, err
	}
	l.Body = wrappedKey

	return l, nil
}

type Ed25519Identity struct {
	secretKey, ourPublicKey []byte
	sshKey                  ssh.PublicKey
}

var _ Identity = &Ed25519Identity{}

func (*Ed25519Identity) Type() string { return "ssh-ed25519" }

func NewEd25519Identity(key ed25519.PrivateKey) (*Ed25519Identity, error) {
	s, err := ssh.NewSignerFromKey(key)
	if err != nil {
		return nil, err
	}
	i := &Ed25519Identity{
		sshKey:    s.PublicKey(),
		secretKey: ed25519PrivateKeyToCurve25519(key),
	}
	i.ourPublicKey, _ = curve25519.X25519(i.secretKey, curve25519.Basepoint)
	return i, nil
}

func ed25519PrivateKeyToCurve25519(pk ed25519.PrivateKey) []byte {
	h := sha512.New()
	_, _ = h.Write(pk.Seed())
	out := h.Sum(nil)
	return out[:curve25519.ScalarSize]
}

func (i *Ed25519Identity) Unwrap(block *Stanza) ([]byte, error) {
	if block.Type != "ssh-ed25519" {
		return nil, ErrIncorrectIdentity
	}
	if len(block.Args) != 2 {
		return nil, errors.New("invalid ssh-ed25519 recipient block")
	}
	publicKey, err := DecodeString(block.Args[1])
	if err != nil {
		return nil, fmt.Errorf("failed to parse ssh-ed25519 recipient: %v", err)
	}
	if len(publicKey) != curve25519.PointSize {
		return nil, errors.New("invalid ssh-ed25519 recipient block")
	}

	if block.Args[0] != sshFingerprint(i.sshKey) {
		return nil, ErrIncorrectIdentity
	}

	sharedSecret, err := curve25519.X25519(i.secretKey, publicKey)
	if err != nil {
		return nil, fmt.Errorf("invalid X25519 recipient: %v", err)
	}

	tweak := make([]byte, curve25519.ScalarSize)
	tH := hkdf.New(sha256.New, nil, i.sshKey.Marshal(), []byte(ed25519Label))
	if _, err := io.ReadFull(tH, tweak); err != nil {
		return nil, err
	}
	sharedSecret, _ = curve25519.X25519(tweak, sharedSecret)

	salt := make([]byte, 0, len(publicKey)+len(i.ourPublicKey))
	salt = append(salt, publicKey...)
	salt = append(salt, i.ourPublicKey...)
	h := hkdf.New(sha256.New, sharedSecret, salt, []byte(ed25519Label))
	wrappingKey := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(h, wrappingKey); err != nil {
		return nil, err
	}

	fileKey, err := aeadDecrypt(wrappingKey, block.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt file key: %v", err)
	}
	return fileKey, nil
}
