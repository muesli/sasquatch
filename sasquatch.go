package sasquatch

import (
	"crypto/hmac"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/crypto/ssh/terminal"

	"github.com/muesli/sasquatch/stream"
)

// A Stanza is a section of the header that encapsulates the file key as
// encrypted to a specific recipient.
type Stanza struct {
	Type string
	Args []string
	Body []byte
}

// Encrypt returns a WriteCloser. Writes to the returned value are encrypted and
// written to dst as an encrypted file. Every recipient will be able to decrypt
// the file.
//
// The caller must call Close on the returned value when done for the last chunk
// to be encrypted and flushed to dst.
func Encrypt(dst io.Writer, recipients ...Recipient) (io.WriteCloser, error) {
	return EncryptWithMetadata(dst, nil, recipients...)
}

// EncryptWithMetadata behaves like Encrypt, but additionally stores unencrypted
// metadata.
func EncryptWithMetadata(dst io.Writer, metadata []byte, recipients ...Recipient) (io.WriteCloser, error) {
	if len(recipients) == 0 {
		return nil, errors.New("no recipients specified")
	}

	fileKey := make([]byte, 16)
	if _, err := rand.Read(fileKey); err != nil {
		return nil, err
	}

	hdr := &Header{
		Metadata: metadata,
	}
	for i, r := range recipients {
		if r.Type() == "scrypt" && len(recipients) != 1 {
			return nil, errors.New("an scrypt recipient must be the only one")
		}

		block, err := r.Wrap(fileKey)
		if err != nil {
			return nil, fmt.Errorf("failed to wrap key for recipient #%d: %v", i, err)
		}
		hdr.Recipients = append(hdr.Recipients, (*Stanza)(block))
	}
	if mac, err := headerMAC(fileKey, hdr); err != nil {
		return nil, fmt.Errorf("failed to compute header MAC: %v", err)
	} else {
		hdr.MAC = mac
	}
	if err := hdr.Marshal(dst); err != nil {
		return nil, fmt.Errorf("failed to write header: %v", err)
	}

	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	if _, err := dst.Write(nonce); err != nil {
		return nil, fmt.Errorf("failed to write nonce: %v", err)
	}

	return stream.NewWriter(streamKey(fileKey, nonce), dst)
}

// Decrypt returns a Reader reading the decrypted plaintext of the encrypted file read
// from src. All identities will be tried until one successfully decrypts the file.
func Decrypt(src io.Reader, identities ...Identity) (io.Reader, error) {
	r, _, err := DecryptWithMetadata(src, identities...)
	return r, err
}

// Decrypt returns a Reader reading the decrypted plaintext of the encrypted file read
// from src. All identities will be tried until one successfully decrypts the file.
func DecryptWithMetadata(src io.Reader, identities ...Identity) (io.Reader, []byte, error) {
	if len(identities) == 0 {
		return nil, nil, errors.New("no identities specified")
	}

	hdr, payload, err := Parse(src)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read header: %v", err)
	}
	if len(hdr.Recipients) > 20 {
		return nil, nil, errors.New("too many recipients")
	}

	var fileKey []byte
RecipientsLoop:
	for _, r := range hdr.Recipients {
		if r.Type == "scrypt" && len(hdr.Recipients) != 1 {
			return nil, nil, errors.New("an scrypt recipient must be the only one")
		}

		for _, i := range identities {
			if i.Type() != r.Type {
				continue
			}

			if i, ok := i.(IdentityMatcher); ok {
				err := i.Match((*Stanza)(r))
				if err != nil {
					if err == ErrIncorrectIdentity {
						continue
					}
					return nil, nil, err
				}
			}

			fileKey, err = i.Unwrap((*Stanza)(r))
			if err != nil {
				if err == ErrIncorrectIdentity {
					// TODO: we should collect these errors and return them as an
					// []error type with an Error method. That will require turning
					// ErrIncorrectIdentity into an interface or wrapper error.
					continue
				}
				return nil, nil, err
			}

			break RecipientsLoop
		}
	}
	if fileKey == nil {
		return nil, nil, errors.New("no identity matched a recipient")
	}

	if mac, err := headerMAC(fileKey, hdr); err != nil {
		return nil, nil, fmt.Errorf("failed to compute header MAC: %v", err)
	} else if !hmac.Equal(mac, hdr.MAC) {
		return nil, nil, errors.New("bad header MAC")
	}

	nonce := make([]byte, 16)
	if _, err := io.ReadFull(payload, nonce); err != nil {
		return nil, nil, fmt.Errorf("failed to read nonce: %v", err)
	}

	r, err := stream.NewReader(streamKey(fileKey, nonce), payload)
	return r, hdr.Metadata, err
}

func Metadata(src io.Reader) ([]byte, error) {
	hdr, _, err := Parse(src)
	if err != nil {
		return nil, fmt.Errorf("failed to read header: %v", err)
	}

	return hdr.Metadata, nil
}

func readPassphrase() ([]byte, error) {
	fd := int(os.Stdin.Fd())
	if !terminal.IsTerminal(fd) {
		tty, err := os.Open("/dev/tty")
		if err != nil {
			return nil, fmt.Errorf("standard input is not available or not a terminal, and opening /dev/tty failed: %v", err)
		}
		defer tty.Close()
		fd = int(tty.Fd())
	}
	defer fmt.Fprintf(os.Stderr, "\n")
	p, err := terminal.ReadPassword(fd)
	if err != nil {
		return nil, err
	}
	return p, nil
}
