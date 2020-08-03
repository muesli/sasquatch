package sasquatch

import (
	"bytes"
	"io/ioutil"
	"testing"

	"github.com/mitchellh/go-homedir"
)

func TestFindSSHKeys(t *testing.T) {
	keys, err := FindSSHKeys()
	if err != nil {
		t.Error(err)
	}

	if len(keys) == 0 {
		t.Fatal("no keys found")
	}
	// fmt.Println(keys)
}

func TestFindSSHAgentSigners(t *testing.T) {
	signers, err := SSHAgentSigners()
	if err != nil {
		t.Error(err)
	}

	if len(signers) == 0 {
		// t.Fatal("no signers found")
	}

	/*
		for _, k := range signers {
			s := EncodeToString(k.PublicKey().Marshal())
			fmt.Println(s)
		}
	*/
}

func TestIdentityFromFile(t *testing.T) {
	key, _ := homedir.Expand("~/.ssh/id_rsa")
	i, err := ParseIdentitiesFile(key)
	if err != nil {
		t.Fatal(err)
	}

	if len(i) == 0 {
		t.Fatal("no key found")
	}
}

func TestRecipientFromFile(t *testing.T) {
	key, _ := homedir.Expand("~/.ssh/id_rsa.pub")
	c, err := ioutil.ReadFile(key)
	if err != nil {
		t.Fatal(err)
	}

	_, err = ParseRecipient(string(c))
	if err != nil {
		t.Fatal(err)
	}
}

func TestSSHEncrypt(t *testing.T) {
	buf := bytes.NewBuffer(nil)

	r := FindRecipients()
	if len(r) == 0 {
		t.Fatal("no recipients found")
	}
	// fmt.Printf("found %d recipients\n", len(r))

	w, err := Encrypt(buf, r...)
	if err != nil {
		t.Fatal(err)
	}

	data := []byte("Hello World!")
	_, err = w.Write(data)
	if err != nil {
		t.Fatal(err)
	}
	err = w.Close()
	if err != nil {
		t.Fatal(err)
	}

	// _ = ioutil.WriteFile("/tmp/sasquatch.crypted.rsa", buf.Bytes(), 0644)

	ids := FindIdentities()
	dr, err := Decrypt(buf, ids...)
	if err != nil {
		t.Fatal(err)
	}

	dbuf, _ := ioutil.ReadAll(dr)
	if !bytes.Equal(dbuf, data) {
		t.Fatalf("Decrypted data does not match!")
	}
}

func TestChallengeEncrypt(t *testing.T) {
	buf := bytes.NewBuffer(nil)

	signers, err := SSHAgentSigners()
	if err != nil {
		t.Fatal(err)
	}

	r, err := NewChallengeRecipient(signers[0])
	if err != nil {
		t.Fatal(err)
	}

	w, err := Encrypt(buf, r)
	if err != nil {
		t.Fatal(err)
	}

	data := []byte("Hello World!")
	_, err = w.Write(data)
	if err != nil {
		t.Fatal(err)
	}
	err = w.Close()
	if err != nil {
		t.Fatal(err)
	}

	// _ = ioutil.WriteFile("/tmp/sasquatch.crypted.agent", buf.Bytes(), 0644)

	ids := FindIdentities()
	dr, err := Decrypt(buf, ids...)
	if err != nil {
		t.Fatal(err)
	}

	dbuf, _ := ioutil.ReadAll(dr)
	if !bytes.Equal(dbuf, data) {
		t.Fatalf("Decrypted data does not match!")
	}
}

func TestScryptEncrypt(t *testing.T) {
	buf := bytes.NewBuffer(nil)

	r, err := NewScryptRecipient("password")
	if err != nil {
		t.Fatal(err)
	}

	w, err := Encrypt(buf, r)
	if err != nil {
		t.Fatal(err)
	}

	data := []byte("Hello World!")
	_, err = w.Write(data)
	if err != nil {
		t.Fatal(err)
	}
	err = w.Close()
	if err != nil {
		t.Fatal(err)
	}

	id, err := NewScryptIdentity("password")
	if err != nil {
		t.Fatal(err)
	}

	dr, err := Decrypt(buf, id)
	if err != nil {
		t.Fatal(err)
	}

	dbuf, _ := ioutil.ReadAll(dr)
	if !bytes.Equal(dbuf, data) {
		t.Fatalf("Decrypted data does not match!")
	}
}
