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
		t.Fatal("no signers found")
	}

	/*
		for _, k := range signers {
			s := EncodeToString(k.PublicKey().Marshal())
			fmt.Println(s)
		}
	*/
}

func TestFindRecipients(t *testing.T) {
	rcp := FindRecipients()

	if len(rcp) == 0 {
		t.Fatal("no recipients found")
	}
}

func TestFindIdentities(t *testing.T) {
	identities := FindIdentities()

	if len(identities) == 0 {
		t.Fatal("no identities found")
	}
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

func TestRecipientFromPubKey(t *testing.T) {
	pubkey := `ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQCnpGXlDvHC7YbQTBhxYnQVFlPjhG9NJzJA+DvucLjyEhoFZT7FRd1Zpy1vX3asswolBW+BkfI7y0opamhWoJbUKZFXsQnymfLknqMZ10FcXBpkbGj/wE9NdDu36CORb9W9mItwhqrIY5eAhktMmVnqaq3bqRW08y8BiTzbt17ulxr81/OFymKPnX5qKfGErKXkT8L8umuGcNknpumyDHvxDHWQ8El4KmLDHFb7UsZxY272dMuFXXGVCN90V5aEzXNklPhkHcQnaCvGhPmBwQBCjaBYc+0oQFLO7+s1mXkS92pt4hiX1Srui+VYtTN6Laqcu/HIwFjKC65EmNCW/6t9XzP+lZbu9U5gRPLS3tDEUkp5j3yMyM/E28fdsGvYnb8Fyj7ifV6fCcWvCkEfj+vDK4iJn9NmkPfsQvt4Hi4p5voPyCZw6PvCyQZW1jpIDDBBtGZxOxAn9aVQicJ34ZIusbCgygLonkgZ/C67Kd9ewIsNLGYjtKvo8k6l6vqWjqt5HmQCIT6SPMEhlh9hitcLbUh7EvcpqfMpClSpEDwnbh7k1g4Izv073ky16ACT0IA2ocGXnZGcjUYNiPhYry4hzajSTCveJJrOWi0j13BSSZJa9j0EsVSGHzln+H/Oz8V4QqOOnlw8Kuud9FPnOgA6e7+jRAk3aSpulNosUtsMUw==`

	_, err := ParseRecipient(pubkey)
	if err != nil {
		t.Fatal(err)
	}
}

func TestSSHEncrypt(t *testing.T) {
	buf := bytes.NewBuffer(nil)

	key, _ := homedir.Expand("~/.ssh/id_rsa.pub")
	c, err := ioutil.ReadFile(key)
	if err != nil {
		t.Fatal(err)
	}

	r, err := ParseRecipient(string(c))
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
