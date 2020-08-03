# sasquatch

A simple file encryption library, heavily inspired by @Benjojo12 and
@FiloSottile's fantastic age project.

## Features

- [x] Multiple recipients
- [x] Supports encrypting with your existing SSH keys / ssh-agent
- [x] Convenient API

## Crypto Backends

- [x] ssh-rsa
- [x] ssh-ed25519
- [x] ssh-agent signing challenge
- [x] scrypt / password

## Example

### Encryption

```go
buf := bytes.NewBuffer(nil)

alice, err := sasquatch.ParseRecipient("ssh-ed25519 ...")
bob, err := sasquatch.ParseRecipient("ssh-rsa ...")

r := []sasquatch.Recipient{alice, bob}
w, err := sasquatch.Encrypt(buf, r...)

data := []byte("Hello Alice, Hey Bob!")
w.Write(data)
w.Close()

ioutil.WriteFile("/tmp/sasquatch.encrypted", buf.Bytes(), 0644)
```

### Decryption

```go
buf, err := ioutil.ReadFile("/tmp/sasquatch.encrypted")

// find all available identities
identities := sasquatch.FindIdentities()
r, err := sasquatch.Decrypt(buf, identities...)

buf, err := ioutil.ReadAll(r)
ioutil.WriteFile("/tmp/sasquatch.decrypted", buf.Bytes(), 0644)
```

### ssh-agent Challenge

```go
// encryption
signers, err := sasquatch.SSHAgentSigners()
rcp, err := sasquatch.NewChallengeRecipient(signers[0])
sasquatch.Encrypt(buf, rcp)

// decryption
id, err := sasquatch.NewChallengeIdentity(signers[0])
r, err := sasquatch.Decrypt(buf, id)
```

### scrypt / password Encryption

```go
// encryption
rcp, err := sasquatch.NewScryptRecipient("password")
sasquatch.Encrypt(buf, rcp)

// decryption
id, err := sasquatch.NewScryptIdentity("password")
r, err := sasquatch.Decrypt(buf, id)
```
