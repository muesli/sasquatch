# sasquatch

[![Build Status](https://github.com/muesli/sasquatch/workflows/build/badge.svg)](https://github.com/muesli/sasquatch/actions)
[![Coverage Status](https://coveralls.io/repos/github/muesli/sasquatch/badge.svg?branch=master)](https://coveralls.io/github/muesli/sasquatch?branch=master)
[![Go ReportCard](https://goreportcard.com/badge/muesli/sasquatch)](https://goreportcard.com/report/muesli/sasquatch)
[![GoDoc](https://godoc.org/github.com/golang/gddo?status.svg)](https://godoc.org/github.com/muesli/sasquatch)

A simple data encryption library, heavily inspired by [@Benjojo12](https://github.com/benjojo) and
[@FiloSottile](https://github.com/FiloSottile)'s fantastic [age](https://github.com/FiloSottile/age) project.

## Features

- [x] Multiple recipients
- [x] Supports encrypting with your existing SSH keys / ssh-agent
- [x] Convenient API

## Crypto Backends

- [x] ssh-rsa
- [x] ssh-ed25519
- [x] ssh-agent signing challenge (excluding ECDSA identities, as ECDSA signatures aren't deterministic)
- [x] scrypt / password

## Example

### Encryption

```go
buf := bytes.NewBuffer(nil)

alice, err := sasquatch.ParseRecipient("ssh-ed25519 ...")
bob, err := sasquatch.ParseRecipient("ssh-rsa ...")

rcp := []sasquatch.Recipient{alice, bob}
w, err := sasquatch.Encrypt(buf, rcp...)

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
