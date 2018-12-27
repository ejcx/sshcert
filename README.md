# sshcert
sshcert is a package and CLI for handling SSH user certs

## Installation
```
go get github.com/ejcx/sshcert
```

## Usage
### Creating an SSH certificate authority
Calling `NewCA` will create a new SSH user certificate authority.
```
ca, err := NewCA()
```

### Signing an SSH user certificate
The `SignCert` method is used to sign a new certificate to provide access to a server who is trusting a certificate.

`SignCert` requires an `ssh.PublicKey` and `SigningArguments` be passed in order to sign a public key.

`NewSigningArguments` can be used to instantiate a `SigningArgument` struct. Pass `NewSigningArguments` the list of Linux users that you providing the cert to. If you wish to log in as `root` (which is a bad practice) pass `root`.

```
sa := NewSigningArguments([]string{"evan"})
ca.SignCert(evanPublicKey, sa)
```

### Marshalling and Unmarshalling a CA
CA cannot be marshalled using the json package. Instead call `Bytes` to convert the SSH key to it's binary format, or call `PrivateString` to convert the CA to a PEM encoded private key, that can then be converted back to a CA using `ParsePrivateString`

## Converting to binary format
```
buf, err := ca.Bytes()
if err != nil {
    log.Fatalf("Could not parse CA: %s", err)
}
```

To unmarshal call `FromBytes`.

```
var ca sshcert.CA
err := ca.FromBytes(buf)
if err != nil {
    log.Fatalf("Could not parse CA: %s", err)
}
```

## Converting to PEM encoded format
```
pemKey, err := ca.PrivateString()
if err != nil {
    log.Fatalf("Could not convert CA to PEM encoded key: %s", err)
}

var newCA sshcert.CA
err = newCA.ParsePrivateString(pemKey)
if err != nil {
    log.Fatalf("Could not convert the PEM encoded key into CA: %s", err)
}
```