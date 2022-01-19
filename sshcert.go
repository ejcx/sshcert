package sshcert

// sshcert is a package for creating and signing SSH user certificates.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	caName         = "open-ssh-ca@ejj.io"
	hour           = time.Second * 3600
	allowableDrift = 60 * time.Second
	pemHeader      = "BEGIN SSHCERT PRIVATE KEY"
)

var (
	// DefaultPermissions are the default permissions associated with the
	// signing of an ssh user certificate. In this case, we specify three
	// extensions.
	// - permit-pty:
	//     Is set because creating a new pty on connection is required for
	//     the best shell ux.
	// - permit-user-rc:
	//     Allow users to forward their ssh agent to use jumpboxes.
	// - permit-agent-forwarding
	//     Allows your engineers to utilize a jumpbox seamlessly.
	DefaultPermissions = ssh.Permissions{
		Extensions: map[string]string{
			"permit-pty":              "",
			"permit-user-rc":          "",
			"permit-port-forwarding":  "",
			"permit-agent-forwarding": "",
		},
	}
)

// CA represents an SSH certificate authority.
type CA struct {
	PrivateKey *ecdsa.PrivateKey
	customName string
}

// Cert represents an SSH public key that has been signed by a
// certificate authority.
type Cert struct {
	Certificate *ssh.Certificate
}

// SigningArguments is the information that the SSH Certificate Authority
// needs in order to sign an SSH public key. All of these fields are required.
// If you would like to read more about how to configure the SigningArguments
// then I found the following to be a good source of information:
//   - https://github.com/metacloud/openssh/blob/master/PROTOCOL.certkeys
// If you would like to use default settings then call `NewSigningArguments`
type SigningArguments struct {
	Principals  []string
	Permissions ssh.Permissions
	Duration    time.Duration
}

// NewCA will instantiate a new CA and generate a fresh ecdsa Private key.
func NewCA() (CA, error) {
	key, err := createPrivateKey()
	return CA{
		PrivateKey: key,
		customName: caName,
	}, err
}

// SignCert is called to sign an ssh public key and produce an ssh certificate.
// It's required to pass in SigningArguments or the signing will fail.
func (c *CA) SignCert(pub ssh.PublicKey, signArgs *SigningArguments) (*Cert, error) {
	cert := &ssh.Certificate{
		Key:      pub,
		Serial:   randomSerial(),
		CertType: ssh.UserCert,
		KeyId:    randomHex(),
		// Subtract 60 seconds to allow for some clock drift between the signature signing and the remote servers
		ValidAfter:      uint64(time.Now().Add(-allowableDrift).Unix()),
		ValidBefore:     uint64(time.Now().Add(signArgs.Duration).Unix()),
		ValidPrincipals: signArgs.Principals,
		Permissions:     signArgs.Permissions,
	}
	err := cert.SignCert(rand.Reader, c.Signer())
	if err != nil {
		return nil, err
	}
	return &Cert{Certificate: cert}, nil
}

// PrivateString converts a CA in to a PEM encoded private key
func (c *CA) PrivateString() (string, error) {
	privDer, err := x509.MarshalECPrivateKey(c.PrivateKey)
	if err != nil {
		return "", err
	}
	privBlock := pem.Block{
		Type:    pemHeader,
		Headers: nil,
		Bytes:   privDer,
	}
	privatePEM := pem.EncodeToMemory(&privBlock)
	return string(privatePEM), nil
}

// ParsePrivateString hydrates a CA type with a PEM encoded private key. This
// method will modify the CA's private key.
func (c *CA) ParsePrivateString(data []byte) error {
	// Decode returns a block and a 'rest'. We don't really care
	// about the rest. In this case, the actual key data we need
	// is in the block bytes.
	block, _ := pem.Decode(data)
	return c.FromBytes(block.Bytes)
}

// Signer returns the signer associated with a private key.
func (c *CA) Signer() ssh.Signer {
	// We can ignore this error. NewSignerFromKey supports ecdsa
	// PrivateKeys, but it's possible in the future we could
	// add support for unsupported crypto primitives. We will
	// need to check this error when we support more than ecdsa.
	signer, _ := ssh.NewSignerFromKey(c.PrivateKey)
	return signer
}

// String will output the public key of the Certificate Authority that is
// used with the `TrustedUserCAKeys` directive in an sshd config.
func (c *CA) String() string {
	return fmt.Sprintf("%s %s %s", c.Signer().PublicKey().Type(), base64.StdEncoding.EncodeToString(c.Signer().PublicKey().Marshal()), c.customName)
}

// Bytes converts the certificate authority private key to it's SSH key bytes.
func (c *CA) Bytes() ([]byte, error) {
	return x509.MarshalECPrivateKey(c.PrivateKey)
}

// FromBytes hydreates a CA with the private key bytes.
func (c *CA) FromBytes(data []byte) error {
	priv, err := x509.ParseECPrivateKey(data)
	if err != nil {
		return err
	}
	c.PrivateKey = priv
	return nil
}

func (c *CA) SetName(name string) {
	c.customName = name
}

// String will output the SSH certificate in a format that can be used
// with an ssh client.
func (c *Cert) String() string {
	return fmt.Sprintf("%s %s", c.Type(), base64.StdEncoding.EncodeToString(c.Certificate.Marshal()))
}

// Type returns the certificate's algorithm name.
func (c *Cert) Type() string {
	return c.Certificate.Type()
}

// NewSigningArguments will create a default SigningArguments type with the
// principals passed in. The list of principals passed in to this function
// is the list of linux users that the user will be able to ssh to.
func NewSigningArguments(principals []string) *SigningArguments {
	return &SigningArguments{
		Permissions: DefaultPermissions,
		Duration:    hour,
		Principals:  principals,
	}
}

// SetPermissions will set the permissions of a SigningArguments type.
func (s *SigningArguments) SetPermissions(permissions ssh.Permissions) {
	s.Permissions = permissions
}

// SetDuration will set the duration of a SigningArguments type.
func (s *SigningArguments) SetDuration(d time.Duration) {
	s.Duration = d
}

// // SetPrincipals will set the principals of a SigningArguments type.
func (s *SigningArguments) SetPrincipals(principals []string) {
	s.Principals = principals
}

// ParsePublicKey will parse and return an SSH public key from it's
// non-wire format.
func ParsePublicKey(pub string) (ssh.PublicKey, error) {
	pubParts := strings.Split(pub, " ")
	if len(pubParts) != 2 && len(pubParts) != 3 {
		return nil, errors.New("Invalid public key format")
	}
	pubBytes, err := base64.StdEncoding.DecodeString(pubParts[1])
	pubKey, err := ssh.ParsePublicKey(pubBytes)
	if err != nil {
		return nil, err
	}
	return pubKey, nil
}

func createPrivateKey() (*ecdsa.PrivateKey, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return &ecdsa.PrivateKey{}, err
	}
	return privateKey, nil
}

func randomSerial() uint64 {
	buf := make([]byte, 8)
	rand.Read(buf)
	return binary.LittleEndian.Uint64(buf)
}

func randomHex() string {
	buf := make([]byte, 16)
	rand.Read(buf)
	return hex.EncodeToString(buf)
}
