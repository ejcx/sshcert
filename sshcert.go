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
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	caName = "open-ssh-ca@ejj.io"
	hour   = time.Second * 3600
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
	DefaultPermissions = ssh.Permissions{
		Extensions: map[string]string{
			"permit-pty":              "",
			"permit-user-rc":          "",
			"permit-agent-forwarding": "",
		},
	}
)

type CA struct {
	PrivateKey *ecdsa.PrivateKey
}
type Cert struct {
	Certificate *ssh.Certificate
}

type SigningArguments struct {
	Principals  []string
	Permissions ssh.Permissions
	Duration    time.Duration
}

func NewCA() (CA, error) {
	key, err := createPrivateKey()
	return CA{
		PrivateKey: key,
	}, err
}

func (c *CA) SignCert(pub ssh.PublicKey, signArgs *SigningArguments) (*Cert, error) {
	cert := &ssh.Certificate{
		Key:             pub,
		Serial:          randomSerial(),
		CertType:        ssh.UserCert,
		KeyId:           randomHex(),
		ValidAfter:      uint64(time.Now().Unix()),
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

func (c *Cert) String() string {
	return fmt.Sprintf("%s %s", ssh.CertAlgoECDSA256v01, base64.StdEncoding.EncodeToString(c.Certificate.Marshal()))
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

func (c *CA) String() string {
	return fmt.Sprintf("%s %s %s", c.Signer().PublicKey().Type(), base64.StdEncoding.EncodeToString(c.Signer().PublicKey().Marshal()), caName)
}

func (c *CA) Marshal() ([]byte, error) {
	return x509.MarshalECPrivateKey(c.PrivateKey)
}

func UnmarshalCA(buf []byte) (*CA, error) {
	priv, err := x509.ParseECPrivateKey(buf)
	if err != nil {
		return nil, err
	}
	return &CA{
		PrivateKey: priv,
	}, nil
}

func NewSigningArguments(principals []string) *SigningArguments {
	return &SigningArguments{
		Permissions: DefaultPermissions,
		Duration:    hour,
		Principals:  principals,
	}
}

func (s *SigningArguments) SetPermissions(permissions ssh.Permissions) {
	s.Permissions = permissions
}

func (s *SigningArguments) SetDuration(d time.Duration) {
	s.Duration = d
}

func (s *SigningArguments) SetPrincipals(principals []string) {
	s.Principals = principals
}

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
