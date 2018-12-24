package sshcert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
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
	CAName = "evans-open-ssh-ca@ejj.io"
	Hour   = time.Second * 3600
)

var (
	DefaultPermissions = ssh.Permissions{
		Extensions: map[string]string{
			"permit-pty":              "",
			"permit-user-rc":          "",
			"permit-agent-forwarding": "",
		},
	}
)

type SshCa struct {
	Signer ssh.Signer
}
type SshCert struct {
	Certificate *ssh.Certificate
}

type SigningArguments struct {
	Principals  []string
	Permissions ssh.Permissions
	Duration    time.Duration
}

func NewCA() (SshCa, error) {
	signer, err := createSSHSigner()
	if err != nil {
		return SshCa{}, err
	}
	return SshCa{
		Signer: signer,
	}, nil
}

func (s *SshCa) SignCert(pub ssh.PublicKey, signArgs *SigningArguments) (*SshCert, error) {
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
	err := cert.SignCert(rand.Reader, s.Signer)
	if err != nil {
		return nil, err
	}
	return &SshCert{Certificate: cert}, nil
}

func (c *SshCert) String() string {
	return fmt.Sprintf("%s %s", ssh.CertAlgoECDSA256v01, base64.StdEncoding.EncodeToString(c.Certificate.Marshal()))
}

func (s *SshCa) String() string {
	return fmt.Sprintf("%s %s %s", s.Signer.PublicKey().Type(), base64.StdEncoding.EncodeToString(s.Signer.PublicKey().Marshal()), CAName)
}

func NewSigningArguments(principals []string) *SigningArguments {
	return &SigningArguments{
		Permissions: DefaultPermissions,
		Duration:    Hour,
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

func createSSHSigner() (ssh.Signer, error) {
	key, err := createPrivateKey()
	if err != nil {
		return nil, err
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		return nil, err
	}
	return signer, nil
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
