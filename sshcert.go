package sshcert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	CAName = "evans-open-ssh-ca@ejj.io"
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
	Duration    time.Time
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

// createPrivateKey will create a new ecdsa PrivateKey.
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

// String will print the public key entry that should be added to the server's sshd_config
func (s *SshCa) String() string {
	return fmt.Sprintf("%s %s %s", s.Signer.PublicKey().Type(), base64.StdEncoding.EncodeToString(s.Signer.PublicKey().Marshal()), CAName)
}

func randomSerial() uint64 {
	buf := make([]byte, 8)
	rand.Read(buf)
	return binary.LittleEndian.Uint64(buf)
}

func (s *SshCa) SignCert(pub ssh.PublicKey) (*SshCert, error) {
	cert := &ssh.Certificate{
		Key:             pub,
		Serial:          randomSerial(),
		CertType:        ssh.UserCert,
		KeyId:           "aaaa",
		ValidPrincipals: []string{"evan"},
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
