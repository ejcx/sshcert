package sshcert

import (
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestCreatePrivateKey(t *testing.T) {
	key, err := createPrivateKey()
	if err != nil {
		t.Fatalf("Could not generate private key: %s", err)
	}
	if key == nil {
		t.Fatalf("key is nil")
	}
}

func TestCreateSSHSigner(t *testing.T) {
	_, err := createSSHSigner()
	if err != nil {
		t.Fatalf("Could not get signer: %s", err)
	}
}
func TestNewCA(t *testing.T) {
	_, err := NewCA()
	if err != nil {
		t.Fatalf("Could not create ca: %s", err)
	}
}

func TestPublicKeyString(t *testing.T) {
	ca, _ := NewCA()
	fmt.Println(ca.String())
}

func TestSignCert(t *testing.T) {
	ca, _ := NewCA()
	pubBytes, _ := ioutil.ReadFile("testkeys.pub")
	pubKeyParts := strings.Split(string(pubBytes), " ")
	if len(pubKeyParts) != 3 {
		t.Fatalf("Invalid pub key parts. Expected 3 parts got %d", len(pubKeyParts))
	}
	pubBytes, err := base64.StdEncoding.DecodeString(pubKeyParts[1])
	pub, err := ssh.ParsePublicKey(pubBytes)
	if err != nil {
		t.Fatalf("Could not parse public key: %s", err)
	}
	cert, err := ca.SignCert(pub)
	if err != nil {
		t.Fatalf("Could nbot sign cert: %s", err)
	}
	fmt.Println(cert.String())
}
