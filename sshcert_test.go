package sshcert

import (
	"fmt"
	"io/ioutil"
	"testing"
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

func TestParsePublicKey(t *testing.T) {
	pubBytes, _ := ioutil.ReadFile("testkeys.pub")
	pub, err := ParsePublicKey(string(pubBytes))
	if err != nil {
		t.Fatalf("Could not parse public key: %s", err)
	}
	fmt.Println(pub)

}

func TestSignCert(t *testing.T) {
	ca, _ := NewCA()
	pubBytes, _ := ioutil.ReadFile("testkeys.pub")
	pub, _ := ParsePublicKey(string(pubBytes))
	signArgs := NewSigningArguments([]string{"root"})

	cert, err := ca.SignCert(pub, signArgs)
	if err != nil {
		t.Fatalf("Could nbot sign cert: %s", err)
	}
	fmt.Println(cert.String())
}

func TestGenerateNonce(t *testing.T) {
	r := randomHex()
	if len(r) != 32 {
		t.Fatalf("Invalid nonce generated: %s", r)
	}
}
