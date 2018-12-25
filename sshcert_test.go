package sshcert

import (
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

func TestNewCA(t *testing.T) {
	_, err := NewCA()
	if err != nil {
		t.Fatalf("Could not create ca: %s", err)
	}
}

func TestPublicKeyString(t *testing.T) {
	ca, _ := NewCA()
	_, err := ParsePublicKey(ca.String())
	if err != nil {
		t.Fatalf("Could not parse public key: %s", err)
	}
}

func TestParsePublicKey(t *testing.T) {
	pubBytes, _ := ioutil.ReadFile("testfiles/testkeys.pub")
	_, err := ParsePublicKey(string(pubBytes))
	if err != nil {
		t.Fatalf("Could not parse public key: %s", err)
	}

}

func TestSignCert(t *testing.T) {
	ca, _ := NewCA()
	pubBytes, _ := ioutil.ReadFile("testfiles/testkeys.pub")
	pub, _ := ParsePublicKey(string(pubBytes))
	signArgs := NewSigningArguments([]string{"root"})

	_, err := ca.SignCert(pub, signArgs)
	if err != nil {
		t.Fatalf("Could not sign cert: %s", err)
	}
}

func TestGenerateNonce(t *testing.T) {
	r := randomHex()
	if len(r) != 32 {
		t.Fatalf("Invalid nonce generated: %s", r)
	}
}

func TestMarshalUnmarshal(t *testing.T) {
	ca, _ := NewCA()
	buf, err := ca.Marshal()
	if err != nil {
		t.Fatalf("Could not marshal ca: %s", err)
	}
	ca2, err := UnmarshalCA(buf)
	if err != nil {
		t.Fatalf("Could not unmarshal ca: %s", err)
	}
	if ca.PrivateKey.D.Cmp(ca2.PrivateKey.D) != 0 {
		t.Fatal("The private keys are different after marshal/unmarshal")
	}
}
