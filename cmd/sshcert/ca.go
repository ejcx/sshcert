package main

import (
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"strings"
	"time"

	"github.com/ejcx/sshcert"
	"github.com/spf13/cobra"
)

var (
	caName         string
	privateKeyFile string
	publicKeyFile  string
	principals     string
	duration       string
)

var caCmd = &cobra.Command{
	Use:   "ca-create",
	Short: "Create a new certificate authority",
	Run: func(cmd *cobra.Command, args []string) {
		CACreate(cmd, args)
	},
}

var signCmd = &cobra.Command{
	Use:   "sign",
	Short: "Sign an ssh public key to create a certificate",
	Run: func(cmd *cobra.Command, args []string) {
		SignCert(cmd, args)
	},
}

func init() {
	signCmd.Flags().StringVar(&privateKeyFile, "private-key", "", "The private key used to sign the public key.")
	signCmd.Flags().StringVar(&publicKeyFile, "public-key", "", "The public key that is being signed.")
	signCmd.Flags().StringVar(&principals, "principals", "", "Comma delimited list of principals (linux users)")
	signCmd.Flags().StringVar(&duration, "duration", "30m", "Duration of certificate validity.")
	signCmd.MarkFlagRequired("private-key")
	signCmd.MarkFlagRequired("public-key")
	signCmd.MarkFlagRequired("principals")

	caCmd.Flags().StringVar(&caName, "name", "", "The name of the certificate authority keys")

	RootCmd.AddCommand(caCmd)
	RootCmd.AddCommand(signCmd)
}

func CACreate(cmd *cobra.Command, args []string) {
	ca, err := sshcert.NewCA()
	if err != nil {
		log.Fatalf("Could not create new ca: %s", err)
	}
	if caName == "" {
		buf := make([]byte, 16)
		rand.Read(buf)
		caName = hex.EncodeToString(buf)
	}
	pubFile := fmt.Sprintf("%s.pub", caName)
	privDer, err := x509.MarshalECPrivateKey(ca.PrivateKey)
	if err != nil {
		log.Fatalf("Could not marshal private ssh ca key: %s", err)
	}
	privBlock := pem.Block{
		Type:    "BEGIN SSHCERT PRIVATE KEY",
		Headers: nil,
		Bytes:   privDer,
	}
	privatePEM := pem.EncodeToMemory(&privBlock)
	errPub := ioutil.WriteFile(pubFile, []byte(ca.String()), 0600)
	errPriv := ioutil.WriteFile(caName, privatePEM, 0600)
	if errPub != nil {
		log.Fatalf("Could not write public key file: %s", err)
	}
	if errPriv != nil {
		log.Fatalf("Could not write private key file: %s", err)
	}
	fmt.Printf("Wrote public key file to %s\n", pubFile)
	fmt.Printf("Wrote private key file to %s\n", caName)
}

func SignCert(cmd *cobra.Command, args []string) {
	var (
		ca sshcert.CA
	)
	privateKeyBytes, err := ioutil.ReadFile(privateKeyFile)
	if err != nil {
		log.Fatalf("Could not read private key file: %s", err)
	}
	publicKeyBytes, err := ioutil.ReadFile(publicKeyFile)
	if err != nil {
		log.Fatalf("Could not read public key file: %s", err)
	}
	principalsList := strings.Split(principals, ",")

	err = ca.ParsePrivateString(privateKeyBytes)
	if err != nil {
		log.Fatalf("Could not parse private key: %s", err)
	}

	publicKey, err := sshcert.ParsePublicKey(string(publicKeyBytes))
	if err != nil {
		log.Fatalf("Could not parse ssh public key: %s", err)
	}
	signingArgs := sshcert.NewSigningArguments(principalsList)
	d, err := time.ParseDuration(duration)
	if err != nil {
		log.Fatalf("Could not parse duration: %s", err)
	}
	signingArgs.Duration = d
	certificate, err := ca.SignCert(publicKey, signingArgs)
	if err != nil {
		log.Fatalf("Could not sign public key: %s", err)
	}
	certificateFile := fmt.Sprintf("%s.cert", publicKeyFile)
	err = ioutil.WriteFile(certificateFile, []byte(certificate.String()), 0644)
	if err != nil {
		log.Fatalf("Could not write certificate file: %s", err)
	}
}
