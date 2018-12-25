// Copyright © 2018 NAME HERE <EMAIL ADDRESS>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"fmt"
	"io/ioutil"
	"log"

	"github.com/ejcx/sshcert"
	"github.com/spf13/cobra"
)

var (
	principal string
)

var RootCmd = &cobra.Command{
	Use:   "sshcert",
	Short: "Generate a toy ssh cert configuration",
	Run: func(cmd *cobra.Command, args []string) {
		Main(cmd, args)
	},
}

func init() {
	RootCmd.Flags().StringVar(&principal, "principal", "", "The linux user for logging in.")
	RootCmd.MarkFlagRequired("principal")

}

func Execute() {
	if err := RootCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}

func main() {
	Execute()
}

func Main(cmd *cobra.Command, args []string) {
	ca, err := sshcert.NewCA()
	if err != nil {
		log.Fatalf("Could not create CA: %s", err)
	}
	signArgs := sshcert.NewSigningArguments([]string{principal})
	buf, err := ioutil.ReadFile("pockey.pub")
	if err != nil {
		log.Fatalf("Could not read pubkey.pub: %s", err)
	}
	pub, err := sshcert.ParsePublicKey(string(buf))
	if err != nil {
		log.Fatalf("Could not parse public key: %s", err)
	}
	sshcert, err := ca.SignCert(pub, signArgs)
	if err != nil {
		log.Fatalf("Could not sign cert: %s", err)
	}
	fmt.Println(ca.String())
	fmt.Println(sshcert)
}
