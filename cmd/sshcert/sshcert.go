package main

import (
	"log"

	"github.com/spf13/cobra"
)

var (
	principal string
)

var RootCmd = &cobra.Command{
	Use:   "sshcert",
	Short: "CLI for generating ssh certificates and signing ssh keys",
}

func Execute() {
	if err := RootCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}

func main() {
	Execute()
}
