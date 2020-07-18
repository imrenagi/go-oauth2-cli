package main

import (
	"log"
	"os"

	"github.com/imrenagi/go-oauth2-cli/cmd/commands"
)

func main() {
	cmd := commands.NewRootCommand(os.Args[1:])

	err := cmd.Execute()
	if err != nil {
		log.Fatalf("Unable to execute application command")
	}
}
