package commands

import (
	"github.com/spf13/cobra"
)

var (
	cliName = "sso-cli"
)

func init() {
	cobra.OnInitialize(initConfig)
}

func initConfig() {
}

// NewRootCommand register all command group
func NewRootCommand(args []string) *cobra.Command {

	var command = &cobra.Command{
		Use:   cliName,
		Short: "sso-cli is an application for demonstrating how to use oauth2 flow login in cli",
		Run: func(c *cobra.Command, args []string) {

			c.HelpFunc()(c, args)
		},
	}

	flags := command.PersistentFlags()

	command.AddCommand(
		NewLoginCmd(),
	)

	flags.ParseErrorsWhitelist.UnknownFlags = true
	flags.Parse(args)

	return command
}
