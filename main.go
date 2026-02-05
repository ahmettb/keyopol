package main

import (
	"fmt"
	"keyopol-app/internal/cli"
	"keyopol-app/internal/runner"
	"keyopol-app/internal/ui"
	"os"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/spf13/cobra"
)

var version = "2.0.0-cloud"

func main() {
	rootCmd := &cobra.Command{
		Use:     "keyopol",
		Short:   "Zero-knowledge, local-first secret manager",
		Long:    `Keyopol is a terminal-based secret manager with optional AWS cloud sync.`,
		Version: version,
		Run: func(cmd *cobra.Command, args []string) {
			// No arguments = launch TUI
			p := tea.NewProgram(ui.InitialModel(), tea.WithAltScreen())
			if _, err := p.Run(); err != nil {
				fmt.Printf("Error: %v\n", err)
				os.Exit(1)
			}
		},
	}

	// Legacy commands (backward compatibility)
	rootCmd.AddCommand(&cobra.Command{
		Use:   "run",
		Short: "Run a command with secrets injected as environment variables",
		Long:  "Execute a command with project secrets automatically loaded",
		Run: func(cmd *cobra.Command, args []string) {
			runner.Run()
		},
	})

	// New cloud commands
	rootCmd.AddCommand(cli.NewCloudCommand())
	rootCmd.AddCommand(cli.NewPushCommand())
	rootCmd.AddCommand(cli.NewPullCommand())
	rootCmd.AddCommand(cli.NewSecretCommand())
	rootCmd.AddCommand(cli.NewGetCommand()) // ✓ New secure get command
	rootCmd.AddCommand(cli.NewServeCommand())

	// Execute
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
