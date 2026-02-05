package cli

import (
	"keyopol-app/internal/api"
	"keyopol-app/internal/store"

	"github.com/spf13/cobra"
)

func NewServeCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "serve",
		Short: "Start the web API server",
		Run: func(cmd *cobra.Command, args []string) {
			db := store.InitDB()
			server := api.NewServer(db)
			server.Start(":8080")
		},
	}
}
