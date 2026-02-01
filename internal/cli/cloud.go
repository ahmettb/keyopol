package cli

import (
	"fmt"
	"keyopol-app/internal/cloud"

	"github.com/spf13/cobra"
)

// NewCloudCommand creates the cloud command
func NewCloudCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cloud",
		Short: "Manage cloud provider configuration",
		Long:  "Enable or disable cloud sync and configure cloud providers (AWS, GCP, Azure)",
	}

	cmd.AddCommand(newCloudEnableCommand())
	cmd.AddCommand(newCloudDisableCommand())
	cmd.AddCommand(newCloudStatusCommand())

	return cmd
}

func newCloudEnableCommand() *cobra.Command {
	var (
		region   string
		profile  string
		kmsKeyID string
	)

	cmd := &cobra.Command{
		Use:   "enable [provider]",
		Short: "Enable cloud sync",
		Long:  "Enable cloud sync with the specified provider (currently only 'aws' is supported)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			provider := args[0]

			if provider != "aws" {
				return fmt.Errorf("unsupported provider: %s (only 'aws' is currently supported)", provider)
			}

			if err := cloud.EnableAWS(region, profile, kmsKeyID); err != nil {
				return fmt.Errorf("failed to enable AWS: %w", err)
			}

			fmt.Println("✓ Cloud sync enabled with AWS")
			fmt.Printf("  Region: %s\n", region)
			if profile != "" {
				fmt.Printf("  Profile: %s\n", profile)
			}
			if kmsKeyID != "" {
				fmt.Printf("  KMS Key: %s\n", kmsKeyID)
			}

			fmt.Println("\nYou can now use:")
			fmt.Println("  keyopol push cloud      - Push secrets to AWS")
			fmt.Println("  keyopol pull cloud      - Pull secrets from AWS")

			return nil
		},
	}

	cmd.Flags().StringVar(&region, "region", "us-east-1", "AWS region")
	cmd.Flags().StringVar(&profile, "profile", "", "AWS CLI profile (optional)")
	cmd.Flags().StringVar(&kmsKeyID, "kms-key", "", "Custom KMS key ID for shared secrets (optional)")

	return cmd
}

func newCloudDisableCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "disable",
		Short: "Disable cloud sync",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := cloud.DisableCloud(); err != nil {
				return fmt.Errorf("failed to disable cloud: %w", err)
			}

			fmt.Println("✓ Cloud sync disabled")
			return nil
		},
	}
}

func newCloudStatusCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show cloud configuration status",
		RunE: func(cmd *cobra.Command, args []string) error {
			config, err := cloud.GetConfig()
			if err != nil {
				return fmt.Errorf("failed to get cloud config: %w", err)
			}

			if !config.Enabled {
				fmt.Println("Cloud sync: DISABLED")
				fmt.Println("\nTo enable cloud sync, run:")
				fmt.Println("  keyopol cloud enable aws")
				return nil
			}

			fmt.Printf("Cloud sync: ENABLED\n")
			fmt.Printf("Provider: %s\n", config.Provider)
			fmt.Println("\nSettings:")
			for key, value := range config.Settings {
				if key != "kmsKeyID" || value != "" {
					fmt.Printf("  %s: %s\n", key, value)
				}
			}

			return nil
		},
	}
}
