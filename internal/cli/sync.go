package cli

import (
	"context"
	"fmt"
	"keyopol-app/internal/cloud"
	"keyopol-app/internal/cloud/aws"
	"keyopol-app/internal/crypto"
	"keyopol-app/internal/domain"
	"keyopol-app/internal/storage/sqlite"
	"keyopol-app/internal/sync"

	"github.com/spf13/cobra"
)

// NewPushCommand creates the push command
func NewPushCommand() *cobra.Command {
	var (
		project     string
		environment string
		scope       string
		key         string
	)

	cmd := &cobra.Command{
		Use:   "push cloud",
		Short: "Push secrets to cloud storage",
		Long: `Push encrypted secrets to cloud storage (AWS Secrets Manager).
Secrets are uploaded in their encrypted form - AWS never sees plaintext.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Check if cloud is enabled
			if !cloud.IsCloudEnabled() {
				return fmt.Errorf("cloud sync is not enabled. Run: keyopol cloud enable aws")
			}

			// Initialize stores
			localStore, err := sqlite.NewAdapter("")
			if err != nil {
				return fmt.Errorf("failed to initialize local store: %w", err)
			}
			defer localStore.Close()

			// Get cloud config
			config, err := cloud.GetConfig()
			if err != nil {
				return fmt.Errorf("failed to get cloud config: %w", err)
			}

			awsSettings, err := cloud.GetAWSSettings(config)
			if err != nil {
				return fmt.Errorf("failed to get AWS settings: %w", err)
			}

			// Initialize cloud provider
			cloudStore, err := aws.NewSecretsManagerAdapter(awsSettings.Region, awsSettings.Profile)
			if err != nil {
				return fmt.Errorf("failed to initialize AWS: %w", err)
			}

			// Build filter
			filter := domain.Filter{
				Project:     project,
				Environment: environment,
				Scope:       scope,
				Key:         key,
			}

			// Push secrets
			engine := sync.NewPushEngine(localStore, cloudStore)
			result, err := engine.Push(context.Background(), filter)
			if err != nil {
				return fmt.Errorf("push failed: %w", err)
			}

			// Display results
			fmt.Println(result.Summary())

			if result.PushedSecrets > 0 {
				fmt.Printf("\n✓ Successfully pushed %d secret(s) to AWS\n", result.PushedSecrets)
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&project, "project", "", "Filter by project")
	cmd.Flags().StringVar(&environment, "env", "", "Filter by environment")
	cmd.Flags().StringVar(&scope, "scope", "", "Filter by scope")
	cmd.Flags().StringVar(&key, "key", "", "Push specific key only")

	return cmd
}

// NewPullCommand creates the pull command
func NewPullCommand() *cobra.Command {
	var (
		project      string
		environment  string
		scope        string
		conflictMode string
	)

	cmd := &cobra.Command{
		Use:   "pull cloud",
		Short: "Pull secrets from cloud storage",
		Long: `Pull encrypted secrets from cloud storage (AWS Secrets Manager).
Secrets are downloaded in encrypted form and stored locally.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Check if cloud is enabled
			if !cloud.IsCloudEnabled() {
				return fmt.Errorf("cloud sync is not enabled. Run: keyopol cloud enable aws")
			}

			// Check master key
			masterKey := crypto.GetMasterKey()
			if masterKey == "" {
				return fmt.Errorf("master key not found. Set KEYOPOL_MASTER_KEY environment variable")
			}

			// Initialize stores
			localStore, err := sqlite.NewAdapter("")
			if err != nil {
				return fmt.Errorf("failed to initialize local store: %w", err)
			}
			defer localStore.Close()

			// Get cloud config
			config, err := cloud.GetConfig()
			if err != nil {
				return fmt.Errorf("failed to get cloud config: %w", err)
			}

			awsSettings, err := cloud.GetAWSSettings(config)
			if err != nil {
				return fmt.Errorf("failed to get AWS settings: %w", err)
			}

			// Initialize cloud provider
			cloudStore, err := aws.NewSecretsManagerAdapter(awsSettings.Region, awsSettings.Profile)
			if err != nil {
				return fmt.Errorf("failed to initialize AWS: %w", err)
			}

			// Build filter
			filter := domain.Filter{
				Project:     project,
				Environment: environment,
				Scope:       scope,
			}

			// Determine conflict resolution mode
			mode := sync.ConflictModeNewestWins
			switch conflictMode {
			case "cloud":
				mode = sync.ConflictModeCloudWins
			case "local":
				mode = sync.ConflictModeLocalWins
			case "newest":
				mode = sync.ConflictModeNewestWins
			default:
				if conflictMode != "" {
					return fmt.Errorf("invalid conflict mode: %s (use: cloud, local, or newest)", conflictMode)
				}
			}

			// Pull secrets
			engine := sync.NewPullEngine(localStore, cloudStore)
			result, err := engine.Pull(context.Background(), filter, mode)
			if err != nil {
				return fmt.Errorf("pull failed: %w", err)
			}

			// Display results
			fmt.Println(result.Summary())

			totalSynced := result.PulledSecrets + result.UpdatedSecrets
			if totalSynced > 0 {
				fmt.Printf("\n✓ Successfully pulled %d secret(s) from AWS\n", totalSynced)
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&project, "project", "", "Filter by project")
	cmd.Flags().StringVar(&environment, "env", "", "Filter by environment")
	cmd.Flags().StringVar(&scope, "scope", "", "Filter by scope")
	cmd.Flags().StringVar(&conflictMode, "conflict", "newest", "Conflict resolution: cloud, local, or newest")

	return cmd
}
