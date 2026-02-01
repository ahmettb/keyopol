package cli

import (
	"context"
	"fmt"
	"keyopol-app/internal/cloud"
	"keyopol-app/internal/cloud/aws"
	"keyopol-app/internal/crypto"
	"keyopol-app/internal/domain"
	"keyopol-app/internal/storage/sqlite"
	"time"

	"github.com/spf13/cobra"
)

// NewSecretCommand creates the secret command
func NewSecretCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "secret",
		Short: "Manage secrets",
		Long:  "Add, list, update, and delete secrets with support for shared (KMS) secrets",
	}

	cmd.AddCommand(newSecretAddCommand())
	cmd.AddCommand(newSecretListCommand())

	return cmd
}

func newSecretAddCommand() *cobra.Command {
	var (
		project     string
		environment string
		scope       string
		key         string
		value       string
		shared      bool
	)

	cmd := &cobra.Command{
		Use:   "add",
		Short: "Add a new secret",
		Long: `Add a new secret to keyopol.
		
Personal secrets are encrypted with your master password.
Shared secrets are encrypted with AWS KMS (requires --shared flag).`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Validate required fields
			if project == "" || key == "" || value == "" {
				return fmt.Errorf("--project, --key, and --value are required")
			}

			// Default environment
			if environment == "" {
				environment = "default"
			}

			// Initialize store
			store, err := sqlite.NewAdapter("")
			if err != nil {
				return fmt.Errorf("failed to initialize store: %w", err)
			}
			defer store.Close()

			ctx := context.Background()

			if shared {
				// Shared secret - use KMS
				return addSharedSecret(ctx, store, project, environment, scope, key, value)
			} else {
				// Personal secret - use master password
				return addPersonalSecret(ctx, store, project, environment, scope, key, value)
			}
		},
	}

	cmd.Flags().StringVar(&project, "project", "", "Project name (required)")
	cmd.Flags().StringVar(&environment, "env", "default", "Environment (default: default)")
	cmd.Flags().StringVar(&scope, "scope", "", "Scope (optional)")
	cmd.Flags().StringVar(&key, "key", "", "Secret key name (required)")
	cmd.Flags().StringVar(&value, "value", "", "Secret value (required)")
	cmd.Flags().BoolVar(&shared, "shared", false, "Create as shared secret using KMS")

	cmd.MarkFlagRequired("project")
	cmd.MarkFlagRequired("key")
	cmd.MarkFlagRequired("value")

	return cmd
}

func addPersonalSecret(ctx context.Context, store *sqlite.Adapter, project, environment, scope, key, value string) error {
	// Get master key
	masterKey := crypto.GetMasterKey()
	if masterKey == "" {
		return fmt.Errorf("master key not found. Set KEYOPOL_MASTER_KEY environment variable")
	}

	// Encrypt value
	encryptor := crypto.NewLocalEncryptor()
	encryptedValue, err := encryptor.Encrypt(value, masterKey)
	if err != nil {
		return fmt.Errorf("encryption failed: %w", err)
	}

	// Create secret
	secret := &domain.Secret{
		Project:     project,
		Environment: environment,
		Scope:       scope,
		Key:         key,
		Value:       encryptedValue,
		IsShared:    false,
		CloudSynced: false,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	if err := store.Create(ctx, secret); err != nil {
		return fmt.Errorf("failed to create secret: %w", err)
	}

	fmt.Printf("✓ Personal secret added: %s\n", secret.Path())
	fmt.Println("\nTo sync to cloud, run:")
	fmt.Printf("  keyopol push cloud --project %s\n", project)

	return nil
}

func addSharedSecret(ctx context.Context, store *sqlite.Adapter, project, environment, scope, key, value string) error {
	// Check if cloud is enabled
	if !cloud.IsCloudEnabled() {
		return fmt.Errorf("shared secrets require cloud sync. Run: keyopol cloud enable aws")
	}

	// Get cloud config
	config, err := cloud.GetConfig()
	if err != nil {
		return fmt.Errorf("failed to get cloud config: %w", err)
	}

	awsSettings, err := cloud.GetAWSSettings(config)
	if err != nil {
		return fmt.Errorf("failed to get AWS settings: %w", err)
	}

	// Initialize KMS client
	kmsClient, err := aws.NewKMSClient(awsSettings.Region, awsSettings.Profile, awsSettings.KMSKeyID)
	if err != nil {
		return fmt.Errorf("failed to initialize KMS: %w", err)
	}

	// Encrypt with KMS
	encryptedValue, err := kmsClient.EncryptWithKMS(ctx, []byte(value), "")
	if err != nil {
		return fmt.Errorf("KMS encryption failed: %w", err)
	}

	// Store encrypted value in AWS Secrets Manager
	cloudStore, err := aws.NewSecretsManagerAdapter(awsSettings.Region, awsSettings.Profile)
	if err != nil {
		return fmt.Errorf("failed to initialize AWS: %w", err)
	}

	secret := &domain.Secret{
		Project:     project,
		Environment: environment,
		Scope:       scope,
		Key:         key,
		Value:       string(encryptedValue),
		IsShared:    true,
		CloudSynced: true,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	// Push to cloud
	if err := cloudStore.Push(ctx, secret); err != nil {
		return fmt.Errorf("failed to push to AWS: %w", err)
	}

	// Store metadata locally (without value)
	secret.Value = "" // Don't store KMS-encrypted value locally
	if err := store.Create(ctx, secret); err != nil {
		return fmt.Errorf("failed to create local metadata: %w", err)
	}

	fmt.Printf("✓ Shared secret added (KMS): %s\n", secret.CloudPath())
	fmt.Println("  Encrypted with AWS KMS")
	fmt.Println("  Stored in AWS Secrets Manager")
	fmt.Println("  Access controlled by IAM policies")

	return nil
}

func newSecretListCommand() *cobra.Command {
	var (
		project     string
		environment string
		scope       string
		showShared  bool
	)

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List secrets",
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := sqlite.NewAdapter("")
			if err != nil {
				return fmt.Errorf("failed to initialize store: %w", err)
			}
			defer store.Close()

			filter := domain.Filter{
				Project:     project,
				Environment: environment,
				Scope:       scope,
			}

			if showShared {
				filter.OnlyShared = true
			}

			secrets, err := store.List(context.Background(), filter)
			if err != nil {
				return fmt.Errorf("failed to list secrets: %w", err)
			}

			if len(secrets) == 0 {
				fmt.Println("No secrets found")
				return nil
			}

			fmt.Printf("Found %d secret(s):\n\n", len(secrets))
			for _, s := range secrets {
				typeStr := "personal"
				if s.IsShared {
					typeStr = "shared (KMS)"
				}
				fmt.Printf("  %s [%s]\n", s.Path(), typeStr)
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&project, "project", "", "Filter by project")
	cmd.Flags().StringVar(&environment, "env", "", "Filter by environment")
	cmd.Flags().StringVar(&scope, "scope", "", "Filter by scope")
	cmd.Flags().BoolVar(&showShared, "shared", false, "Show only shared secrets")

	return cmd
}
