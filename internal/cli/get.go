package cli

import (
	"context"
	"fmt"
	"keyopol-app/internal/cloud"
	"keyopol-app/internal/cloud/aws"
	"keyopol-app/internal/crypto"
	"keyopol-app/internal/domain"
	"keyopol-app/internal/storage/sqlite"

	"github.com/spf13/cobra"
)

// NewGetCommand creates the get command for retrieving secret values
func NewGetCommand() *cobra.Command {
	var (
		project     string
		environment string
		scope       string
		showValue   bool // Whether to display the secret value or just metadata
	)

	cmd := &cobra.Command{
		Use:   "get [key]",
		Short: "Get a secret value",
		Long: `Retrieve and decrypt a secret value.
For personal secrets: uses your master password
For shared secrets: uses AWS KMS (requires IAM permissions)`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			key := args[0]

			if project == "" {
				return fmt.Errorf("--project is required")
			}

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

			// Build filter
			filter := domain.Filter{
				Project:     project,
				Environment: environment,
				Scope:       scope,
				Key:         key,
			}

			// Get secret from local store
			secret, err := store.Get(ctx, filter)
			if err != nil {
				return fmt.Errorf("secret not found: %w", err)
			}

			// Display metadata
			fmt.Printf("Secret: %s\n", secret.Path())
			fmt.Printf("Type: ")
			if secret.IsShared {
				fmt.Println("Shared (KMS)")
			} else {
				fmt.Println("Personal")
			}
			fmt.Printf("Created: %s\n", secret.CreatedAt.Format("2006-01-02 15:04:05"))
			fmt.Printf("Updated: %s\n", secret.UpdatedAt.Format("2006-01-02 15:04:05"))
			fmt.Printf("Cloud Synced: %v\n", secret.CloudSynced)

			if !showValue {
				fmt.Println("\nTo see the value, use --show-value flag")
				return nil
			}

			// Decrypt and show value
			var plaintext string

			if secret.IsShared {
				// Shared secret - decrypt with KMS
				plaintext, err = decryptSharedSecret(ctx, secret)
				if err != nil {
					return fmt.Errorf("failed to decrypt shared secret: %w", err)
				}
			} else {
				// Personal secret - decrypt with master password
				plaintext, err = decryptPersonalSecret(secret)
				if err != nil {
					return fmt.Errorf("failed to decrypt personal secret: %w", err)
				}
			}

			fmt.Printf("\nValue: %s\n", plaintext)

			return nil
		},
	}

	cmd.Flags().StringVar(&project, "project", "", "Project name (required)")
	cmd.Flags().StringVar(&environment, "env", "default", "Environment")
	cmd.Flags().StringVar(&scope, "scope", "", "Scope")
	cmd.Flags().BoolVar(&showValue, "show-value", false, "Display the decrypted secret value")

	cmd.MarkFlagRequired("project")

	return cmd
}

func decryptPersonalSecret(secret *domain.Secret) (string, error) {
	// Get master password
	masterPassword, err := crypto.GetMasterPasswordSecure()
	if err != nil {
		return "", fmt.Errorf("failed to get master password: %w", err)
	}

	// Decrypt
	encryptor := crypto.NewLocalEncryptor()
	plaintext, err := encryptor.Decrypt(secret.Value, masterPassword)
	if err != nil {
		return "", fmt.Errorf("decryption failed (wrong password?): %w", err)
	}

	return plaintext, nil
}

func decryptSharedSecret(ctx context.Context, secret *domain.Secret) (string, error) {
	// Check if value is envelope encrypted
	if !crypto.IsEnvelopeEncrypted(secret.Value) {
		return "", fmt.Errorf("shared secret is not envelope encrypted")
	}

	// Get cloud config
	config, err := cloud.GetConfig()
	if err != nil {
		return "", fmt.Errorf("failed to get cloud config: %w", err)
	}

	awsSettings, err := cloud.GetAWSSettings(config)
	if err != nil {
		return "", fmt.Errorf("failed to get AWS settings: %w", err)
	}

	// Initialize KMS client
	kmsClient, err := aws.NewKMSClient(awsSettings.Region, awsSettings.Profile, awsSettings.KMSKeyID)
	if err != nil {
		return "", fmt.Errorf("failed to initialize KMS: %w", err)
	}

	// Decrypt with envelope
	plaintext, err := crypto.DecryptWithEnvelope(ctx, secret.Value, kmsClient)
	if err != nil {
		return "", fmt.Errorf("envelope decryption failed (check IAM permissions): %w", err)
	}

	return plaintext, nil
}
