package aws

import (
	"context"
	"fmt"
	"keyopol-app/internal/domain"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager"
	"github.com/aws/aws-sdk-go-v2/service/secretsmanager/types"
)

// SecretsManagerAdapter implements domain.CloudProvider using AWS Secrets Manager
type SecretsManagerAdapter struct {
	client *secretsmanager.Client
	region string
}

// NewSecretsManagerAdapter creates a new AWS Secrets Manager adapter
func NewSecretsManagerAdapter(region, profile string) (*SecretsManagerAdapter, error) {
	ctx := context.Background()

	var opts []func(*config.LoadOptions) error

	if region != "" {
		opts = append(opts, config.WithRegion(region))
	}

	if profile != "" {
		opts = append(opts, config.WithSharedConfigProfile(profile))
	}

	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	client := secretsmanager.NewFromConfig(cfg)

	return &SecretsManagerAdapter{
		client: client,
		region: cfg.Region,
	}, nil
}

// Push implements domain.CloudProvider
func (a *SecretsManagerAdapter) Push(ctx context.Context, secret *domain.Secret) error {
	secretName := secretToARN(secret)

	// Check if secret exists
	exists, err := a.secretExists(ctx, secretName)
	if err != nil {
		return fmt.Errorf("failed to check if secret exists: %w", err)
	}

	if exists {
		// Update existing secret
		_, err = a.client.PutSecretValue(ctx, &secretsmanager.PutSecretValueInput{
			SecretId:     aws.String(secretName),
			SecretString: aws.String(secret.Value), // Already encrypted
		})
		if err != nil {
			return fmt.Errorf("failed to update secret: %w", err)
		}
	} else {
		// Create new secret
		_, err = a.client.CreateSecret(ctx, &secretsmanager.CreateSecretInput{
			Name:         aws.String(secretName),
			SecretString: aws.String(secret.Value), // Already encrypted
			Description:  aws.String(buildDescription(secret)),
			Tags: []types.Tag{
				{Key: aws.String("keyopol"), Value: aws.String("true")},
				{Key: aws.String("project"), Value: aws.String(secret.Project)},
				{Key: aws.String("environment"), Value: aws.String(secret.Environment)},
				{Key: aws.String("scope"), Value: aws.String(secret.Scope)},
			},
		})
		if err != nil {
			return fmt.Errorf("failed to create secret: %w", err)
		}
	}

	return nil
}

// Pull implements domain.CloudProvider
func (a *SecretsManagerAdapter) Pull(ctx context.Context, filter domain.Filter) ([]*domain.Secret, error) {
	// List all secrets with keyopol tag
	var secrets []*domain.Secret
	var nextToken *string

	for {
		input := &secretsmanager.ListSecretsInput{
			Filters: []types.Filter{
				{
					Key:    types.FilterNameStringTypeTagKey,
					Values: []string{"keyopol"},
				},
			},
			MaxResults: aws.Int32(100),
			NextToken:  nextToken,
		}

		output, err := a.client.ListSecrets(ctx, input)
		if err != nil {
			return nil, fmt.Errorf("failed to list secrets: %w", err)
		}

		for _, secretMeta := range output.SecretList {
			// Parse secret name to extract metadata
			secret, err := a.fetchSecret(ctx, aws.ToString(secretMeta.Name))
			if err != nil {
				// Log error but continue with other secrets
				fmt.Printf("Warning: failed to fetch secret %s: %v\n", aws.ToString(secretMeta.Name), err)
				continue
			}

			// Apply filter
			if filter.Matches(secret) {
				secrets = append(secrets, secret)
			}
		}

		nextToken = output.NextToken
		if nextToken == nil {
			break
		}
	}

	return secrets, nil
}

// Delete implements domain.CloudProvider
func (a *SecretsManagerAdapter) Delete(ctx context.Context, filter domain.Filter) error {
	if filter.Project == "" || filter.Key == "" {
		return fmt.Errorf("project and key are required for delete")
	}

	// Build the secret name
	secret := &domain.Secret{
		Project:     filter.Project,
		Environment: filter.Environment,
		Scope:       filter.Scope,
		Key:         filter.Key,
	}

	if secret.Environment == "" {
		secret.Environment = "default"
	}

	secretName := secretToARN(secret)

	// Delete the secret (with recovery window)
	_, err := a.client.DeleteSecret(ctx, &secretsmanager.DeleteSecretInput{
		SecretId:             aws.String(secretName),
		RecoveryWindowInDays: aws.Int64(7), // 7-day recovery window
	})

	if err != nil {
		return fmt.Errorf("failed to delete secret: %w", err)
	}

	return nil
}

// IsConfigured implements domain.CloudProvider
func (a *SecretsManagerAdapter) IsConfigured() bool {
	return a.client != nil
}

// GetProviderName implements domain.CloudProvider
func (a *SecretsManagerAdapter) GetProviderName() string {
	return "aws"
}

// Helper methods

func (a *SecretsManagerAdapter) secretExists(ctx context.Context, secretName string) (bool, error) {
	_, err := a.client.DescribeSecret(ctx, &secretsmanager.DescribeSecretInput{
		SecretId: aws.String(secretName),
	})

	if err != nil {
		// Check if error is ResourceNotFoundException
		if strings.Contains(err.Error(), "ResourceNotFoundException") {
			return false, nil
		}
		return false, err
	}

	return true, nil
}

func (a *SecretsManagerAdapter) fetchSecret(ctx context.Context, secretName string) (*domain.Secret, error) {
	output, err := a.client.GetSecretValue(ctx, &secretsmanager.GetSecretValueInput{
		SecretId: aws.String(secretName),
	})

	if err != nil {
		return nil, err
	}

	// Parse secret name to extract metadata
	// Format: keyopol/{project}/{environment}/{scope}/{key} or keyopol/{project}/{environment}/{key}
	secret := arnToSecret(secretName)
	secret.Value = aws.ToString(output.SecretString)

	return secret, nil
}

// secretToARN converts a domain.Secret to AWS Secrets Manager name
// Format: keyopol/{project}/{environment}/{scope}/{key}
func secretToARN(secret *domain.Secret) string {
	env := secret.Environment
	if env == "" {
		env = "default"
	}

	path := "keyopol/" + secret.Project + "/" + env

	if secret.Scope != "" {
		path += "/" + secret.Scope
	}

	path += "/" + secret.Key

	return path
}

// arnToSecret converts AWS Secrets Manager name to domain.Secret
func arnToSecret(arn string) *domain.Secret {
	// Remove "keyopol/" prefix
	path := strings.TrimPrefix(arn, "keyopol/")

	parts := strings.Split(path, "/")

	secret := &domain.Secret{}

	if len(parts) >= 3 {
		secret.Project = parts[0]
		secret.Environment = parts[1]

		if len(parts) == 3 {
			// Format: project/env/key
			secret.Key = parts[2]
		} else if len(parts) == 4 {
			// Format: project/env/scope/key
			secret.Scope = parts[2]
			secret.Key = parts[3]
		}
	}

	return secret
}

func buildDescription(secret *domain.Secret) string {
	desc := fmt.Sprintf("Keyopol secret: %s", secret.Path())
	if secret.IsShared {
		desc += " (shared/KMS)"
	} else {
		desc += " (personal/encrypted)"
	}
	return desc
}
