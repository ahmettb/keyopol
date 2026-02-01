package aws

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// KMSClient implements domain.KMSProvider using AWS KMS
type KMSClient struct {
	client *kms.Client
	keyID  string
}

// NewKMSClient creates a new AWS KMS client
func NewKMSClient(region, profile, keyID string) (*KMSClient, error) {
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

	client := kms.NewFromConfig(cfg)

	// If no key ID specified, use default alias
	if keyID == "" {
		keyID = "alias/keyopol-shared-secrets"
	}

	return &KMSClient{
		client: client,
		keyID:  keyID,
	}, nil
}

// EncryptWithKMS encrypts data using AWS KMS
func (k *KMSClient) EncryptWithKMS(ctx context.Context, plaintext []byte, keyID string) ([]byte, error) {
	if keyID == "" {
		keyID = k.keyID
	}

	output, err := k.client.Encrypt(ctx, &kms.EncryptInput{
		KeyId:     aws.String(keyID),
		Plaintext: plaintext,
	})

	if err != nil {
		return nil, fmt.Errorf("KMS encryption failed: %w", err)
	}

	return output.CiphertextBlob, nil
}

// DecryptWithKMS decrypts data using AWS KMS
func (k *KMSClient) DecryptWithKMS(ctx context.Context, ciphertext []byte) ([]byte, error) {
	output, err := k.client.Decrypt(ctx, &kms.DecryptInput{
		CiphertextBlob: ciphertext,
	})

	if err != nil {
		return nil, fmt.Errorf("KMS decryption failed: %w", err)
	}

	return output.Plaintext, nil
}

// GenerateDataKey generates a data key for envelope encryption
func (k *KMSClient) GenerateDataKey(ctx context.Context, keyID string) (plaintext, encrypted []byte, err error) {
	if keyID == "" {
		keyID = k.keyID
	}

	output, err := k.client.GenerateDataKey(ctx, &kms.GenerateDataKeyInput{
		KeyId:   aws.String(keyID),
		KeySpec: "AES_256",
	})

	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate data key: %w", err)
	}

	return output.Plaintext, output.CiphertextBlob, nil
}

// CreateKey creates a new KMS key for keyopol shared secrets
func (k *KMSClient) CreateKey(ctx context.Context, description string) (string, error) {
	if description == "" {
		description = "Keyopol shared secrets encryption key"
	}

	output, err := k.client.CreateKey(ctx, &kms.CreateKeyInput{
		Description: aws.String(description),
		KeyUsage:    "ENCRYPT_DECRYPT",
		Tags: []types.Tag{
			{
				TagKey:   aws.String("Application"),
				TagValue: aws.String("keyopol"),
			},
			{
				TagKey:   aws.String("Purpose"),
				TagValue: aws.String("shared-secrets"),
			},
		},
	})

	if err != nil {
		return "", fmt.Errorf("failed to create KMS key: %w", err)
	}

	keyID := aws.ToString(output.KeyMetadata.KeyId)

	// Create alias
	aliasName := "alias/keyopol-shared-secrets"
	_, err = k.client.CreateAlias(ctx, &kms.CreateAliasInput{
		AliasName:   aws.String(aliasName),
		TargetKeyId: aws.String(keyID),
	})

	if err != nil {
		// Key was created but alias failed - non-fatal
		fmt.Printf("Warning: KMS key created but failed to create alias: %v\n", err)
		return keyID, nil
	}

	return keyID, nil
}
