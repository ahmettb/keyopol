package domain

import "context"

// SecretStore defines the interface for secret persistence
// Can be implemented by SQLite, AWS Secrets Manager, etc.
type SecretStore interface {
	// Create a new secret
	Create(ctx context.Context, secret *Secret) error

	// Get a single secret by filter (requires exact match)
	Get(ctx context.Context, filter Filter) (*Secret, error)

	// List all secrets matching the filter
	List(ctx context.Context, filter Filter) ([]*Secret, error)

	// Update an existing secret
	Update(ctx context.Context, secret *Secret) error

	// Delete a secret matching the filter
	Delete(ctx context.Context, filter Filter) error

	// Close the store connection
	Close() error
}

// CloudProvider defines the interface for cloud secret storage
type CloudProvider interface {
	// Push a secret to cloud storage (encrypted blob)
	Push(ctx context.Context, secret *Secret) error

	// Pull secrets from cloud storage matching the filter
	Pull(ctx context.Context, filter Filter) ([]*Secret, error)

	// Delete a secret from cloud storage
	Delete(ctx context.Context, filter Filter) error

	// Check if cloud is configured and accessible
	IsConfigured() bool

	// GetProviderName returns the name of the provider (e.g., "aws")
	GetProviderName() string
}

// Encryptor defines the interface for encryption operations
type Encryptor interface {
	// Encrypt plaintext using the given key
	Encrypt(plaintext, key string) (string, error)

	// Decrypt ciphertext using the given key
	Decrypt(ciphertext, key string) (string, error)
}

// KMSProvider defines the interface for KMS operations
type KMSProvider interface {
	// Encrypt data using KMS
	EncryptWithKMS(ctx context.Context, plaintext []byte, keyID string) ([]byte, error)

	// Decrypt data using KMS
	DecryptWithKMS(ctx context.Context, ciphertext []byte) ([]byte, error)

	// Generate a data key for envelope encryption
	GenerateDataKey(ctx context.Context, keyID string) (plaintext, encrypted []byte, err error)
}

// Project represents a project grouping
type Project struct {
	ID   int64
	Name string
}

// ProjectStore defines operations for project management
type ProjectStore interface {
	// Create a new project
	CreateProject(ctx context.Context, name string) error

	// List all projects
	ListProjects(ctx context.Context) ([]*Project, error)

	// Update project name
	UpdateProject(ctx context.Context, oldName, newName string) error

	// Delete a project and all its secrets
	DeleteProject(ctx context.Context, name string) error
}
