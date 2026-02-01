package domain

import "time"

// Secret represents a secret value with its metadata and scope
type Secret struct {
	// Core fields
	ID    int64
	Key   string
	Value string // Encrypted or plaintext depending on context

	// Hierarchical scoping
	Project     string
	Environment string // e.g., dev, staging, prod
	Scope       string // Optional sub-category (e.g., database, api, oauth)

	// Secret type
	IsShared bool // True if encrypted with KMS, false if local master password

	// Cloud sync metadata
	CloudSynced bool      // True if pushed to cloud
	LastSyncAt  time.Time // Last cloud sync timestamp

	// UI state (transient)
	IsVisible bool // For TUI visibility toggle

	// Timestamps
	CreatedAt time.Time
	UpdatedAt time.Time
}

// Path returns the hierarchical path of the secret
// Format: project/environment/scope/key or project/environment/key
func (s *Secret) Path() string {
	if s.Scope != "" {
		return s.Project + "/" + s.Environment + "/" + s.Scope + "/" + s.Key
	}
	return s.Project + "/" + s.Environment + "/" + s.Key
}

// CloudPath returns the AWS Secrets Manager compatible path
// Format: keyopol/{project}/{environment}/{scope}/{key}
func (s *Secret) CloudPath() string {
	path := "keyopol/" + s.Project + "/" + s.Environment
	if s.Scope != "" {
		path += "/" + s.Scope
	}
	return path + "/" + s.Key
}

// IsLocal returns true if this is a local (non-shared) secret
func (s *Secret) IsLocal() bool {
	return !s.IsShared
}

// NeedsSync returns true if the secret has local changes not synced to cloud
func (s *Secret) NeedsSync() bool {
	return !s.CloudSynced || s.UpdatedAt.After(s.LastSyncAt)
}
