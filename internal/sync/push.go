package sync

import (
	"context"
	"fmt"
	"keyopol-app/internal/domain"
	"time"
)

// PushEngine handles pushing secrets to cloud
type PushEngine struct {
	localStore domain.SecretStore
	cloudStore domain.CloudProvider
}

// NewPushEngine creates a new push engine
func NewPushEngine(localStore domain.SecretStore, cloudStore domain.CloudProvider) *PushEngine {
	return &PushEngine{
		localStore: localStore,
		cloudStore: cloudStore,
	}
}

// Push pushes secrets matching the filter to cloud
func (e *PushEngine) Push(ctx context.Context, filter domain.Filter) (*PushResult, error) {
	if !e.cloudStore.IsConfigured() {
		return nil, fmt.Errorf("cloud provider not configured")
	}

	// Get secrets from local store
	secrets, err := e.localStore.List(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to list local secrets: %w", err)
	}

	result := &PushResult{
		TotalSecrets:   len(secrets),
		PushedSecrets:  0,
		SkippedSecrets: 0,
		FailedSecrets:  0,
		Errors:         make(map[string]error),
	}

	for _, secret := range secrets {
		// Skip shared secrets (they should be managed via KMS directly)
		if secret.IsShared {
			result.SkippedSecrets++
			result.Errors[secret.Path()] = fmt.Errorf("shared secrets are not pushed (managed via KMS)")
			continue
		}

		// Push to cloud (secret.Value is already encrypted locally)
		if err := e.cloudStore.Push(ctx, secret); err != nil {
			result.FailedSecrets++
			result.Errors[secret.Path()] = err
			continue
		}

		// Update sync metadata
		secret.CloudSynced = true
		secret.LastSyncAt = time.Now()

		if err := e.localStore.Update(ctx, secret); err != nil {
			// Non-fatal: secret was pushed but metadata update failed
			fmt.Printf("Warning: secret pushed but failed to update sync metadata: %v\n", err)
		}

		result.PushedSecrets++
	}

	return result, nil
}

// PushResult contains the result of a push operation
type PushResult struct {
	TotalSecrets   int
	PushedSecrets  int
	SkippedSecrets int
	FailedSecrets  int
	Errors         map[string]error
}

// Summary returns a human-readable summary
func (r *PushResult) Summary() string {
	summary := fmt.Sprintf("Push complete: %d total, %d pushed, %d skipped, %d failed",
		r.TotalSecrets, r.PushedSecrets, r.SkippedSecrets, r.FailedSecrets)

	if len(r.Errors) > 0 {
		summary += "\n\nErrors:"
		for path, err := range r.Errors {
			summary += fmt.Sprintf("\n  %s: %v", path, err)
		}
	}

	return summary
}
