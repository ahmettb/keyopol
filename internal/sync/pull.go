package sync

import (
	"context"
	"fmt"
	"keyopol-app/internal/domain"
	"time"
)

// PullEngine handles pulling secrets from cloud
type PullEngine struct {
	localStore domain.SecretStore
	cloudStore domain.CloudProvider
}

// NewPullEngine creates a new pull engine
func NewPullEngine(localStore domain.SecretStore, cloudStore domain.CloudProvider) *PullEngine {
	return &PullEngine{
		localStore: localStore,
		cloudStore: cloudStore,
	}
}

// Pull pulls secrets from cloud matching the filter
func (e *PullEngine) Pull(ctx context.Context, filter domain.Filter, conflictMode ConflictMode) (*PullResult, error) {
	if !e.cloudStore.IsConfigured() {
		return nil, fmt.Errorf("cloud provider not configured")
	}

	// Get secrets from cloud
	cloudSecrets, err := e.cloudStore.Pull(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to pull from cloud: %w", err)
	}

	result := &PullResult{
		TotalSecrets:    len(cloudSecrets),
		PulledSecrets:   0,
		SkippedSecrets:  0,
		UpdatedSecrets:  0,
		ConflictSecrets: 0,
		Errors:          make(map[string]error),
	}

	for _, cloudSecret := range cloudSecrets {
		// Check if secret exists locally
		localFilter := domain.Filter{
			Project:     cloudSecret.Project,
			Environment: cloudSecret.Environment,
			Scope:       cloudSecret.Scope,
			Key:         cloudSecret.Key,
		}

		localSecret, err := e.localStore.Get(ctx, localFilter)

		if err == nil {
			// Secret exists locally - handle conflict
			conflict := e.detectConflict(localSecret, cloudSecret)

			if conflict {
				result.ConflictSecrets++

				resolved, err := e.resolveConflict(ctx, localSecret, cloudSecret, conflictMode)
				if err != nil {
					result.Errors[cloudSecret.Path()] = err
					continue
				}

				if !resolved {
					result.SkippedSecrets++
					result.Errors[cloudSecret.Path()] = fmt.Errorf("conflict: local secret is newer")
					continue
				}
			}

			// Update existing secret
			cloudSecret.ID = localSecret.ID // Preserve local ID
			cloudSecret.CloudSynced = true
			cloudSecret.LastSyncAt = time.Now()

			if err := e.localStore.Update(ctx, cloudSecret); err != nil {
				result.Errors[cloudSecret.Path()] = err
				continue
			}

			result.UpdatedSecrets++
		} else {
			// Secret doesn't exist locally - create it
			cloudSecret.CloudSynced = true
			cloudSecret.LastSyncAt = time.Now()

			if err := e.localStore.Create(ctx, cloudSecret); err != nil {
				result.Errors[cloudSecret.Path()] = err
				continue
			}

			result.PulledSecrets++
		}
	}

	return result, nil
}

// ConflictMode defines how to handle conflicts
type ConflictMode int

const (
	// ConflictModeCloudWins always takes the cloud version
	ConflictModeCloudWins ConflictMode = iota

	// ConflictModeLocalWins always keeps the local version
	ConflictModeLocalWins

	// ConflictModeNewestWins keeps the newest version based on timestamp
	ConflictModeNewestWins
)

func (e *PullEngine) detectConflict(local, cloud *domain.Secret) bool {
	// Conflict exists if local has been modified since last sync
	if local.CloudSynced && !local.LastSyncAt.IsZero() {
		return local.UpdatedAt.After(local.LastSyncAt)
	}

	// If never synced, consider it a conflict
	return !local.CloudSynced
}

func (e *PullEngine) resolveConflict(ctx context.Context, local, cloud *domain.Secret, mode ConflictMode) (bool, error) {
	switch mode {
	case ConflictModeCloudWins:
		return true, nil // Proceed with cloud version

	case ConflictModeLocalWins:
		return false, nil // Keep local version

	case ConflictModeNewestWins:
		// Compare timestamps
		if cloud.UpdatedAt.After(local.UpdatedAt) {
			return true, nil
		}
		return false, nil

	default:
		return false, fmt.Errorf("unknown conflict mode: %d", mode)
	}
}

// PullResult contains the result of a pull operation
type PullResult struct {
	TotalSecrets    int
	PulledSecrets   int // New secrets created
	UpdatedSecrets  int // Existing secrets updated
	SkippedSecrets  int
	ConflictSecrets int
	Errors          map[string]error
}

// Summary returns a human-readable summary
func (r *PullResult) Summary() string {
	summary := fmt.Sprintf("Pull complete: %d total, %d new, %d updated, %d conflicts, %d skipped",
		r.TotalSecrets, r.PulledSecrets, r.UpdatedSecrets, r.ConflictSecrets, r.SkippedSecrets)

	if len(r.Errors) > 0 {
		summary += "\n\nErrors:"
		for path, err := range r.Errors {
			summary += fmt.Sprintf("\n  %s: %v", path, err)
		}
	}

	return summary
}
