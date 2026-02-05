package sync

import (
	"context"
	"fmt"
	"keyopol-app/internal/crypto"
	"keyopol-app/internal/domain"
	"time"
)

// EncryptionAwarePullEngine wraps PullEngine to handle encryption/decryption
// for personal secrets during cloud sync.
//
// When pulling personal secrets from cloud:
// 1. Secret is encrypted with master password (from original device)
// 2. We need to validate it can be decrypted (same master password)
// 3. Optionally re-encrypt with local salt (for better security)
type EncryptionAwarePullEngine struct {
	baseEngine     *PullEngine
	masterPassword string
	encryptor      domain.Encryptor
}

// NewEncryptionAwarePullEngine creates a pull engine that handles encryption
func NewEncryptionAwarePullEngine(
	localStore domain.SecretStore,
	cloudStore domain.CloudProvider,
	masterPassword string,
) *EncryptionAwarePullEngine {
	return &EncryptionAwarePullEngine{
		baseEngine:     NewPullEngine(localStore, cloudStore),
		masterPassword: masterPassword,
		encryptor:      crypto.NewLocalEncryptor(),
	}
}

// Pull pulls secrets and handles decryption/re-encryption for personal secrets
func (e *EncryptionAwarePullEngine) Pull(
	ctx context.Context,
	filter domain.Filter,
	conflictMode ConflictMode,
	validateDecryption bool,
) (*PullResult, error) {
	if !e.baseEngine.cloudStore.IsConfigured() {
		return nil, fmt.Errorf("cloud provider not configured")
	}

	// Pull secrets from cloud
	cloudSecrets, err := e.baseEngine.cloudStore.Pull(ctx, filter)
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
		// For personal (non-shared) secrets, validate decryption
		if !cloudSecret.IsShared && validateDecryption {
			// Try to decrypt with current master password
			_, err := e.encryptor.Decrypt(cloudSecret.Value, e.masterPassword)
			if err != nil {
				result.Errors[cloudSecret.Path()] = fmt.Errorf("decryption failed (wrong master password?): %w", err)
				result.SkippedSecrets++
				continue
			}

			// Optional: Re-encrypt with current device's salt
			// This is beneficial if salt has changed (better security)
			// For now, we keep the original encryption
		}

		// Check if secret exists locally
		localFilter := domain.Filter{
			Project:     cloudSecret.Project,
			Environment: cloudSecret.Environment,
			Scope:       cloudSecret.Scope,
			Key:         cloudSecret.Key,
		}

		localSecret, err := e.baseEngine.localStore.Get(ctx, localFilter)

		if err == nil {
			// Secret exists locally - handle conflict
			conflict := e.baseEngine.detectConflict(localSecret, cloudSecret)

			if conflict {
				result.ConflictSecrets++

				resolved, err := e.baseEngine.resolveConflict(ctx, localSecret, cloudSecret, conflictMode)
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
			cloudSecret.ID = localSecret.ID
			cloudSecret.CloudSynced = true
			cloudSecret.LastSyncAt = timeNow()

			if err := e.baseEngine.localStore.Update(ctx, cloudSecret); err != nil {
				result.Errors[cloudSecret.Path()] = err
				continue
			}

			result.UpdatedSecrets++
		} else {
			// Secret doesn't exist locally - create it
			cloudSecret.CloudSynced = true
			cloudSecret.LastSyncAt = timeNow()

			if err := e.baseEngine.localStore.Create(ctx, cloudSecret); err != nil {
				result.Errors[cloudSecret.Path()] = err
				continue
			}

			result.PulledSecrets++
		}
	}

	return result, nil
}

// timeNow is a helper for testing (can be mocked)
var timeNow = func() time.Time {
	return time.Now()
}
