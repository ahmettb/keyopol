package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"keyopol-app/internal/domain"
	"log"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

var (
	ErrNotFound      = errors.New("secret not found")
	ErrInvalidFilter = errors.New("invalid filter: project is required")
)

// Adapter implements domain.SecretStore using SQLite
type Adapter struct {
	db *sql.DB
}

// NewAdapter creates a new SQLite adapter
func NewAdapter(dbPath string) (*Adapter, error) {
	// If no path provided, use default
	if dbPath == "" {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("failed to get home directory: %w", err)
		}
		configDir := filepath.Join(homeDir, ".keyopol")
		if err := os.MkdirAll(configDir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create config directory: %w", err)
		}
		dbPath = filepath.Join(configDir, "secrets.db")
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	adapter := &Adapter{db: db}

	// Run migrations
	if err := adapter.migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("migration failed: %w", err)
	}

	return adapter, nil
}

// migrate runs database migrations
func (a *Adapter) migrate() error {
	// 1. Create tables if they don't exist
	baseSchema := []string{
		`CREATE TABLE IF NOT EXISTS projects (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT UNIQUE NOT NULL
		)`,
		`CREATE TABLE IF NOT EXISTS secrets (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			project_id INTEGER NOT NULL,
			key TEXT NOT NULL,
			value TEXT NOT NULL,
			created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			FOREIGN KEY(project_id) REFERENCES projects(id) ON DELETE CASCADE
		)`,
		`CREATE TABLE IF NOT EXISTS sync_metadata (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			project TEXT NOT NULL,
			environment TEXT NOT NULL,
			last_sync_at DATETIME,
			sync_direction TEXT,
			sync_status TEXT,
			UNIQUE(project, environment)
		)`,
	}

	for _, schema := range baseSchema {
		if _, err := a.db.Exec(schema); err != nil {
			return fmt.Errorf("schema creation failed: %w", err)
		}
	}

	// 2. Check and add missing columns to 'secrets' table (Migration for existing users)
	columnsToAdd := map[string]string{
		"environment":  "TEXT DEFAULT 'default'",
		"scope":        "TEXT DEFAULT ''",
		"is_shared":    "BOOLEAN DEFAULT 0",
		"cloud_synced": "BOOLEAN DEFAULT 0",
		"last_sync_at": "DATETIME",
	}

	existingColumns := make(map[string]bool)
	rows, err := a.db.Query("PRAGMA table_info(secrets)")
	if err != nil {
		return fmt.Errorf("failed to check table info: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull, pk int
		var dfltValue interface{}
		rows.Scan(&cid, &name, &ctype, &notnull, &dfltValue, &pk)
		existingColumns[name] = true
	}

	for colName, colDef := range columnsToAdd {
		if !existingColumns[colName] {
			alterQuery := fmt.Sprintf("ALTER TABLE secrets ADD COLUMN %s %s", colName, colDef)
			if _, err := a.db.Exec(alterQuery); err != nil {
				return fmt.Errorf("failed to add column %s: %w", colName, err)
			}
			fmt.Printf("Migrated database: added column '%s' to secrets table\n", colName)
		}
	}

	// 3. Create Indexes (Safe to run multiple times with IF NOT EXISTS)
	indexes := []string{
		`CREATE INDEX IF NOT EXISTS idx_secrets_project ON secrets(project_id)`,
		`CREATE INDEX IF NOT EXISTS idx_secrets_env ON secrets(environment)`,
		`CREATE INDEX IF NOT EXISTS idx_secrets_scope ON secrets(scope)`,
		`CREATE INDEX IF NOT EXISTS idx_secrets_synced ON secrets(cloud_synced)`,
	}

	for _, idx := range indexes {
		if _, err := a.db.Exec(idx); err != nil {
			return fmt.Errorf("index creation failed: %w", err)
		}
	}

	return nil
}

// Create implements domain.SecretStore
func (a *Adapter) Create(ctx context.Context, secret *domain.Secret) error {
	// Get or create project
	projectID, err := a.getOrCreateProjectID(ctx, secret.Project)
	if err != nil {
		return fmt.Errorf("failed to get project ID: %w", err)
	}

	query := `
		INSERT INTO secrets (
			project_id, key, value, environment, scope, 
			is_shared, cloud_synced, created_at, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`

	now := time.Now()
	_, err = a.db.ExecContext(ctx, query,
		projectID,
		secret.Key,
		secret.Value,
		secret.Environment,
		secret.Scope,
		secret.IsShared,
		secret.CloudSynced,
		now,
		now,
	)

	if err != nil {
		return fmt.Errorf("failed to create secret: %w", err)
	}

	return nil
}

// Get implements domain.SecretStore
func (a *Adapter) Get(ctx context.Context, filter domain.Filter) (*domain.Secret, error) {
	if filter.Project == "" {
		return nil, ErrInvalidFilter
	}

	query, args := a.buildSelectQuery(filter, true) // limitOne = true

	var secret domain.Secret
	var projectID int64
	var createdAt, updatedAt string
	var lastSyncAt sql.NullString

	err := a.db.QueryRowContext(ctx, query, args...).Scan(
		&secret.ID,
		&projectID,
		&secret.Key,
		&secret.Value,
		&secret.Environment,
		&secret.Scope,
		&secret.IsShared,
		&secret.CloudSynced,
		&lastSyncAt,
		&createdAt,
		&updatedAt,
	)

	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get secret: %w", err)
	}

	// Parse timestamps
	secret.CreatedAt, _ = time.Parse("2006-01-02 15:04:05", createdAt)
	secret.UpdatedAt, _ = time.Parse("2006-01-02 15:04:05", updatedAt)
	if lastSyncAt.Valid {
		secret.LastSyncAt, _ = time.Parse("2006-01-02 15:04:05", lastSyncAt.String)
	}

	secret.Project = filter.Project

	return &secret, nil
}

// List implements domain.SecretStore
func (a *Adapter) List(ctx context.Context, filter domain.Filter) ([]*domain.Secret, error) {
	query, args := a.buildSelectQuery(filter, false) // limitOne = false

	rows, err := a.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to list secrets: %w", err)
	}
	defer rows.Close()

	var secrets []*domain.Secret

	for rows.Next() {
		var secret domain.Secret
		var projectID int64
		var projectName string
		var createdAt, updatedAt string
		var lastSyncAt sql.NullString

		err := rows.Scan(
			&secret.ID,
			&projectID,
			&projectName,
			&secret.Key,
			&secret.Value,
			&secret.Environment,
			&secret.Scope,
			&secret.IsShared,
			&secret.CloudSynced,
			&lastSyncAt,
			&createdAt,
			&updatedAt,
		)

		if err != nil {
			return nil, fmt.Errorf("failed to scan secret: %w", err)
		}

		secret.Project = projectName

		// Parse timestamps
		secret.CreatedAt, _ = time.Parse("2006-01-02 15:04:05", createdAt)
		secret.UpdatedAt, _ = time.Parse("2006-01-02 15:04:05", updatedAt)
		if lastSyncAt.Valid {
			secret.LastSyncAt, _ = time.Parse("2006-01-02 15:04:05", lastSyncAt.String)
		}

		secrets = append(secrets, &secret)
	}

	return secrets, nil
}

// Update implements domain.SecretStore
func (a *Adapter) Update(ctx context.Context, secret *domain.Secret) error {
	if secret.Project == "" || secret.Key == "" {
		return ErrInvalidFilter
	}

	projectID, err := a.getProjectID(ctx, secret.Project)
	if err != nil {
		return fmt.Errorf("project not found: %w", err)
	}

	query := `
		UPDATE secrets 
		SET value = ?, is_shared = ?, cloud_synced = ?, 
		    last_sync_at = ?, updated_at = ?
		WHERE project_id = ? AND environment = ? AND scope = ? AND key = ?`

	now := time.Now()
	var lastSyncAt interface{} = nil
	if !secret.LastSyncAt.IsZero() {
		lastSyncAt = secret.LastSyncAt
	}

	result, err := a.db.ExecContext(ctx, query,
		secret.Value,
		secret.IsShared,
		secret.CloudSynced,
		lastSyncAt,
		now,
		projectID,
		secret.Environment,
		secret.Scope,
		secret.Key,
	)

	if err != nil {
		return fmt.Errorf("failed to update secret: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return ErrNotFound
	}

	return nil
}

// Delete implements domain.SecretStore
func (a *Adapter) Delete(ctx context.Context, filter domain.Filter) error {
	if filter.Project == "" {
		return ErrInvalidFilter
	}

	projectID, err := a.getProjectID(ctx, filter.Project)
	if err != nil {
		return fmt.Errorf("project not found: %w", err)
	}

	query := `DELETE FROM secrets WHERE project_id = ?`
	args := []interface{}{projectID}

	if filter.Environment != "" {
		query += ` AND environment = ?`
		args = append(args, filter.Environment)
	}
	if filter.Scope != "" {
		query += ` AND scope = ?`
		args = append(args, filter.Scope)
	}
	if filter.Key != "" {
		query += ` AND key = ?`
		args = append(args, filter.Key)
	}

	result, err := a.db.ExecContext(ctx, query, args...)
	if err != nil {
		return fmt.Errorf("failed to delete secret: %w", err)
	}

	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return ErrNotFound
	}

	return nil
}

// Close implements domain.SecretStore
func (a *Adapter) Close() error {
	return a.db.Close()
}

// Helper methods

func (a *Adapter) getProjectID(ctx context.Context, name string) (int64, error) {
	var id int64
	err := a.db.QueryRowContext(ctx, "SELECT id FROM projects WHERE name = ?", name).Scan(&id)
	if err == sql.ErrNoRows {
		return 0, fmt.Errorf("project not found: %s", name)
	}
	return id, err
}

func (a *Adapter) getOrCreateProjectID(ctx context.Context, name string) (int64, error) {
	// Try to get existing project
	id, err := a.getProjectID(ctx, name)
	if err == nil {
		return id, nil
	}

	// Create new project
	_, err = a.db.ExecContext(ctx, "INSERT OR IGNORE INTO projects (name) VALUES (?)", name)
	if err != nil {
		return 0, err
	}

	// Try to get ID again (handles race conditions)
	return a.getProjectID(ctx, name)
}

func (a *Adapter) buildSelectQuery(filter domain.Filter, limitOne bool) (string, []interface{}) {
	query := `
		SELECT s.id, s.project_id, p.name as project_name, s.key, s.value, 
		       s.environment, s.scope, s.is_shared, s.cloud_synced, 
		       s.last_sync_at, s.created_at, s.updated_at
		FROM secrets s
		JOIN projects p ON s.project_id = p.id
		WHERE 1=1`

	args := []interface{}{}

	if filter.Project != "" {
		query += ` AND p.name = ?`
		args = append(args, filter.Project)
	}
	if filter.Environment != "" {
		query += ` AND s.environment = ?`
		args = append(args, filter.Environment)
	}
	if filter.Scope != "" {
		query += ` AND s.scope = ?`
		args = append(args, filter.Scope)
	}
	if filter.Key != "" {
		query += ` AND s.key = ?`
		args = append(args, filter.Key)
	}
	if filter.OnlyShared {
		query += ` AND s.is_shared = 1`
	}
	if filter.OnlyLocal {
		query += ` AND s.is_shared = 0`
	}
	if filter.OnlyUnsynced {
		query += ` AND (s.cloud_synced = 0 OR s.updated_at > s.last_sync_at)`
	}

	query += ` ORDER BY p.name, s.environment, s.scope, s.key`

	if limitOne {
		query += ` LIMIT 1`
	}

	return query, args
}

// ProjectStore implementation

func (a *Adapter) CreateProject(ctx context.Context, name string) error {
	_, err := a.db.ExecContext(ctx, "INSERT OR IGNORE INTO projects (name) VALUES (?)", name)
	return err
}

func (a *Adapter) ListProjects(ctx context.Context) ([]*domain.Project, error) {
	rows, err := a.db.QueryContext(ctx, "SELECT id, name FROM projects ORDER BY name")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var projects []*domain.Project
	for rows.Next() {
		var p domain.Project
		if err := rows.Scan(&p.ID, &p.Name); err != nil {
			return nil, err
		}
		projects = append(projects, &p)
	}

	return projects, nil
}

func (a *Adapter) UpdateProject(ctx context.Context, oldName, newName string) error {
	result, err := a.db.ExecContext(ctx, "UPDATE projects SET name = ? WHERE name = ?", newName, oldName)
	if err != nil {
		return err
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("project not found: %s", oldName)
	}
	return nil
}

func (a *Adapter) DeleteProject(ctx context.Context, name string) error {
	result, err := a.db.ExecContext(ctx, "DELETE FROM projects WHERE name = ?", name)
	if err != nil {
		return err
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("project not found: %s", name)
	}
	return nil
}

// GetDB returns the underlying database (for legacy code compatibility)
func (a *Adapter) GetDB() *sql.DB {
	return a.db
}

// Legacy compatibility function
func Init() *Adapter {
	adapter, err := NewAdapter("")
	if err != nil {
		log.Fatal("Failed to initialize database:", err)
	}
	return adapter
}
