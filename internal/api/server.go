package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"keyopol-app/internal/cloud"
	"keyopol-app/internal/cloud/aws"
	"keyopol-app/internal/crypto"
	"keyopol-app/internal/domain"
	"keyopol-app/internal/storage/sqlite"
	"keyopol-app/internal/sync"
	"log"
	"net/http"
	"time"
)

type Server struct {
	DB *sql.DB
}

func NewServer(db *sql.DB) *Server {
	return &Server{DB: db}
}

func (s *Server) Start(addr string) error {
	mux := http.NewServeMux()

	// Public / Auth
	mux.HandleFunc("/api/auth/unlock", s.handleUnlock)

	// Projects
	mux.HandleFunc("/api/projects", s.handleProjects)
	mux.HandleFunc("/api/projects/", s.handleProjectByName) // Handle /api/projects/:name

	// Secrets
	mux.HandleFunc("/api/secrets", s.handleSecrets)
	mux.HandleFunc("/api/secrets/decrypt", s.handleSecretDecrypt)

	// Cloud
	mux.HandleFunc("/api/cloud/config", s.handleCloudConfig)
	mux.HandleFunc("/api/cloud/enable", s.handleCloudEnable)
	mux.HandleFunc("/api/cloud/disable", s.handleCloudDisable)
	mux.HandleFunc("/api/cloud/push", s.handleCloudPush)
	mux.HandleFunc("/api/cloud/pull", s.handleCloudPull)

	// System / Stats
	mux.HandleFunc("/api/stats", s.handleStats)
	mux.HandleFunc("/api/activity", s.handleActivity)
	mux.HandleFunc("/api/master-key", s.handleMasterKey)

	handler := s.enableCORS(mux)
	handler = s.loggingMiddleware(handler)

	log.Printf("🚀 Keyopol API Server starting on %s", addr)
	return http.ListenAndServe(addr, handler)
}

func (s *Server) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Create a custom response writer to capture status code
		type responseWriter struct {
			http.ResponseWriter
			status      int
			wroteHeader bool
		}

		rw := &responseWriter{ResponseWriter: w, status: http.StatusOK}

		next.ServeHTTP(rw, r)

		duration := time.Since(start)
		log.Printf("[%s] %s %s | Status: %d | Duration: %v",
			r.Method, r.URL.Path, r.RemoteAddr, rw.status, duration)
	})
}

func (s *Server) enableCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-Master-Key")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func (s *Server) handleProjects(w http.ResponseWriter, r *http.Request) {
	adapter, err := sqlite.NewAdapter("")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer adapter.Close()
	ctx := context.Background()

	if r.Method == "GET" {
		projects, err := adapter.ListProjects(ctx)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(projects)
		return
	}

	if r.Method == "POST" {
		var req struct {
			Name string `json:"name"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if req.Name == "" {
			http.Error(w, "name required", http.StatusBadRequest)
			return
		}

		if err := adapter.CreateProject(ctx, req.Name); err != nil {
			log.Printf("❌ Failed to create project %s: %v", req.Name, err)
			http.Error(w, "Failed to create project: "+err.Error(), http.StatusInternalServerError)
			return
		}
		log.Printf("✅ Project created: %s", req.Name)
		w.WriteHeader(http.StatusCreated)
		return
	}

	if r.Method == "DELETE" {
		name := r.URL.Query().Get("name")
		if name == "" {
			http.Error(w, "name required", http.StatusBadRequest)
			return
		}
		if err := adapter.DeleteProject(ctx, name); err != nil {
			http.Error(w, "Failed to delete project: "+err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		return
	}
}

func (s *Server) handleSecrets(w http.ResponseWriter, r *http.Request) {
	masterKey := r.Header.Get("X-Master-Key")

	if r.Method == "GET" {
		adapter, _ := sqlite.NewAdapter("")
		defer adapter.Close()
		filter := domain.Filter{
			Project:     r.URL.Query().Get("project"),
			Environment: r.URL.Query().Get("environment"),
			Scope:       r.URL.Query().Get("scope"),
			Key:         r.URL.Query().Get("key"),
		}
		secrets, _ := adapter.List(context.Background(), filter)
		json.NewEncoder(w).Encode(map[string]interface{}{"secrets": secrets})
		return
	}

	if r.Method == "POST" {
		var req struct {
			Project     string `json:"project"`
			Environment string `json:"environment"`
			Scope       string `json:"scope"`
			Key         string `json:"key"`
			Value       string `json:"value"`
			IsShared    bool   `json:"isShared"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		adapter, _ := sqlite.NewAdapter("")
		defer adapter.Close()
		ctx := context.Background()

		if req.IsShared {
			// Simplified shared secret for PoC
			secret := &domain.Secret{
				Project:     req.Project,
				Environment: req.Environment,
				Scope:       req.Scope,
				Key:         req.Key,
				Value:       req.Value, // In real world, use KMS
				IsShared:    true,
				CloudSynced: true,
				CreatedAt:   time.Now(),
				UpdatedAt:   time.Now(),
			}
			adapter.Create(ctx, secret)
		} else {
			encryptor := crypto.NewLocalEncryptor()
			encryptedValue, _ := encryptor.Encrypt(req.Value, masterKey)
			secret := &domain.Secret{
				Project:     req.Project,
				Environment: req.Environment,
				Scope:       req.Scope,
				Key:         req.Key,
				Value:       encryptedValue,
				IsShared:    false,
				CreatedAt:   time.Now(),
				UpdatedAt:   time.Now(),
			}
			log.Printf("✅ Personal secret created: %s/%s/%s", req.Project, req.Environment, req.Key)
			adapter.Create(ctx, secret)
		}
		w.WriteHeader(http.StatusCreated)
		return
	}

	if r.Method == "DELETE" {
		project := r.URL.Query().Get("project")
		env := r.URL.Query().Get("environment")
		scope := r.URL.Query().Get("scope")
		key := r.URL.Query().Get("key")

		adapter, _ := sqlite.NewAdapter("")
		defer adapter.Close()
		adapter.Delete(context.Background(), domain.Filter{Project: project, Environment: env, Scope: scope, Key: key})
		w.WriteHeader(http.StatusOK)
		return
	}
}

func (s *Server) handleSecretDecrypt(w http.ResponseWriter, r *http.Request) {
	masterKey := r.Header.Get("X-Master-Key")
	project := r.URL.Query().Get("project")
	env := r.URL.Query().Get("environment")
	scope := r.URL.Query().Get("scope")
	key := r.URL.Query().Get("key")

	adapter, _ := sqlite.NewAdapter("")
	defer adapter.Close()
	secrets, _ := adapter.List(context.Background(), domain.Filter{Project: project, Environment: env, Scope: scope, Key: key})
	if len(secrets) == 0 {
		http.Error(w, "secret not found", http.StatusNotFound)
		return
	}

	secret := secrets[0]
	var decrypted string
	if secret.IsShared {
		// Mock KMS decryption
		decrypted = secret.Value
	} else {
		encryptor := crypto.NewLocalEncryptor()
		var err error
		decrypted, err = encryptor.Decrypt(secret.Value, masterKey)
		if err != nil {
			http.Error(w, "incorrect master password", http.StatusUnauthorized)
			return
		}
	}

	json.NewEncoder(w).Encode(map[string]string{"value": decrypted})
}

func (s *Server) handleProjectByName(w http.ResponseWriter, r *http.Request) {
	name := r.URL.Path[len("/api/projects/"):]
	if name == "" {
		http.Error(w, "name required", http.StatusBadRequest)
		return
	}

	adapter, _ := sqlite.NewAdapter("")
	defer adapter.Close()

	if r.Method == "GET" {
		project, _ := adapter.GetProject(context.Background(), name)
		json.NewEncoder(w).Encode(project)
		return
	}

	if r.Method == "DELETE" {
		log.Printf("🗑️ Deleting project: %s", name)
		adapter.DeleteProject(context.Background(), name)
		w.WriteHeader(http.StatusOK)
		return
	}
}

func (s *Server) handleCloudConfig(w http.ResponseWriter, r *http.Request) {
	config, _ := cloud.GetConfig()
	json.NewEncoder(w).Encode(config)
}

func (s *Server) handleCloudDisable(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	cloud.DisableCloud()
	w.WriteHeader(http.StatusOK)
}

func (s *Server) handleUnlock(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		MasterPassword string `json:"masterPassword"`
	}
	json.NewDecoder(r.Body).Decode(&req)

	log.Printf("🔑 Unlock attempt initiated")
	// In a real app, we would verify a hash or try to decrypt a test secret
	// For this PoC, we'll just accept it and the frontend will store it
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "unlocked"})
}

func (s *Server) handleActivity(w http.ResponseWriter, r *http.Request) {
	// Mock activity for now
	activities := []map[string]interface{}{
		{"action": "Secret Created", "target": "DB_URL", "env": "prod", "time": time.Now().Add(-5 * time.Minute).Format(time.RFC3339)},
		{"action": "Cloud Push", "target": "myapp", "env": "all", "time": time.Now().Add(-15 * time.Minute).Format(time.RFC3339)},
		{"action": "Login", "target": "UI", "env": "-", "time": time.Now().Add(-20 * time.Minute).Format(time.RFC3339)},
	}
	json.NewEncoder(w).Encode(activities)
}

func (s *Server) handleCloudEnable(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Provider string `json:"provider"`
		Region   string `json:"region"`
		Profile  string `json:"profile"`
		KMSKeyID string `json:"kmsKeyID"`
	}
	json.NewDecoder(r.Body).Decode(&req)

	if req.Provider != "aws" {
		http.Error(w, "Only AWS supported", http.StatusBadRequest)
		return
	}

	log.Printf("☁️ Enabling AWS Cloud Sync: Region=%s, Profile=%s", req.Region, req.Profile)
	if err := cloud.EnableAWS(req.Region, req.Profile, req.KMSKeyID); err != nil {
		log.Printf("❌ Failed to enable AWS: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	log.Printf("✅ AWS Cloud Sync enabled successfully")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "enabled"})
}

func (s *Server) handleCloudPush(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Project     string `json:"project"`
		Environment string `json:"environment"`
		Scope       string `json:"scope"`
	}
	json.NewDecoder(r.Body).Decode(&req)

	if !cloud.IsCloudEnabled() {
		http.Error(w, "Cloud not enabled", http.StatusBadRequest)
		return
	}

	localStore, _ := sqlite.NewAdapter("")
	defer localStore.Close()

	config, _ := cloud.GetConfig()
	awsSettings, _ := cloud.GetAWSSettings(config)
	cloudStore, _ := aws.NewSecretsManagerAdapter(awsSettings.Region, awsSettings.Profile)

	log.Printf("📤 Cloud Push initiated for project: %s, env: %s", req.Project, req.Environment)
	filter := domain.Filter{Project: req.Project, Environment: req.Environment, Scope: req.Scope}
	engine := sync.NewPushEngine(localStore, cloudStore)
	result, err := engine.Push(context.Background(), filter)
	if err != nil {
		log.Printf("❌ Cloud Push failed: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	log.Printf("✅ Cloud Push success: %+v", result)
	json.NewEncoder(w).Encode(result)
}

func (s *Server) handleCloudPull(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Project     string `json:"project"`
		Environment string `json:"environment"`
		Scope       string `json:"scope"`
	}
	json.NewDecoder(r.Body).Decode(&req)

	if !cloud.IsCloudEnabled() {
		http.Error(w, "Cloud not enabled", http.StatusBadRequest)
		return
	}

	localStore, _ := sqlite.NewAdapter("")
	defer localStore.Close()

	config, _ := cloud.GetConfig()
	awsSettings, _ := cloud.GetAWSSettings(config)
	cloudStore, _ := aws.NewSecretsManagerAdapter(awsSettings.Region, awsSettings.Profile)

	log.Printf("📥 Cloud Pull initiated for project: %s, env: %s", req.Project, req.Environment)
	filter := domain.Filter{Project: req.Project, Environment: req.Environment, Scope: req.Scope}
	engine := sync.NewPullEngine(localStore, cloudStore)
	result, err := engine.Pull(context.Background(), filter, sync.ConflictModeNewestWins)
	if err != nil {
		log.Printf("❌ Cloud Pull failed: %v", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	log.Printf("✅ Cloud Pull success: %+v", result)
	json.NewEncoder(w).Encode(result)
}

func (s *Server) handleMasterKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != "PUT" {
		http.Error(w, "PUT only", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		OldKey string `json:"oldKey"`
		NewKey string `json:"newKey"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	adapter, err := sqlite.NewAdapter("")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer adapter.Close()

	ctx := context.Background()

	// 1. Get ALL secrets (no filter)
	secrets, err := adapter.List(ctx, domain.Filter{})
	if err != nil {
		http.Error(w, "Failed to list secrets: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// 2. Decrypt all personal secrets with OLD key
	// We do this in-memory first to verify old key is correct before modifying DB
	encryptor := crypto.NewLocalEncryptor()
	reEncrypted := make(map[int64]string)

	for _, secret := range secrets {
		if secret.IsShared {
			continue // Shared secrets use KMS, not master password
		}

		// Try to decrypt
		decrypted, err := encryptor.Decrypt(secret.Value, req.OldKey)
		if err != nil {
			http.Error(w, fmt.Sprintf("Incorrect master key. Failed to decrypt secret: %s", secret.Key), http.StatusUnauthorized)
			return
		}

		// Re-encrypt with NEW key
		encrypted, err := encryptor.Encrypt(decrypted, req.NewKey)
		if err != nil {
			http.Error(w, "Encryption failed: "+err.Error(), http.StatusInternalServerError)
			return
		}

		reEncrypted[secret.ID] = encrypted
	}

	// 3. Update DB
	// Note: Ideally this should be a transaction
	tx, err := adapter.GetDB().BeginTx(ctx, nil)
	if err != nil {
		http.Error(w, "Transaction failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	for id, newVal := range reEncrypted {
		_, err := tx.ExecContext(ctx, "UPDATE secrets SET value = ? WHERE id = ?", newVal, id)
		if err != nil {
			tx.Rollback()
			http.Error(w, "Update failed: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}

	if err := tx.Commit(); err != nil {
		http.Error(w, "Commit failed: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "success", "message": "Master key rotated successfully"})
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	adapter, _ := sqlite.NewAdapter("")
	defer adapter.Close()

	secrets, _ := adapter.List(context.Background(), domain.Filter{})

	cloudConfig, _ := cloud.GetConfig()
	backend := "Local (SQLite)"
	if cloudConfig.Enabled {
		backend = "AWS (" + cloudConfig.Settings["region"] + ")"
	}

	stats := map[string]interface{}{
		"totalSecrets": len(secrets),
		"backend":      backend,
		"health":       "Operational",
		"lastUpdate":   time.Now().Format(time.RFC3339),
	}

	json.NewEncoder(w).Encode(stats)
}
