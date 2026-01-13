package store

import (
	"database/sql"
	"keyopol-app/internal/crypto"

	_ "modernc.org/sqlite"
)

type Secret struct {
	Key       string
	ValueDec  string
	IsVisible bool
	CreatedAt string
	UpdatedAt string
}

func InitDB() *sql.DB {
	db, err := sql.Open("sqlite", "./secrets.db")
	if err != nil {
		panic(err)
	}

	createProjects := `
	CREATE TABLE IF NOT EXISTS projects (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT UNIQUE
	);`

	createSecrets := `
	CREATE TABLE IF NOT EXISTS secrets (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		project_id INTEGER,
		key TEXT,
		value TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY(project_id) REFERENCES projects(id)
	);`

	db.Exec(createProjects)
	db.Exec(createSecrets)

	return db
}

func GetProjects(db *sql.DB) []string {
	rows, err := db.Query("SELECT name FROM projects ORDER BY name")
	if err != nil {
		return []string{}
	}
	defer rows.Close()

	var projects []string
	for rows.Next() {
		var name string
		rows.Scan(&name)
		projects = append(projects, name)
	}
	return projects
}

func CreateProject(db *sql.DB, name string) {
	db.Exec("INSERT OR IGNORE INTO projects (name) VALUES (?)", name)
}

func UpdateProject(db *sql.DB, oldName, newName string) {
	db.Exec("UPDATE projects SET name = ? WHERE name = ?", newName, oldName)
}

func DeleteProject(db *sql.DB, name string) {
	db.Exec("DELETE FROM secrets WHERE project_id = (SELECT id FROM projects WHERE name = ?)", name)
	db.Exec("DELETE FROM projects WHERE name = ?", name)
}

func GetSecrets(db *sql.DB, project, masterKey string) []Secret {
	query := `
	SELECT s.key, s.value, s.created_at, s.updated_at 
	FROM secrets s 
	JOIN projects p ON s.project_id = p.id 
	WHERE p.name = ?
	ORDER BY s.key`

	rows, err := db.Query(query, project)
	if err != nil {
		return []Secret{}
	}
	defer rows.Close()

	var secrets []Secret
	for rows.Next() {
		var s Secret
		var encVal string
		rows.Scan(&s.Key, &encVal, &s.CreatedAt, &s.UpdatedAt)

		if len(s.CreatedAt) > 16 {
			s.CreatedAt = s.CreatedAt[:16]
		}
		if len(s.UpdatedAt) > 16 {
			s.UpdatedAt = s.UpdatedAt[:16]
		}

		s.ValueDec = crypto.Decrypt(encVal, masterKey)
		s.IsVisible = false
		secrets = append(secrets, s)
	}
	return secrets
}

func AddSecret(db *sql.DB, project, key, value, masterKey string) {
	encVal := crypto.Encrypt(value, masterKey)
	var pID int
	err := db.QueryRow("SELECT id FROM projects WHERE name = ?", project).Scan(&pID)
	if err != nil {
		return
	}
	db.Exec("INSERT INTO secrets (project_id, key, value) VALUES (?, ?, ?)", pID, key, encVal)
}

func UpdateSecret(db *sql.DB, project, key, newValue, masterKey string) {
	encVal := crypto.Encrypt(newValue, masterKey)
	query := `UPDATE secrets SET value = ?, updated_at = CURRENT_TIMESTAMP WHERE key = ? AND project_id = (SELECT id FROM projects WHERE name = ?)`
	db.Exec(query, encVal, key, project)
}

func DeleteSecret(db *sql.DB, project, key string) {
	db.Exec(`DELETE FROM secrets WHERE key = ? AND project_id = (SELECT id FROM projects WHERE name = ?)`, key, project)
}
