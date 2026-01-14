package runner

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"runtime"

	"keyopol-app/internal/crypto"
	"keyopol-app/internal/store"
)

func Run() {
	runCmd := flag.NewFlagSet("run", flag.ExitOnError)
	projectName := runCmd.String("project", "", "Project name")
	runCmd.Parse(os.Args[2:])

	if *projectName == "" {
		fmt.Println("[ERROR] Project name is required. Usage: keyopol run --project <NAME> -- <COMMAND>")
		os.Exit(1)
	}

	db := store.InitDB()
	defer db.Close()
	masterKey := crypto.GetMasterKey()

	secrets := store.GetSecrets(db, *projectName, masterKey)
	if len(secrets) == 0 {
		fmt.Printf("[WARN] No secrets found for project: %s\n", *projectName)
	} else {
		fmt.Printf("[INFO] Loaded %d secrets for project: %s\n", len(secrets), *projectName)
	}

	envList := os.Environ()
	for _, s := range secrets {
		if s.ValueDec != "LOCKED" && s.ValueDec != "ERR_CORRUPT" {
			envList = append(envList, fmt.Sprintf("%s=%s", s.Key, s.ValueDec))
		}
	}

	args := runCmd.Args()
	if len(args) == 0 {
		fmt.Println("[ERROR] No command specified.")
		os.Exit(1)
	}

	cmdName := args[0]
	cmdArgs := args[1:]

	if runtime.GOOS == "windows" {
		switch cmdName {
		case "npm", "yarn", "pnpm", "mvn", "gradle", "go":
			cmdName += ".cmd"
		}
	}

	cmd := exec.Command(cmdName, cmdArgs...)
	cmd.Env = envList
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	fmt.Printf("[INFO] Executing: %s\n", cmdName)
	fmt.Println("------------------------------------------------------------")

	if err := cmd.Run(); err != nil {
		os.Exit(1)
	}
}

func Get() {
	if len(os.Args) < 4 {
		fmt.Println("Usage: keyopol get <Project> <Key>")
		os.Exit(1)
	}
	projName, keyName := os.Args[2], os.Args[3]

	db := store.InitDB()
	defer db.Close()

	var valEnc string

	query := `
        SELECT s.value 
        FROM secrets s 
        JOIN projects p ON s.project_id = p.id 
        WHERE p.name = ? AND s.key = ?
    `

	err := db.QueryRow(query, projName, keyName).Scan(&valEnc)
	if err != nil {
		fmt.Printf("[ERROR] Secret not found: Project='%s', Key='%s'\n", projName, keyName)
		os.Exit(1)
	}

	masterKey := crypto.GetMasterKey()
	if masterKey == "" {
		fmt.Println("[ERROR] Master Key not found (Set KEYOPOL_MASTER_KEY env var)")
		os.Exit(1)
	}

	fmt.Print(crypto.Decrypt(valEnc, masterKey))
}

