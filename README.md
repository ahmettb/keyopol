# Keyopol

Keyopol is a local-first secret management application built with Go. It provides a secure terminal user interface (TUI) for managing environment variables and secrets across different projects, with built-in encryption and seamless integration with your development workflow.

## Features

### Core Functionality
- **Project-Based Organization**: Organize secrets into separate projects for better management
- **Secure Encryption**: All secret values are encrypted using AES-256-GCM encryption before storage
- **Local SQLite Database**: Secrets are stored locally in a SQLite database (secrets.db)
- **Master Key Protection**: Uses a master key (configurable via environment variable) to encrypt/decrypt all secrets
- **Interactive TUI**: Beautiful terminal user interface built with Bubble Tea framework

### User Interface
- **Dual-Panel Layout**: Projects on the left, secrets on the right
- **Keyboard Navigation**: Full keyboard-driven interface with vim-style keybindings
- **Visual Feedback**: Color-coded interface with Rose Pine color scheme
- **Secret Visibility Toggle**: Show/hide secret values on demand
- **Clipboard Integration**: Copy secret values directly to clipboard

### Operations
- **CRUD Operations**: Full create, read, update, and delete support for both projects and secrets
- **Command-Line Runner**: Execute commands with secrets injected as environment variables
- **Secret Retrieval**: Query individual secrets from the command line

## Installation

### Prerequisites
- Go 1.25 or higher

### Build from Source
```bash
git clone <repository-url>
cd keyopol-app
go build -o keyopol
```

## Configuration

### Master Key
Keyopol uses a master key to encrypt and decrypt all secrets. Set the master key using an environment variable:

```bash
export KEYOPOL_MASTER_KEY="your-secure-master-key-here"
```

If no master key is set, a default insecure key will be used (not recommended for production use).

## Usage

### Interactive Mode
Launch the TUI interface:

```bash
./keyopol
```

### Keyboard Controls

#### General Navigation
- `Tab`: Switch focus between projects and secrets panels
- `Up/k/K`: Move cursor up
- `Down/j/J`: Move cursor down
- `Q/q/Ctrl+C`: Quit application

#### Project Management (when focused on projects panel)
- `A/a`: Add new project
- `E/e`: Rename selected project
- `D/d`: Delete selected project

#### Secret Management (when focused on secrets panel)
- `A/a`: Add new secret (prompts for key and value)
- `E/e`: Edit selected secret value
- `D/d`: Delete selected secret
- `Space`: Toggle visibility of secret value
- `C/c`: Copy secret value to clipboard

#### Input Dialogs
- `Enter`: Confirm input
- `Esc`: Cancel operation

### Command-Line Mode

#### Run Command with Secrets
Execute a command with project secrets injected as environment variables:

```bash
./keyopol run --project <PROJECT_NAME> -- <COMMAND> [ARGS...]
```

Example:
```bash
./keyopol run --project my-app -- npm start
./keyopol run --project backend -- go run main.go
```

The application will:
1. Load all secrets for the specified project
2. Decrypt them using the master key
3. Inject them as environment variables
4. Execute the specified command

#### Retrieve Single Secret
Get a specific secret value:

```bash
./keyopol get <PROJECT_NAME> <SECRET_KEY>
```

Example:
```bash
./keyopol get my-app DATABASE_URL
```

## Architecture

### Project Structure
```
keyopol-app/
├── main.go                    # Application entry point
├── internal/
│   ├── crypto/
│   │   └── crypto.go         # Encryption/decryption functions
│   ├── runner/
│   │   └── runner.go         # Command execution logic
│   ├── store/
│   │   └── database.go       # Database operations and models
│   └── ui/
│       └── tui.go            # Terminal user interface
├── go.mod                     # Go module dependencies
├── go.sum                     # Dependency checksums
├── secrets.db                 # SQLite database (created on first run)
└── Dockerfile                 # Docker configuration

```

### Components

#### Crypto Package
Handles all cryptographic operations:
- Master key derivation using MD5 hashing
- AES-256-GCM encryption for secret values
- Secure decryption with error handling

#### Store Package
Manages database operations:
- SQLite database initialization
- Project CRUD operations
- Secret CRUD operations
- Automatic timestamp management

#### Runner Package
Provides command-line execution:
- Secret loading and decryption
- Environment variable injection
- Cross-platform command execution (handles Windows .cmd extensions)

#### UI Package
Implements the terminal user interface:
- Bubble Tea-based interactive TUI
- Rose Pine color scheme
- Modal dialogs for input
- Real-time status messages

### Database Schema

#### Projects Table
```sql
CREATE TABLE projects (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE
);
```

#### Secrets Table
```sql
CREATE TABLE secrets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id INTEGER,
    key TEXT,
    value TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(project_id) REFERENCES projects(id)
);
```

## Security Considerations

### Encryption
- All secret values are encrypted using AES-256-GCM before storage
- Nonces are randomly generated for each encryption operation
- Encrypted data is stored as hexadecimal strings

### Master Key
- The master key should be kept secure and not committed to version control
- Use a strong, randomly generated master key in production
- Consider using a key management service for enterprise deployments

### Local Storage
- Secrets are stored locally in secrets.db
- The database file should be protected with appropriate file permissions
- Consider encrypting the entire database file at rest for additional security

### Error Handling
- Decryption errors return specific error codes (ERR_CORRUPT, ERR_INVALID_KEY, etc.)
- Failed decryption displays "LOCKED" instead of revealing partial data

## Dependencies

### Direct Dependencies
- `github.com/charmbracelet/bubbles`: TUI input components
- `github.com/charmbracelet/bubbletea`: Terminal UI framework
- `github.com/charmbracelet/lipgloss`: Terminal styling
- `modernc.org/sqlite`: Pure Go SQLite implementation

### Indirect Dependencies
- `github.com/atotto/clipboard`: Clipboard operations
- Various Charm libraries for terminal rendering and input handling

## Development

### Running Tests
```bash
go test ./...
```

### Building for Production
```bash
go build -ldflags="-s -w" -o keyopol
```

### Cross-Platform Builds
```bash
# Windows
GOOS=windows GOARCH=amd64 go build -o keyopol.exe

# Linux
GOOS=linux GOARCH=amd64 go build -o keyopol

# macOS
GOOS=darwin GOARCH=amd64 go build -o keyopol
```

## Docker Support

A Dockerfile is included for containerized deployments. Build and run:

```bash
docker build -t keyopol .
docker run -it -e KEYOPOL_MASTER_KEY="your-key" keyopol
```

## Use Cases

### Development Environment
- Store API keys, database credentials, and other secrets per project
- Run development servers with secrets automatically injected
- Share project structure without exposing sensitive values

### CI/CD Integration
- Retrieve specific secrets for build scripts
- Inject secrets into test environments
- Manage multiple deployment configurations

### Team Collaboration
- Each developer maintains their own local secrets
- Consistent secret key names across team members
- No secrets committed to version control

## Limitations

- Secrets are stored locally only (no cloud sync)
- No built-in secret sharing mechanism
- Master key must be managed manually
- No audit logging of secret access

## Best Practices

1. **Use Strong Master Keys**: Generate cryptographically secure random keys
2. **Rotate Secrets Regularly**: Update sensitive credentials periodically
3. **Backup Database**: Keep encrypted backups of secrets.db
4. **Use Project Separation**: Organize secrets by environment (dev, staging, prod)
5. **Limit Secret Visibility**: Only reveal secrets when necessary
6. **Secure Your Workstation**: Ensure your development machine is properly secured

## Troubleshooting

### Secrets Show as "LOCKED"
- Verify the correct master key is set
- Check that the secret was encrypted with the current master key

### Database Errors
- Ensure secrets.db has proper read/write permissions
- Check for database corruption and restore from backup if needed

### Command Execution Fails
- Verify the command exists in your PATH
- On Windows, ensure .cmd extension is handled correctly
- Check that secret values are properly formatted

## License

This project's license information is not specified in the repository.

## Contributing

Contribution guidelines are not specified in the repository.
