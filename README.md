# KEYOPOL

> **Zero-knowledge, local-first secret manager with optional AWS cloud sync**

Keyopol is a modern secret management tool that bridges the gap between local development and cloud security. It starts as a completely local, zero-knowledge secret store, but can be upgraded to an AWS-backed team secret manager without losing its local-first benefits.

Designed for **Platform Engineers** and **Security-Conscious Developers**.

---

## 🚀 Features

### Core Experience (Local-First)
- **Zero-Knowledge Architecture** – Master key stays in RAM only, never written to disk
- **Beautiful TUI** – Elegant terminal interface with Rose Pine theme (Bubble Tea + Lipgloss)
- **Instant Clipboard Access** – Copy secrets with a single keystroke
- **Command Injection** – Run commands with secrets auto-injected as environment variables

### Cloud Extensions (AWS)
- **Hybrid Cloud Sync** – Sync personal secrets across devices using AWS Secrets Manager (Encrypted blobs)
- **Team Sharing** – Share secrets securely with teammates using AWS KMS + IAM
- **Role-Based Access** – Fine-grained access control via standard AWS IAM policies
- **GitOps Friendly** – Secrets live in the cloud, not in your git repo or `.env` files

---

## 📦 Installation

### Option 1: Pre-built Binaries (Recommended)

Download the latest release for your platform from [Releases](https://github.com/yourusername/keyopol/releases).

### Option 2: Install via Go

```bash
go install github.com/yourusername/keyopol@latest
```

---

## 🛠 Usage Guide

### 1. Local Mode (Default)

The classic Keyopol experience. Everything is stored in a local SQLite database, encrypted with your master password (AES-256-GCM).

```bash
# Initialize and launch TUI
keyopol

# Add a secret manually
keyopol secret add \
  --project my-app \
  --key DATABASE_URL \
  --value "postgres://localhost:5432/db"

# Run a command with injected secrets
keyopol run --project my-app -- npm start
```

### 2. Enable Cloud Sync (Personal)

Sync your personal secrets across devices. Keyopol encrypts secrets locally before uploading them to AWS Secrets Manager. AWS *never* sees your plaintext secrets or your master password.

```bash
# Enable AWS backend
keyopol cloud enable aws --region us-east-1 --profile default

# Push local secrets to cloud
keyopol push cloud --project my-app

# On another device:
keyopol pull cloud --project my-app
```

### 3. Team Capabilities (Shared Secrets)

For secrets that need to be shared with a team (e.g., Staging DB credentials), Keyopol uses **AWS KMS**. These secrets are NOT encrypted with your master password, but with a shared KMS key controlled by IAM.

```bash
# Add a shared secret (uses KMS encryption)
keyopol secret add \
  --project backend \
  --env prod \
  --key STRIPE_KEY \
  --value "sk_live_..." \
  --shared

# Teammates can pull and view it (if IAM allows)
keyopol pull cloud --project backend
keyopol get backend STRIPE_KEY --env prod
```

---

## 🔐 Security Architecture

Keyopol employs a **Dual-Encryption Strategy**:

### 1. Personal Secrets (Zero-Knowledge)
*   **Encryption**: AES-256-GCM
*   **Key Derivation**: Argon2id (Master Password → Key)
*   **Storage**: Encrypted blob in AWS Secrets Manager
*   **Security**: Only YOU can decrypt these. Losing master password = Data Loss.

### 2. Shared Secrets (Team Access)
*   **Encryption**: AWS KMS (Envelope Encryption)
*   **Access Control**: AWS IAM Policies
*   **Storage**: Encrypted data key + Ciphertext in AWS Secrets Manager
*   **Security**: Access is granted via IAM roles. No master password needed.

---

## 🏗 System Architecture

```mermaid
graph TD
    User[User Terminal]
    
    subgraph Local Device
        TUI[Bubble Tea TUI]
        CLI[Cobra CLI]
        SQLite[(Local Encrypted DB)]
        Mem[Memory (Decrypted Secrets)]
    end
    
    subgraph AWS Cloud
        ASM[Secrets Manager]
        KMS[KMS Service]
        IAM[IAM Policies]
    end

    User --> TUI
    User --> CLI
    CLI --> SQLite
    TUI --> Mem
    
    %% Personal Flow
    CLI -- "Push Encrypted Blob" --> ASM
    ASM -- "Pull Encrypted Blob" --> CLI
    
    %% Shared Flow
    CLI -- "Generate Data Key" --> KMS
    KMS -- "Decrypt Data Key" --> CLI
    IAM -- "Authorize" --> KMS
    IAM -- "Authorize" --> ASM
```

---

## 📋 Commands Reference

| Command | Description | Example |
|---------|-------------|---------|
| `keyopol` | Launch the Interactive TUI | `keyopol` |
| `keyopol run` | Execute command with secrets injected | `keyopol run --project myapp -- npm start` |
| `keyopol secret add` | Add a new secret (Personal or Shared) | `keyopol secret add --project myapp --key API_KEY --value "xyz" [--shared]` |
| `keyopol get` | **NEW** Get and decrypt a secret | `keyopol get API_KEY --project myapp --show-value` |
| `keyopol secret list` | List secrets | `keyopol secret list --project myapp` |
| `keyopol cloud enable` | Configure cloud provider | `keyopol cloud enable aws --region us-east-1` |
| `keyopol cloud status` | Show cloud configuration | `keyopol cloud status` |
| `keyopol push cloud` | Upload encrypted secrets to AWS | `keyopol push cloud --project myapp` |
| `keyopol pull cloud` | **IMPROVED** Download & validate secrets from AWS | `keyopol pull cloud --project myapp` |

### 🔒 Security Notes

**Master Password:**
- Prompted from terminal (echo disabled) ✓
- Falls back to `KEYOPOL_MASTER_KEY` env var for CI/CD
- **NEVER** stored on disk

**Encryption:**
- **Personal Secrets:** AES-256-GCM + Argon2id with unique salt per installation
- **Shared Secrets:** AWS KMS Envelope Encryption (unlimited size)
- Salt auto-generated on first use: `~/.keyopol/salt`

**Cloud Security:**
- AWS never sees plaintext secrets (zero-knowledge for personal)
- Envelope encryption for shared secrets (KMS best practice)
- Pull validates decryption with current master password

---

## ☁️ AWS IAM Setup (For Teams)

To allow a developer to access shared secrets for a specific project:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "secretsmanager:GetSecretValue",
                "kms:Decrypt"
            ],
            "Resource": [
                "arn:aws:secretsmanager:*:*:secret:keyopol/backend/*",
                "arn:aws:kms:*:*:key/your-shared-key-id"
            ]
        }
    ]
}
```

---

## 🌐 Web Dashboard

Keyopol now includes a modern web-based dashboard for managing your projects and secrets.

### 1. Start the API Server
First, run the backend server which exposes a REST API:
```bash
keyopol serve
# Server runs on http://localhost:8080
```

### 2. Start the Frontend
Navigate to the `frontend-keyopol` directory and start the React application:
```bash
cd frontend-keyopol
npm install # Only for first time setup
npm start
# Dashboard opens at http://localhost:3000
```

---

## 📜 License

MIT License. Open source and free to use.
