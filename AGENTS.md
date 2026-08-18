# KyRecovery Server

KyRecovery Server is the self-hosted recovery and restore-verification service for the KySecurity Suite of software (KySignOn, KyPassword, KyBookmarks, KyNotes, KyPost) and Business.app ecosystem. Supported service connectors operate through the unified, content-blind declarative recipe engine (`generic`, `kysignon`, `kypassword`, and dynamic pairing clients).

## Core Capabilities & Responsibilities

1. **Encrypted Recovery Capsules**: Generates and stores content-blind `.kycap` recovery archives containing service databases, signing keys, and configuration manifests.
2. **Zero-Code Product Pairing & Self-Declaring Ingest**: Generates ephemeral 6-digit pairing codes (`/api/pairing/*`). Any KySecurity or Business.app service pairs seamlessly and pushes self-declared backups (`/api/backup/push`) with custom files and verification recipes without KyRecovery server code modifications.
3. **Local Admin Bootstrap & KySignOn OIDC SSO Pairing**: Generates local administrator credentials on first startup, protects dashboard and API routes with Argon2id salted password authentication and SQLite session tokens, and provides an interactive KySignOn OIDC SSO pairing portal with PKCE (`S256`) and RBAC (`admin`, `operator`, `viewer`).
4. **Interactive Custodian Quorum Ceremonies ($M$-of-$N$)**: Coordinates multi-party asynchronous Shamir share gathering via ephemeral in-memory sessions with automatic zeroing memory scrub upon execution.
5. **Offsite Remote Capsule Replication (S3 / Cloudflare R2 / Local Mounts)**: Automatically or manually replicates content-blind `.kycap` recovery archives to AWS S3, Cloudflare R2, MinIO, or offsite disk mounts using pure-Go SigV4 signing.
6. **Air-Gapped Terminal Disaster Console (`kyrecovery tui`)**: Provides an interactive keyboard-driven ANSI terminal interface for bare-metal offline disaster recovery environments without network access or web browsers.
7. **Capsule Version Diff & Snapshot Rollback Inspector**: Computes content-blind file, size, and dependency diffs across historical captures to detect drift and accelerate disaster rollback decisions.
8. **Automated Ephemeral Restore Drills**: Runs scheduled or on-demand restore drills in isolated scratch sandboxes, testing database integrity, token signing, and dependency manifests, followed by automatic cryptographic wiping.
9. **Tamper-Evident Hash-Chained Audit Ledger**: Records cryptographically chained events for capture, approval, export, drill, and restore operations.
10. **Emergency Recovery Kit Export**: Produces self-contained, human-readable offline disaster recovery runbooks (HTML & Markdown).
11. **Privacy-Safe Structured Logging**: Adheres strictly to `LOGGING.md` by emitting structured JSON/logfmt to stdout/stderr without logging secrets, keys, or capsule contents.

## Security Invariants

- Capsule data is encrypted at rest and in transit using AES-256-GCM / ChaCha20-Poly1305.
- The server must never store plaintext master keys or passwords in the database.
- Drill scratch environments must be created with restricted permissions (`0700`) and securely scrubbed upon drill completion.
- SQLite database transactions must be atomic and use WAL mode with foreign key constraints.
- Sensitive HTTP responses must enforce `Cache-Control: no-store` and standard security headers.

# Ponytail, lazy senior dev mode

Use the smallest correct change.

1. Reuse what already exists.
2. Prefer stdlib and native platform APIs.
3. Add dependencies only when they remove meaningful code.
4. Fix shared root causes, not one caller.
5. If a shortcut has a limit, mark it with `ponytail:` and name the upgrade path.

Non-trivial logic must include one runnable check (unit test or minimal self-check).

# DOX framework

## Core Contract

- AGENTS.md files are binding contracts for their subtree.
- Read from root to nearest AGENTS.md before editing.
- The nearest AGENTS.md controls local details; parent docs keep global rules.

## Update After Editing

- Run a DOX pass for every meaningful change.
- Update nearest owning AGENTS.md when behavior, responsibilities, or verification changes.
## Verification

Run all unit and integration tests across the repository:
```bash
go test -v ./...
```

Verify binary build and CLI drill verification:
```bash
go build -o kyrecovery cmd/kyrecovery/main.go
./kyrecovery help
```

## Child DOX Index
